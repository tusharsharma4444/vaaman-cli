// @vaaman/core — OpenRouter unified AI client
// Single integration point for all LLM calls across Vaaman.
// Supports both simple chat (Deep Intel, Trust Engine) and tool-use chat (Swarm agents).
//
// OpenRouter provides a unified API across Anthropic, OpenAI, Meta, etc.
// Tool calls are returned in OpenAI-compatible format regardless of underlying model.

const OPENROUTER_BASE = 'https://openrouter.ai/api/v1'

export interface MessageParam {
  role: 'system' | 'user' | 'assistant'
  content: string
  tool_calls?: ToolCall[]
}

export interface ToolCall {
  id: string
  name: string
  arguments: Record<string, unknown>
}

export interface ToolDefinition {
  name: string
  description: string
  input_schema: {
    type: 'object'
    properties: Record<string, unknown>
    required?: string[]
  }
}

export interface ChatParams {
  model?: string
  messages: MessageParam[]
  system?: string
  tools?: ToolDefinition[]
  maxTokens?: number
  temperature?: number
}

export interface ChatResponse {
  content: string
  toolCalls: ToolCall[] | null
  stopReason: 'stop' | 'tool_calls' | 'length' | 'error'
  model: string
  usage: { inputTokens: number; outputTokens: number }
  latencyMs: number
}

export interface ToolResult<T = unknown> {
  data: T
  confidence: number
  flags: string[]
  summary: string
}

export class OpenRouterClient {
  private apiKey: string
  private defaultModel = process.env.VAAMAN_MODEL || 'deepseek/deepseek-v4-flash'
  private appUrl: string
  private appName: string

  constructor(options?: { apiKey?: string; defaultModel?: string; appUrl?: string; appName?: string }) {
    this.apiKey = options?.apiKey ?? process.env.OPENROUTER_API_KEY ?? ''
    this.defaultModel = options?.defaultModel ?? process.env.VAAMAN_MODEL ?? 'deepseek/deepseek-v4-flash'
    this.appUrl = options?.appUrl ?? 'https://github.com/tusharsharma4444/vaaman-cli'
    this.appName = options?.appName ?? 'vaaman-ai'
  }

  async chat(params: ChatParams): Promise<ChatResponse> {
    const start = Date.now()

    if (!this.apiKey) {
      throw new Error(
        'OPENROUTER_API_KEY environment variable is required. ' +
        'Get a key at https://openrouter.ai/keys'
      )
    }

    const messages: Record<string, unknown>[] = []

    if (params.system) {
      messages.push({ role: 'system', content: params.system })
    }

    for (const m of params.messages) {
      const msg: Record<string, unknown> = { role: m.role, content: m.content }
      if (m.tool_calls) {
        msg.tool_calls = m.tool_calls.map(tc => ({
          id: tc.id,
          type: 'function',
          function: {
            name: tc.name,
            arguments: JSON.stringify(tc.arguments),
          },
        }))
      }
      messages.push(msg)
    }

    const body: Record<string, unknown> = {
      model: params.model ?? this.defaultModel,
      messages,
      max_tokens: params.maxTokens ?? 1000,
      temperature: params.temperature ?? 0.1,
    }

    if (params.tools && params.tools.length > 0) {
      body.tools = params.tools.map(t => ({
        type: 'function',
        function: {
          name: t.name,
          description: t.description,
          parameters: t.input_schema,
        },
      }))
    }

    let response: Response
    try {
      response = await fetch(`${OPENROUTER_BASE}/chat/completions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'HTTP-Referer': this.appUrl,
          'X-Title': this.appName,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      })
    } catch (err) {
      return this.errorResponse(`Network error: ${err}`, params.model ?? this.defaultModel, Date.now() - start)
    }

    if (!response.ok) {
      const text = await response.text().catch(() => 'Unknown error')
      return this.errorResponse(
        `OpenRouter error ${response.status}: ${text.slice(0, 200)}`,
        params.model ?? this.defaultModel,
        Date.now() - start
      )
    }

    const data = await response.json() as Record<string, unknown>
    const choice = (data.choices as Record<string, unknown>[])?.[0]
    const msg = (choice?.message ?? {}) as Record<string, unknown>
    const content = (msg.content as string) ?? ''
    const rawToolCalls = msg.tool_calls as Array<Record<string, unknown>> | undefined

    return {
      content,
      toolCalls: rawToolCalls?.map((tc: Record<string, unknown>) => {
        const fn = (tc.function ?? {}) as Record<string, unknown>
        let args: Record<string, unknown> = {}
        try {
          args = JSON.parse((fn.arguments as string) ?? '{}')
        } catch { /* malformed JSON — return empty */ }
        return {
          id: tc.id as string,
          name: fn.name as string,
          arguments: args,
        }
      }) ?? null,
      stopReason: this.normalizeStopReason((choice?.finish_reason as string) ?? 'stop'),
      model: (data.model as string) ?? params.model ?? this.defaultModel,
      usage: (data.usage as { input_tokens: number; output_tokens: number })
        ? { inputTokens: (data.usage as Record<string, number>).input_tokens ?? 0, outputTokens: (data.usage as Record<string, number>).output_tokens ?? 0 }
        : { inputTokens: 0, outputTokens: 0 },
      latencyMs: Date.now() - start,
    }
  }

  private normalizeStopReason(raw: string): ChatResponse['stopReason'] {
    switch (raw) {
      case 'stop': return 'stop'
      case 'tool_calls': return 'tool_calls'
      case 'length': return 'length'
      default: return 'stop'
    }
  }

  private errorResponse(message: string, model: string, latencyMs: number): ChatResponse {
    return {
      content: '',
      toolCalls: null,
      stopReason: 'error',
      model,
      usage: { inputTokens: 0, outputTokens: 0 },
      latencyMs,
    }
  }
}

// Singleton instance — shared across all packages
let defaultClient: OpenRouterClient | null = null

export function getOpenRouter(): OpenRouterClient {
  if (!defaultClient) {
    defaultClient = new OpenRouterClient()
  }
  return defaultClient
}

export function setOpenRouterApiKey(key: string): void {
  defaultClient = new OpenRouterClient({ apiKey: key })
}
