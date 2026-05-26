// Vaaman AI — BaseAgent: multi-pass tool loop
// Every agent in the Vaaman ecosystem extends this class.
// Implements the core agentic pattern: prompt → LLM → tool calls → results → loop → structured output.
//
// Single-pass agents (AI Reasoner): maxRounds = 0, no tools
// Multi-pass agents (CVE, Exploit, Blast): maxRounds = 3-5, tools enabled

import { OpenRouterClient, getLLMCache } from '@vaaman/core'
import type { ChatResponse, MessageParam, ToolCall, ToolDefinition } from '@vaaman/core'
import { VAAMAN_TOOLS } from '@vaaman/core'
import type { AIVerdict } from '@vaaman/core'

export interface AgentConfig {
  model?: string
  maxRounds?: number
  temperature?: number
  systemPrompt: string
}

export interface AgentResult {
  success: boolean
  data: unknown
  toolCallsMade: number
  totalTokens: number
  latencyMs: number
  error?: string
}

export abstract class BaseAgent {
  protected openrouter: OpenRouterClient
  protected history: MessageParam[] = []
  protected tools: ToolDefinition[] = []
  protected rounds = 0
  protected maxRounds: number

  constructor(protected config: AgentConfig) {
    this.openrouter = new OpenRouterClient()
    this.maxRounds = config.maxRounds ?? 3
  }

  enableTools(tools: ToolDefinition[] = VAAMAN_TOOLS): void {
    this.tools = tools
  }

  async run(initialPrompt: string): Promise<AgentResult> {
    const startTime = Date.now()
    let totalTokens = 0
    let toolCallsMade = 0

    // Seed conversation
    this.history = [{ role: 'user', content: initialPrompt }]
    this.rounds = 0

    while (this.rounds <= this.maxRounds) {
      const response = await this.openrouter.chat({
        model: this.config.model ?? 'anthropic/claude-sonnet-4-20250514',
        system: this.config.systemPrompt,
        messages: this.history,
        tools: this.tools.length > 0 ? this.tools : undefined,
        maxTokens: 1500,
        temperature: this.config.temperature ?? 0.1,
      })

      totalTokens += response.usage.inputTokens + response.usage.outputTokens

      // Record assistant response
      this.history.push({
        role: 'assistant',
        content: response.content,
        ...(response.toolCalls ? { tool_calls: response.toolCalls } : {}),
      })

      // Agent decided it has enough information
      if (response.stopReason === 'stop') {
        return {
          success: true,
          data: this.extractOutput(response.content),
          toolCallsMade,
          totalTokens,
          latencyMs: Date.now() - startTime,
        }
      }

      // Agent wants to use tools
      if (response.stopReason === 'tool_calls' && response.toolCalls) {
        const results = await this.executeToolCalls(response.toolCalls)
        toolCallsMade += response.toolCalls.length

        this.history.push({ role: 'user', content: results })
        this.rounds++
        continue
      }

      // Error or length — break to avoid infinite loop
      return {
        success: false,
        data: null,
        toolCallsMade,
        totalTokens,
        latencyMs: Date.now() - startTime,
        error: `Agent stopped unexpectedly: ${response.stopReason}`,
      }
    }

    // Max rounds reached — return partial
    return {
      success: false,
      data: this.extractOutput(this.history[this.history.length - 1]?.content ?? ''),
      toolCallsMade,
      totalTokens,
      latencyMs: Date.now() - startTime,
      error: `Max rounds (${this.maxRounds}) reached`,
    }
  }

  // Subclasses override this to extract structured output from the final response
  protected abstract extractOutput(content: string): unknown

  // Tool execution — subclasses can override individual tools
  protected async executeToolCalls(toolCalls: ToolCall[]): Promise<string> {
    const results: string[] = []

    for (const call of toolCalls) {
      try {
        const result = await this.executeTool(call.name, call.arguments)
        results.push(`Tool result for ${call.name}:\n${JSON.stringify(result, null, 2)}`)
      } catch (err) {
        results.push(`Tool error for ${call.name}: ${err}`)
      }
    }

    return results.join('\n\n')
  }

  // Override this in subclasses to wire actual tool implementations
  protected async executeTool(name: string, args: Record<string, unknown>): Promise<unknown> {
    // Default: return a placeholder — subclasses wire real implementations
    return {
      tool: name,
      args,
      status: 'not_implemented',
      message: `Tool '${name}' is not wired in this agent. Override executeTool() in your agent subclass.`,
    }
  }
}
