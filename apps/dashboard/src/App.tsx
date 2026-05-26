import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Home from './pages/Home'
import ScanResult from './pages/ScanResult'
import AuditReport from './pages/AuditReport'
import History from './pages/History'

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen">
        <header className="border-b border-gray-800 bg-gray-900">
          <div className="max-w-6xl mx-auto px-4 py-3 flex items-center gap-3">
            <span className="text-brand font-bold text-lg">▲ VAAMAN</span>
            <span className="text-gray-500 text-sm">supply chain security</span>
            <nav className="ml-auto flex gap-4 text-sm">
              <a href="/" className="text-gray-300 hover:text-white">Scan</a>
              <a href="/history" className="text-gray-300 hover:text-white">History</a>
            </nav>
          </div>
        </header>
        <main className="max-w-6xl mx-auto px-4 py-6">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/scan/:id" element={<ScanResult />} />
            <Route path="/audit/:id" element={<AuditReport />} />
            <Route path="/history" element={<History />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
