import { useState } from 'react'
import ScannerForm from './components/ScannerForm'
import SecurityReport from './components/SecurityReport'
import VulnerabilityLibrary from './components/VulnerabilityLibrary'
import { performSecurityAssessment } from './services/scannerService'
import './App.css'

function App() {
  const [activeTab, setActiveTab] = useState('scanner')
  const [selectedTargetType, setSelectedTargetType] = useState(null)
  const [scanResults, setScanResults] = useState(null)

  const targetTypes = [
    { id: 'website', name: 'Website', icon: '🌐', description: 'Scan websites for security headers, SSL, and common vulnerabilities' },
    { id: 'email', name: 'Email', icon: '✉️', description: 'Check email security (SPF, DKIM, DMARC) configuration' },
    { id: 'server', name: 'Server', icon: '🖥️', description: 'Assess server security, firewall, and access controls' },
    { id: 'application', name: 'Application', icon: '📱', description: 'Review application security practices and code safety' },
    { id: 'data', name: 'Data', icon: '🔐', description: 'Evaluate data protection and encryption practices' },
    { id: 'finance', name: 'Finance', icon: '💳', description: 'Assess payment systems, trading platforms, and financial API security' },
    { id: 'iot', name: 'IoT Devices', icon: '🏠', description: 'Test smart home devices, industrial IoT, and embedded systems' },
    { id: 'network', name: 'Network', icon: '🔌', description: 'Evaluate WiFi, VPN, DNS, and network infrastructure security' },
    { id: 'cloud', name: 'Cloud', icon: '☁️', description: 'Review cloud infrastructure, containers, and serverless security' },
    { id: 'threats', name: 'Threat Defense', icon: '🛡️', description: 'Assess defenses against modern threats: ransomware, malware, phishing, and attacks' }
  ]

  const handleScanComplete = (target, answers) => {
    const assessmentResults = performSecurityAssessment(selectedTargetType, target, answers)
    setScanResults(assessmentResults)
  }

  const handleBackToScanner = () => {
    setScanResults(null)
    setSelectedTargetType(null)
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="logo">
          <span className="logo-icon">🛡️</span>
          <h1>Malevolent</h1>
        </div>
        <p className="tagline">Security Scanner &amp; Learning Platform</p>
        <nav className="main-nav">
          <button 
            className={`nav-btn ${activeTab === 'scanner' ? 'active' : ''}`}
            onClick={() => { setActiveTab('scanner'); setScanResults(null); setSelectedTargetType(null); }}
          >
            🔍 Scanner
          </button>
          <button 
            className={`nav-btn ${activeTab === 'library' ? 'active' : ''}`}
            onClick={() => setActiveTab('library')}
          >
            📚 Learn
          </button>
        </nav>
      </header>

      <main className="app-main">
        {activeTab === 'scanner' && (
          <>
            {!selectedTargetType && !scanResults && (
              <div className="target-selection">
                <h2>What would you like to scan?</h2>
                <p className="selection-description">
                  Select the type of asset you want to assess for security vulnerabilities.
                </p>
                <div className="target-grid">
                  {targetTypes.map(targetType => (
                    <button
                      key={targetType.id}
                      className="target-card"
                      onClick={() => setSelectedTargetType(targetType.id)}
                    >
                      <span className="target-icon">{targetType.icon}</span>
                      <h3>{targetType.name}</h3>
                      <p>{targetType.description}</p>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {selectedTargetType && !scanResults && (
              <div className="scanner-view">
                <button 
                  className="back-link" 
                  onClick={() => setSelectedTargetType(null)}
                >
                  ← Choose different target
                </button>
                <h2>
                  {targetTypes.find(targetType => targetType.id === selectedTargetType)?.icon}{' '}
                  {targetTypes.find(targetType => targetType.id === selectedTargetType)?.name} Security Assessment
                </h2>
                <ScannerForm 
                  targetType={selectedTargetType} 
                  onComplete={handleScanComplete}
                />
              </div>
            )}

            {scanResults && (
              <SecurityReport 
                results={scanResults} 
                onBack={handleBackToScanner}
              />
            )}
          </>
        )}

        {activeTab === 'library' && (
          <VulnerabilityLibrary />
        )}
      </main>

      <footer className="app-footer">
        <p>
          Malevolent Security Scanner — Learn to identify and fix security vulnerabilities
        </p>
        <p className="footer-disclaimer">
          This tool provides educational guidance. For production systems, always consult security professionals.
        </p>
      </footer>
    </div>
  )
}

export default App
