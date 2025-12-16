import { useState, useCallback } from 'react';
import './SecurityReport.css';

function SecurityReport({ results, onBack }) {
  const [expandedFinding, setExpandedFinding] = useState(null);

  const { target, targetType, score, grade, findings, passedChecks, totalChecks, summary } = results;

  // Memoize toggle function to prevent unnecessary re-renders
  const toggleFinding = useCallback((findingId) => {
    setExpandedFinding(prev => prev === findingId ? null : findingId);
  }, []);

  const getGradeColor = (letter) => {
    switch (letter) {
      case 'A': return '#16a34a';
      case 'B': return '#22c55e';
      case 'C': return '#ca8a04';
      case 'D': return '#ea580c';
      case 'F': return '#dc2626';
      default: return '#888';
    }
  };

  return (
    <div className="security-report">
      <div className="report-header">
        <button className="back-btn" onClick={onBack}>
          ← Back to Assessment
        </button>
        <h2>Security Assessment Report</h2>
        <p className="report-target">
          <span className="target-type">{targetType}</span>: {target}
        </p>
      </div>

      <div className="score-section">
        <div className="score-circle" style={{ borderColor: getGradeColor(grade.letter) }}>
          <span className="grade" style={{ color: getGradeColor(grade.letter) }}>
            {grade.letter}
          </span>
          <span className="score">{score}%</span>
        </div>
        <div className="score-details">
          <h3>{grade.description} Security</h3>
          <p>{passedChecks} of {totalChecks} checks passed</p>
          <p className="summary">{summary}</p>
        </div>
      </div>

      {findings.length > 0 ? (
        <div className="findings-section">
          <h3>Security Issues Found ({findings.length})</h3>
          <p className="section-description">
            Click on each finding to learn more about the issue and how to fix it.
          </p>
          <div className="findings-list">
            {findings.map((finding) => (
              <div 
                key={finding.id} 
                className={`finding-item ${expandedFinding === finding.id ? 'expanded' : ''}`}
              >
                <div 
                  className="finding-header"
                  onClick={() => toggleFinding(finding.id)}
                >
                  <span 
                    className="severity-indicator"
                    style={{ backgroundColor: finding.severityInfo.color }}
                  />
                  <span className="finding-label">{finding.label}</span>
                  <span 
                    className="finding-severity"
                    style={{ color: finding.severityInfo.color }}
                  >
                    {finding.severity}
                  </span>
                  <span className="expand-icon">
                    {expandedFinding === finding.id ? '−' : '+'}
                  </span>
                </div>
                
                {expandedFinding === finding.id && (
                  <div className="finding-details">
                    <div className="finding-status">
                      <span className={`status-badge ${finding.status}`}>
                        {finding.status === 'no' ? 'Not Implemented' : 'Unknown'}
                      </span>
                    </div>

                    <div className="detail-section">
                      <h4>Recommendation</h4>
                      <p>{finding.recommendation}</p>
                    </div>

                    {finding.relatedVulnerability && (
                      <>
                        <div className="detail-section">
                          <h4>About This Vulnerability</h4>
                          <p>{finding.relatedVulnerability.description}</p>
                        </div>

                        <div className="detail-section">
                          <h4>Potential Impact</h4>
                          <p className="impact-text">{finding.relatedVulnerability.impact}</p>
                        </div>

                        <div className="detail-section">
                          <h4>How to Fix</h4>
                          <ol className="fix-steps">
                            {finding.relatedVulnerability.howToFix.map((step, index) => (
                              <li key={index}>{step}</li>
                            ))}
                          </ol>
                        </div>

                        {finding.relatedVulnerability.resources && (
                          <div className="detail-section">
                            <h4>Learn More</h4>
                            <ul className="resource-list">
                              {finding.relatedVulnerability.resources.map((resource, index) => (
                                <li key={index}>
                                  <a 
                                    href={resource.url} 
                                    target="_blank" 
                                    rel="noopener noreferrer"
                                  >
                                    {resource.title} →
                                  </a>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="success-section">
          <div className="success-icon">✓</div>
          <h3>All Security Checks Passed!</h3>
          <p>
            Great job! Your {targetType} passed all security checks in our assessment.
            Continue to monitor and maintain these security practices.
          </p>
        </div>
      )}

      <div className="report-footer">
        <p>
          Report generated on {new Date(results.timestamp).toLocaleString()}
        </p>
        <p className="disclaimer">
          This assessment is based on self-reported information and may not detect all vulnerabilities.
          For comprehensive security testing, consider a professional security audit.
        </p>
      </div>
    </div>
  );
}

export default SecurityReport;
