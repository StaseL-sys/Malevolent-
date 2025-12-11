import { useState } from 'react';
import { getChecklist } from '../services/scannerService';
import { severityLevels } from '../data/securityKnowledge';
import './ScannerForm.css';

function ScannerForm({ targetType, onComplete }) {
  const checklist = getChecklist(targetType);
  const [answers, setAnswers] = useState({});
  const [target, setTarget] = useState('');

  const handleAnswerChange = (itemId, value) => {
    setAnswers(prev => ({
      ...prev,
      [itemId]: value
    }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    onComplete(target, answers);
  };

  const isComplete = checklist.every(item => answers[item.id] !== undefined);
  const answeredCount = Object.keys(answers).length;

  const getPlaceholder = () => {
    switch (targetType) {
      case 'website': return 'https://example.com';
      case 'email': return 'example.com';
      case 'server': return '192.168.1.1 or server.example.com';
      case 'application': return 'My Application Name';
      case 'data': return 'Database or Data Store Name';
      case 'finance': return 'Payment Gateway or Financial System';
      case 'iot': return 'Smart Device or IoT System';
      case 'network': return 'Network Name or WiFi SSID';
      case 'cloud': return 'Cloud Account or Project Name';
      case 'threats': return 'Organization or System Name';
      default: return 'Enter target';
    }
  };

  const getLabel = () => {
    switch (targetType) {
      case 'website': return 'Website URL';
      case 'email': return 'Email Domain';
      case 'server': return 'Server Address';
      case 'application': return 'Application Name';
      case 'data': return 'Data Store Name';
      case 'finance': return 'Financial System';
      case 'iot': return 'IoT Device/System';
      case 'network': return 'Network Name';
      case 'cloud': return 'Cloud Environment';
      case 'threats': return 'Organization/System';
      default: return 'Target';
    }
  };

  return (
    <form className="scanner-form" onSubmit={handleSubmit}>
      <div className="form-section">
        <label className="target-label">
          {getLabel()}
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={getPlaceholder()}
            className="target-input"
            required
          />
        </label>
      </div>

      <div className="form-section">
        <h3>Security Assessment Checklist</h3>
        <p className="form-description">
          Answer the following questions about your {targetType}&apos;s security configuration.
          If you&apos;re unsure about any item, select &quot;Unknown&quot; for a conservative assessment.
        </p>
        <div className="progress-bar">
          <div 
            className="progress-fill" 
            style={{ width: `${(answeredCount / checklist.length) * 100}%` }}
          />
          <span className="progress-text">
            {answeredCount} of {checklist.length} questions answered
          </span>
        </div>
      </div>

      <div className="checklist">
        {checklist.map((item, index) => (
          <div key={item.id} className="checklist-item">
            <div className="checklist-header">
              <span className="checklist-number">{index + 1}</span>
              <span className="checklist-label">{item.label}</span>
              <span 
                className="severity-badge"
                style={{ backgroundColor: severityLevels[item.severity].color }}
              >
                {item.severity}
              </span>
            </div>
            <div className="answer-buttons">
              <button
                type="button"
                className={`answer-btn yes ${answers[item.id] === 'yes' ? 'selected' : ''}`}
                onClick={() => handleAnswerChange(item.id, 'yes')}
              >
                ✓ Yes
              </button>
              <button
                type="button"
                className={`answer-btn no ${answers[item.id] === 'no' ? 'selected' : ''}`}
                onClick={() => handleAnswerChange(item.id, 'no')}
              >
                ✗ No
              </button>
              <button
                type="button"
                className={`answer-btn unknown ${answers[item.id] === 'unknown' ? 'selected' : ''}`}
                onClick={() => handleAnswerChange(item.id, 'unknown')}
              >
                ? Unknown
              </button>
            </div>
          </div>
        ))}
      </div>

      <div className="form-actions">
        <button 
          type="submit" 
          className="submit-btn"
          disabled={!isComplete || !target}
        >
          Generate Security Report
        </button>
        {!isComplete && (
          <p className="form-hint">
            Please answer all questions to generate your security report.
          </p>
        )}
      </div>
    </form>
  );
}

export default ScannerForm;
