/**
 * Security Scanner Service
 * Simulates security scanning and assessment functionality
 */

import { vulnerabilityDatabase, scanningChecklists, severityLevels } from '../data/securityKnowledge';

/**
 * Analyze a target and return security findings
 * @param {string} targetType - Type of target (website, email, server, application, data)
 * @param {string} target - The target to scan (URL, domain, etc.)
 * @param {Object} answers - Checklist answers from user assessment
 * @returns {Object} Scan results with vulnerabilities and recommendations
 */
export function performSecurityAssessment(targetType, target, answers) {
  const vulnerabilities = vulnerabilityDatabase[targetType] || [];
  const checklist = scanningChecklists[targetType] || [];
  
  const findings = [];
  let totalScore = 0;
  let maxScore = 0;

  // Analyze based on checklist answers
  checklist.forEach(checklistItem => {
    const answer = answers[checklistItem.id];
    const severityLevel = severityLevels[checklistItem.severity];
    maxScore += severityLevel.score;

    if (answer === 'no' || answer === 'unknown') {
      // Find related vulnerability details
      const relatedVulnerability = vulnerabilities.find(vulnerability => 
        vulnerability.id.includes(checklistItem.id) || checklistItem.id.includes(vulnerability.id.split('-')[0])
      ) || vulnerabilities[0];

      findings.push({
        id: checklistItem.id,
        label: checklistItem.label,
        status: answer,
        severity: checklistItem.severity,
        severityInfo: severityLevel,
        relatedVulnerability: relatedVulnerability,
        recommendation: getRecommendation(checklistItem.id, targetType)
      });
    } else {
      totalScore += severityLevel.score;
    }
  });

  const score = maxScore > 0 ? Math.round((totalScore / maxScore) * 100) : 0;
  const grade = calculateGrade(score);

  return {
    target,
    targetType,
    timestamp: new Date().toISOString(),
    score,
    grade,
    findings,
    passedChecks: checklist.length - findings.length,
    totalChecks: checklist.length,
    summary: generateSummary(findings, score)
  };
}

/**
 * Get recommendation text for a specific check
 */
function getRecommendation(checkId) {
  const recommendations = {
    // Website
    https: 'Install an SSL/TLS certificate and enforce HTTPS for all traffic.',
    headers: 'Configure security headers including CSP, X-Frame-Options, and HSTS.',
    cookies: 'Set Secure, HttpOnly, and SameSite attributes on all cookies.',
    forms: 'Implement CSRF tokens on all forms that perform state-changing actions.',
    inputs: 'Validate and sanitize all user inputs on both client and server side.',
    errors: 'Use generic error messages and log detailed errors server-side only.',
    version: 'Remove or hide server version information from HTTP headers.',
    robots: 'Use robots.txt to prevent crawling of sensitive paths.',
    
    // Email
    spf: 'Add an SPF TXT record to your DNS to authorize mail servers.',
    dkim: 'Configure DKIM signing for outgoing emails.',
    dmarc: 'Implement a DMARC policy to handle authentication failures.',
    tls: 'Enable TLS 1.2+ for all mail server connections.',
    relay: 'Configure mail server to only relay for authenticated users.',
    blacklist: 'Check and resolve any blacklist issues with major email blocklists.',
    
    // Server
    firewall: 'Install and configure a firewall (iptables, ufw, or cloud security groups).',
    ports: 'Audit open ports and close any that are not needed.',
    updates: 'Apply all pending security patches and enable automatic updates.',
    ssh: 'Disable root login and password auth, use SSH keys only.',
    passwords: 'Change all default passwords to strong, unique passwords.',
    backups: 'Implement automated backups with regular testing of restoration.',
    logging: 'Enable security event logging and centralize log collection.',
    monitoring: 'Set up intrusion detection and security monitoring.',
    
    // Application
    secrets: 'Move all secrets to environment variables or a secrets manager.',
    deps: 'Update all dependencies and set up automated vulnerability scanning.',
    auth: 'Implement multi-factor authentication and secure password handling.',
    authz: 'Add proper authorization checks at every access point.',
    ratelimit: 'Implement rate limiting on all public endpoints.',
    validation: 'Add input validation on all user-supplied data.',
    encoding: 'Properly encode all output to prevent XSS attacks.',
    
    // Data
    encryption: 'Encrypt sensitive data at rest using AES-256 or equivalent.',
    transit: 'Use TLS 1.2+ for all data in transit.',
    access: 'Implement role-based access control for all data access.',
    backup: 'Encrypt all backup files and store keys separately.',
    retention: 'Define and enforce data retention and deletion policies.',
    minimal: 'Review data collection and remove unnecessary fields.'
  };
  
  return recommendations[checkId] || 'Review and address this security control.';
}

/**
 * Calculate letter grade from score
 */
function calculateGrade(score) {
  if (score >= 90) return { letter: 'A', description: 'Excellent' };
  if (score >= 80) return { letter: 'B', description: 'Good' };
  if (score >= 70) return { letter: 'C', description: 'Fair' };
  if (score >= 60) return { letter: 'D', description: 'Poor' };
  return { letter: 'F', description: 'Critical' };
}

/**
 * Generate a summary of the scan results
 */
function generateSummary(findings, score) {
  const criticalCount = findings.filter(finding => finding.severity === 'CRITICAL').length;
  const highCount = findings.filter(finding => finding.severity === 'HIGH').length;

  let summary = '';
  
  if (criticalCount > 0) {
    summary = `Found ${criticalCount} critical issue${criticalCount > 1 ? 's' : ''} requiring immediate attention. `;
  }
  
  if (highCount > 0) {
    summary += `${highCount} high severity issue${highCount > 1 ? 's' : ''} should be addressed soon. `;
  }
  
  if (score >= 90) {
    summary = 'Excellent security posture! ' + summary;
  } else if (score >= 70) {
    summary = 'Good security practices with room for improvement. ' + summary;
  } else if (score >= 50) {
    summary = 'Several security gaps need attention. ' + summary;
  } else {
    summary = 'Significant security issues detected. Immediate action recommended. ' + summary;
  }

  return summary;
}

/**
 * Get all vulnerabilities for a category
 */
export function getVulnerabilitiesByCategory(category) {
  return vulnerabilityDatabase[category] || [];
}

/**
 * Get checklist for a specific target type
 */
export function getChecklist(targetType) {
  return scanningChecklists[targetType] || [];
}

/**
 * Search vulnerabilities by keyword
 */
export function searchVulnerabilities(keyword) {
  const results = [];
  const searchTerm = keyword.toLowerCase();
  
  Object.values(vulnerabilityDatabase).forEach(categoryVulnerabilities => {
    categoryVulnerabilities.forEach(vulnerability => {
      if (
        vulnerability.name.toLowerCase().includes(searchTerm) ||
        vulnerability.description.toLowerCase().includes(searchTerm) ||
        vulnerability.id.toLowerCase().includes(searchTerm)
      ) {
        results.push(vulnerability);
      }
    });
  });
  
  return results;
}

/**
 * Calculate overall security score from multiple assessments
 */
export function calculateOverallScore(assessments) {
  if (!assessments || assessments.length === 0) return 0;
  
  const totalScore = assessments.reduce((sum, assessment) => sum + assessment.score, 0);
  return Math.round(totalScore / assessments.length);
}

export default {
  performSecurityAssessment,
  getVulnerabilitiesByCategory,
  getChecklist,
  searchVulnerabilities,
  calculateOverallScore
};
