/**
 * Security Scanner Service
 * Simulates security scanning and assessment functionality
 */

import { vulnerabilityDatabase, scanningChecklists, severityLevels } from '../data/securityKnowledge';

/**
 * Build a lookup map for vulnerabilities to avoid repeated find() calls
 * @param {Array} vulnerabilities - Array of vulnerability objects
 * @returns {Map} Map of vulnerability IDs and ID prefixes to vulnerability objects
 */
function buildVulnerabilityLookup(vulnerabilities) {
  const lookup = new Map();
  
  for (const vuln of vulnerabilities) {
    lookup.set(vuln.id, vuln);
    // Also map the ID prefix (e.g., 'missing' from 'missing-https')
    const prefix = vuln.id.split('-')[0];
    if (!lookup.has(prefix)) {
      lookup.set(prefix, vuln);
    }
  }
  
  return lookup;
}

/**
 * Analyze a target and return security findings (optimized)
 * @param {string} targetType - Type of target (website, email, server, application, data)
 * @param {string} target - The target to scan (URL, domain, etc.)
 * @param {Object} answers - Checklist answers from user assessment
 * @returns {Object} Scan results with vulnerabilities and recommendations
 */
export function performSecurityAssessment(targetType, target, answers) {
  const vulnerabilities = vulnerabilityDatabase[targetType] || [];
  const checklist = scanningChecklists[targetType] || [];
  
  // Build lookup map once instead of using find() in loop
  const vulnLookup = buildVulnerabilityLookup(vulnerabilities);
  
  const findings = [];
  let totalScore = 0;
  let maxScore = 0;

  // Analyze based on checklist answers
  for (const item of checklist) {
    const answer = answers[item.id];
    const severity = severityLevels[item.severity];
    maxScore += severity.score;

    if (answer === 'no' || answer === 'unknown') {
      // Use lookup map instead of find() for O(1) access
      const itemPrefix = item.id.split('-')[0];
      const relatedVuln = vulnLookup.get(item.id) || 
                         vulnLookup.get(itemPrefix) || 
                         vulnerabilities[0];

      findings.push({
        id: item.id,
        label: item.label,
        status: answer,
        severity: item.severity,
        severityInfo: severity,
        relatedVulnerability: relatedVuln,
        recommendation: getRecommendation(item.id, targetType)
      });
    } else {
      totalScore += severity.score;
    }
  }

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
 * Generate a summary of the scan results (optimized to use single loop)
 */
function generateSummary(findings, score) {
  // Count severities in a single pass instead of multiple filter() calls
  let criticalCount = 0;
  let highCount = 0;
  
  for (const finding of findings) {
    if (finding.severity === 'CRITICAL') criticalCount++;
    else if (finding.severity === 'HIGH') highCount++;
  }

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

// Cache for pre-computed lowercase strings to avoid repeated toLowerCase() calls
let searchCache = null;

/**
 * Build search index with pre-computed lowercase strings for better performance
 */
function buildSearchIndex() {
  if (searchCache) return searchCache;
  
  const index = [];
  for (const categoryVulns of Object.values(vulnerabilityDatabase)) {
    for (const vuln of categoryVulns) {
      index.push({
        vuln,
        searchableText: `${vuln.id} ${vuln.name} ${vuln.description}`.toLowerCase()
      });
    }
  }
  searchCache = index;
  return index;
}

/**
 * Search vulnerabilities by keyword (optimized with pre-computed index)
 */
export function searchVulnerabilities(keyword) {
  if (!keyword) return [];
  
  const searchTerm = keyword.toLowerCase();
  const searchIndex = buildSearchIndex();
  
  // Use filter and map instead of nested loops for better performance
  return searchIndex
    .filter(entry => entry.searchableText.includes(searchTerm))
    .map(entry => entry.vuln);
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
