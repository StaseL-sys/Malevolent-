import { describe, it, expect } from 'vitest';
import {
  performSecurityAssessment,
  getVulnerabilitiesByCategory,
  getChecklist,
  searchVulnerabilities,
  calculateOverallScore
} from '../services/scannerService';

describe('Scanner Service', () => {
  describe('performSecurityAssessment', () => {
    it('should return assessment results with score and grade', () => {
      const answers = {
        https: 'yes',
        headers: 'yes',
        cookies: 'yes',
        forms: 'yes',
        inputs: 'yes',
        errors: 'yes',
        version: 'yes',
        robots: 'yes'
      };

      const result = performSecurityAssessment('website', 'https://example.com', answers);

      expect(result).toHaveProperty('score');
      expect(result).toHaveProperty('grade');
      expect(result).toHaveProperty('findings');
      expect(result).toHaveProperty('target', 'https://example.com');
      expect(result).toHaveProperty('targetType', 'website');
      expect(result.score).toBe(100);
      expect(result.grade.letter).toBe('A');
    });

    it('should identify findings when answers are "no"', () => {
      const answers = {
        https: 'no',
        headers: 'no',
        cookies: 'yes',
        forms: 'yes',
        inputs: 'yes',
        errors: 'yes',
        version: 'yes',
        robots: 'yes'
      };

      const result = performSecurityAssessment('website', 'https://example.com', answers);

      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.score).toBeLessThan(100);
      expect(result.findings.some(finding => finding.id === 'https')).toBe(true);
      expect(result.findings.some(finding => finding.id === 'headers')).toBe(true);
    });

    it('should treat "unknown" as a finding', () => {
      const answers = {
        https: 'yes',
        headers: 'unknown',
        cookies: 'yes',
        forms: 'yes',
        inputs: 'yes',
        errors: 'yes',
        version: 'yes',
        robots: 'yes'
      };

      const result = performSecurityAssessment('website', 'https://example.com', answers);

      expect(result.findings.length).toBe(1);
      expect(result.findings[0].id).toBe('headers');
      expect(result.findings[0].status).toBe('unknown');
    });

    it('should include recommendations for each finding', () => {
      const answers = {
        https: 'no',
        headers: 'yes',
        cookies: 'yes',
        forms: 'yes',
        inputs: 'yes',
        errors: 'yes',
        version: 'yes',
        robots: 'yes'
      };

      const result = performSecurityAssessment('website', 'https://example.com', answers);

      expect(result.findings[0]).toHaveProperty('recommendation');
      expect(result.findings[0].recommendation).toBeTruthy();
    });

    it('should calculate correct grade based on score', () => {
      // All no - should be F
      const allNo = {
        https: 'no',
        headers: 'no',
        cookies: 'no',
        forms: 'no',
        inputs: 'no',
        errors: 'no',
        version: 'no',
        robots: 'no'
      };

      const result = performSecurityAssessment('website', 'https://example.com', allNo);
      expect(result.score).toBe(0);
      expect(result.grade.letter).toBe('F');
    });
  });

  describe('getVulnerabilitiesByCategory', () => {
    it('should return vulnerabilities for website category', () => {
      const vulns = getVulnerabilitiesByCategory('website');
      expect(Array.isArray(vulns)).toBe(true);
      expect(vulns.length).toBeGreaterThan(0);
      expect(vulns[0]).toHaveProperty('id');
      expect(vulns[0]).toHaveProperty('name');
      expect(vulns[0]).toHaveProperty('severity');
    });

    it('should return vulnerabilities for email category', () => {
      const vulns = getVulnerabilitiesByCategory('email');
      expect(vulns.length).toBeGreaterThan(0);
    });

    it('should return vulnerabilities for server category', () => {
      const vulns = getVulnerabilitiesByCategory('server');
      expect(vulns.length).toBeGreaterThan(0);
    });

    it('should return empty array for unknown category', () => {
      const vulns = getVulnerabilitiesByCategory('unknown');
      expect(vulns).toEqual([]);
    });
  });

  describe('getChecklist', () => {
    it('should return checklist for website', () => {
      const checklist = getChecklist('website');
      expect(Array.isArray(checklist)).toBe(true);
      expect(checklist.length).toBeGreaterThan(0);
      expect(checklist[0]).toHaveProperty('id');
      expect(checklist[0]).toHaveProperty('label');
      expect(checklist[0]).toHaveProperty('severity');
    });

    it('should return checklist for all supported types', () => {
      const types = ['website', 'email', 'server', 'application', 'data'];
      types.forEach(type => {
        const checklist = getChecklist(type);
        expect(checklist.length).toBeGreaterThan(0);
      });
    });

    it('should return empty array for unknown type', () => {
      const checklist = getChecklist('unknown');
      expect(checklist).toEqual([]);
    });
  });

  describe('searchVulnerabilities', () => {
    it('should find vulnerabilities by name', () => {
      const results = searchVulnerabilities('SQL');
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].name.toLowerCase()).toContain('sql');
    });

    it('should find vulnerabilities by description', () => {
      const results = searchVulnerabilities('password');
      expect(results.length).toBeGreaterThan(0);
    });

    it('should return empty array for no matches', () => {
      const results = searchVulnerabilities('xyznonexistent123');
      expect(results).toEqual([]);
    });

    it('should be case insensitive', () => {
      const lower = searchVulnerabilities('https');
      const upper = searchVulnerabilities('HTTPS');
      expect(lower.length).toBe(upper.length);
    });
  });

  describe('calculateOverallScore', () => {
    it('should calculate average of assessment scores', () => {
      const assessments = [
        { score: 80 },
        { score: 60 },
        { score: 100 }
      ];
      expect(calculateOverallScore(assessments)).toBe(80);
    });

    it('should return 0 for empty array', () => {
      expect(calculateOverallScore([])).toBe(0);
    });

    it('should return 0 for null/undefined', () => {
      expect(calculateOverallScore(null)).toBe(0);
      expect(calculateOverallScore(undefined)).toBe(0);
    });
  });
});
