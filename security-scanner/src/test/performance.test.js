/**
 * Performance benchmarks for optimized code
 */

import { describe, it, expect } from 'vitest';
import { performSecurityAssessment, searchVulnerabilities } from '../services/scannerService';

describe('Performance Benchmarks', () => {
  describe('searchVulnerabilities performance', () => {
    it('should complete search efficiently with caching', () => {
      const startTime = performance.now();
      
      // First search builds the index
      const results1 = searchVulnerabilities('sql');
      
      const firstSearchTime = performance.now() - startTime;
      
      // Subsequent searches should use cached index
      const secondStart = performance.now();
      const results2 = searchVulnerabilities('xss');
      const secondSearchTime = performance.now() - secondStart;
      
      // Both searches should complete quickly (< 50ms each)
      expect(firstSearchTime).toBeLessThan(50);
      expect(secondSearchTime).toBeLessThan(50);
      
      // Results should be valid
      expect(results1.length).toBeGreaterThan(0);
      expect(results2.length).toBeGreaterThan(0);
    });

    it('should handle empty searches efficiently', () => {
      const startTime = performance.now();
      const results = searchVulnerabilities('');
      const duration = performance.now() - startTime;
      
      expect(duration).toBeLessThan(5);
      expect(results).toEqual([]);
    });

    it('should handle case-insensitive searches without repeated toLowerCase calls', () => {
      const startTime = performance.now();
      
      // Multiple searches with different cases
      searchVulnerabilities('SQL');
      searchVulnerabilities('Sql');
      searchVulnerabilities('sql');
      
      const duration = performance.now() - startTime;
      
      // All three searches together should be fast (< 50ms)
      expect(duration).toBeLessThan(50);
    });
  });

  describe('performSecurityAssessment performance', () => {
    it('should complete assessment efficiently with lookup map', () => {
      const answers = {
        https: 'no',
        headers: 'yes',
        cookies: 'no',
        forms: 'yes',
        inputs: 'no',
        errors: 'yes',
        version: 'no',
        robots: 'yes'
      };
      
      const startTime = performance.now();
      const results = performSecurityAssessment('website', 'https://example.com', answers);
      const duration = performance.now() - startTime;
      
      // Should complete in < 20ms
      expect(duration).toBeLessThan(20);
      
      // Results should be valid
      expect(results.score).toBeGreaterThanOrEqual(0);
      expect(results.score).toBeLessThanOrEqual(100);
      expect(results.findings.length).toBeGreaterThan(0);
    });

    it('should handle large checklists efficiently', () => {
      // Use threats category which has 8 items
      const answers = {
        backups: 'no',
        edr: 'no',
        'patch-mgmt': 'no',
        'mfa-everywhere': 'no',
        'phishing-training': 'no',
        'threat-intel': 'no',
        'incident-response': 'no',
        'network-monitoring': 'no'
      };
      
      const startTime = performance.now();
      const results = performSecurityAssessment('threats', 'Test Org', answers);
      const duration = performance.now() - startTime;
      
      // Should complete quickly even with all items marked as issues
      expect(duration).toBeLessThan(25);
      expect(results.findings.length).toBe(8);
    });

    it('should count severities efficiently in single pass', () => {
      const answers = {
        'private-access': 'no',
        'least-privilege': 'no',
        'secrets-mgmt': 'no',
        'cloud-logging': 'no',
        'encryption': 'no',
        'mfa-cloud': 'no',
        'cspm': 'no'
      };
      
      const startTime = performance.now();
      const results = performSecurityAssessment('cloud', 'AWS Account', answers);
      const duration = performance.now() - startTime;
      
      // Should generate summary efficiently
      expect(duration).toBeLessThan(20);
      expect(results.summary).toBeTruthy();
      expect(typeof results.summary).toBe('string');
    });
  });

  describe('Overall performance characteristics', () => {
    it('should handle multiple consecutive assessments efficiently', () => {
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
      
      const startTime = performance.now();
      
      // Run 10 consecutive assessments
      for (let i = 0; i < 10; i++) {
        performSecurityAssessment('website', `https://example${i}.com`, answers);
      }
      
      const duration = performance.now() - startTime;
      
      // All 10 assessments should complete quickly (< 100ms total)
      expect(duration).toBeLessThan(100);
    });

    it('should handle multiple searches efficiently', () => {
      const searches = ['sql', 'xss', 'csrf', 'encryption', 'phishing', 'malware'];
      
      const startTime = performance.now();
      
      searches.forEach(term => {
        searchVulnerabilities(term);
      });
      
      const duration = performance.now() - startTime;
      
      // All searches should complete quickly (< 100ms total)
      expect(duration).toBeLessThan(100);
    });
  });
});
