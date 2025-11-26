import { describe, it, expect } from 'vitest';
import {
  vulnerabilityDatabase,
  severityLevels,
  scanningChecklists,
  learningModules,
  vulnerabilityCategories
} from '../data/securityKnowledge';

describe('Security Knowledge Base', () => {
  describe('vulnerabilityCategories', () => {
    it('should contain all expected categories', () => {
      expect(vulnerabilityCategories).toHaveProperty('WEBSITE');
      expect(vulnerabilityCategories).toHaveProperty('EMAIL');
      expect(vulnerabilityCategories).toHaveProperty('SERVER');
      expect(vulnerabilityCategories).toHaveProperty('APPLICATION');
      expect(vulnerabilityCategories).toHaveProperty('DATA');
    });
  });

  describe('severityLevels', () => {
    it('should contain all severity levels with required properties', () => {
      const levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
      levels.forEach(level => {
        expect(severityLevels[level]).toHaveProperty('name');
        expect(severityLevels[level]).toHaveProperty('color');
        expect(severityLevels[level]).toHaveProperty('score');
      });
    });

    it('should have scores in decreasing order', () => {
      expect(severityLevels.CRITICAL.score).toBeGreaterThan(severityLevels.HIGH.score);
      expect(severityLevels.HIGH.score).toBeGreaterThan(severityLevels.MEDIUM.score);
      expect(severityLevels.MEDIUM.score).toBeGreaterThan(severityLevels.LOW.score);
      expect(severityLevels.LOW.score).toBeGreaterThan(severityLevels.INFO.score);
    });
  });

  describe('vulnerabilityDatabase', () => {
    const categories = ['website', 'email', 'server', 'application', 'data'];

    categories.forEach(category => {
      describe(`${category} vulnerabilities`, () => {
        it('should have at least one vulnerability', () => {
          expect(vulnerabilityDatabase[category].length).toBeGreaterThan(0);
        });

        it('should have required properties on each vulnerability', () => {
          vulnerabilityDatabase[category].forEach(vuln => {
            expect(vuln).toHaveProperty('id');
            expect(vuln).toHaveProperty('name');
            expect(vuln).toHaveProperty('category', category);
            expect(vuln).toHaveProperty('severity');
            expect(vuln).toHaveProperty('description');
            expect(vuln).toHaveProperty('impact');
            expect(vuln).toHaveProperty('detection');
            expect(vuln).toHaveProperty('howToFix');
            expect(Array.isArray(vuln.howToFix)).toBe(true);
            expect(vuln.howToFix.length).toBeGreaterThan(0);
          });
        });

        it('should have valid severity levels', () => {
          const validSeverities = Object.keys(severityLevels);
          vulnerabilityDatabase[category].forEach(vuln => {
            expect(validSeverities).toContain(vuln.severity);
          });
        });
      });
    });
  });

  describe('scanningChecklists', () => {
    const categories = ['website', 'email', 'server', 'application', 'data'];

    categories.forEach(category => {
      describe(`${category} checklist`, () => {
        it('should have at least one check item', () => {
          expect(scanningChecklists[category].length).toBeGreaterThan(0);
        });

        it('should have required properties on each check', () => {
          scanningChecklists[category].forEach(check => {
            expect(check).toHaveProperty('id');
            expect(check).toHaveProperty('label');
            expect(check).toHaveProperty('severity');
          });
        });

        it('should have valid severity levels', () => {
          const validSeverities = Object.keys(severityLevels);
          scanningChecklists[category].forEach(check => {
            expect(validSeverities).toContain(check.severity);
          });
        });

        it('should have unique IDs', () => {
          const ids = scanningChecklists[category].map(c => c.id);
          const uniqueIds = new Set(ids);
          expect(uniqueIds.size).toBe(ids.length);
        });
      });
    });
  });

  describe('learningModules', () => {
    it('should have at least one module', () => {
      expect(learningModules.length).toBeGreaterThan(0);
    });

    it('should have required properties on each module', () => {
      learningModules.forEach(module => {
        expect(module).toHaveProperty('id');
        expect(module).toHaveProperty('title');
        expect(module).toHaveProperty('description');
        expect(module).toHaveProperty('topics');
        expect(module).toHaveProperty('duration');
        expect(module).toHaveProperty('level');
        expect(Array.isArray(module.topics)).toBe(true);
        expect(module.topics.length).toBeGreaterThan(0);
      });
    });

    it('should have valid levels', () => {
      const validLevels = ['Beginner', 'Intermediate', 'Advanced'];
      learningModules.forEach(module => {
        expect(validLevels).toContain(module.level);
      });
    });
  });
});
