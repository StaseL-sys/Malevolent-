/**
 * Tests for target type constants
 */
import { describe, it, expect } from 'vitest';
import { TARGET_TYPES, TARGET_INPUT_CONFIG, getTargetTypeById, getInputConfig } from '../constants/targetTypes';

describe('Target Type Constants', () => {
  describe('TARGET_TYPES', () => {
    it('should have all 10 target types', () => {
      expect(TARGET_TYPES).toHaveLength(10);
    });

    it('should have required properties for each target type', () => {
      TARGET_TYPES.forEach(type => {
        expect(type).toHaveProperty('id');
        expect(type).toHaveProperty('name');
        expect(type).toHaveProperty('shortName');
        expect(type).toHaveProperty('icon');
        expect(type).toHaveProperty('description');
      });
    });

    it('should have unique IDs', () => {
      const ids = TARGET_TYPES.map(type => type.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(TARGET_TYPES.length);
    });

    it('should include all expected target types', () => {
      const expectedTypes = ['website', 'email', 'server', 'application', 'data', 'finance', 'iot', 'network', 'cloud', 'threats'];
      const actualTypes = TARGET_TYPES.map(type => type.id);
      expectedTypes.forEach(type => {
        expect(actualTypes).toContain(type);
      });
    });

    it('should have non-empty descriptions', () => {
      TARGET_TYPES.forEach(type => {
        expect(type.description.length).toBeGreaterThan(0);
      });
    });

    it('should have icons (emojis)', () => {
      TARGET_TYPES.forEach(type => {
        expect(type.icon.length).toBeGreaterThan(0);
      });
    });
  });

  describe('TARGET_INPUT_CONFIG', () => {
    it('should have configuration for all target types', () => {
      const expectedTypes = ['website', 'email', 'server', 'application', 'data', 'finance', 'iot', 'network', 'cloud', 'threats'];
      expectedTypes.forEach(type => {
        expect(TARGET_INPUT_CONFIG).toHaveProperty(type);
      });
    });

    it('should have label and placeholder for each config', () => {
      Object.values(TARGET_INPUT_CONFIG).forEach(config => {
        expect(config).toHaveProperty('label');
        expect(config).toHaveProperty('placeholder');
        expect(config.label.length).toBeGreaterThan(0);
        expect(config.placeholder.length).toBeGreaterThan(0);
      });
    });

    it('should have specific configurations for known types', () => {
      expect(TARGET_INPUT_CONFIG.website.label).toBe('Website URL');
      expect(TARGET_INPUT_CONFIG.website.placeholder).toBe('https://example.com');
      expect(TARGET_INPUT_CONFIG.email.label).toBe('Email Domain');
      expect(TARGET_INPUT_CONFIG.server.label).toBe('Server Address');
    });
  });

  describe('getTargetTypeById', () => {
    it('should return correct target type for valid ID', () => {
      const website = getTargetTypeById('website');
      expect(website).toBeDefined();
      expect(website.id).toBe('website');
      expect(website.name).toBe('Website');
    });

    it('should return undefined for invalid ID', () => {
      const invalid = getTargetTypeById('nonexistent');
      expect(invalid).toBeUndefined();
    });

    it('should work for all target types', () => {
      const targetIds = ['website', 'email', 'server', 'application', 'data', 'finance', 'iot', 'network', 'cloud', 'threats'];
      targetIds.forEach(id => {
        const type = getTargetTypeById(id);
        expect(type).toBeDefined();
        expect(type.id).toBe(id);
      });
    });
  });

  describe('getInputConfig', () => {
    it('should return correct config for valid target type', () => {
      const websiteConfig = getInputConfig('website');
      expect(websiteConfig.label).toBe('Website URL');
      expect(websiteConfig.placeholder).toBe('https://example.com');
    });

    it('should return default config for invalid target type', () => {
      const defaultConfig = getInputConfig('nonexistent');
      expect(defaultConfig.label).toBe('Target');
      expect(defaultConfig.placeholder).toBe('Enter target');
    });

    it('should work for all target types', () => {
      const targetIds = ['website', 'email', 'server', 'application', 'data', 'finance', 'iot', 'network', 'cloud', 'threats'];
      targetIds.forEach(id => {
        const config = getInputConfig(id);
        expect(config).toBeDefined();
        expect(config).toHaveProperty('label');
        expect(config).toHaveProperty('placeholder');
      });
    });

    it('should have unique labels for each type', () => {
      const targetIds = ['website', 'email', 'server', 'application', 'data'];
      const labels = targetIds.map(id => getInputConfig(id).label);
      const uniqueLabels = new Set(labels);
      expect(uniqueLabels.size).toBe(labels.length);
    });
  });
});
