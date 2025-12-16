/**
 * Tests for grade utilities
 */
import { describe, it, expect } from 'vitest';
import { calculateGrade, getGradeColor, GRADE_COLORS } from '../utils/gradeUtils';

describe('Grade Utilities', () => {
  describe('calculateGrade', () => {
    it('should return A grade for scores 90 and above', () => {
      expect(calculateGrade(90)).toEqual({ letter: 'A', description: 'Excellent' });
      expect(calculateGrade(95)).toEqual({ letter: 'A', description: 'Excellent' });
      expect(calculateGrade(100)).toEqual({ letter: 'A', description: 'Excellent' });
    });

    it('should return B grade for scores 80-89', () => {
      expect(calculateGrade(80)).toEqual({ letter: 'B', description: 'Good' });
      expect(calculateGrade(85)).toEqual({ letter: 'B', description: 'Good' });
      expect(calculateGrade(89)).toEqual({ letter: 'B', description: 'Good' });
    });

    it('should return C grade for scores 70-79', () => {
      expect(calculateGrade(70)).toEqual({ letter: 'C', description: 'Fair' });
      expect(calculateGrade(75)).toEqual({ letter: 'C', description: 'Fair' });
      expect(calculateGrade(79)).toEqual({ letter: 'C', description: 'Fair' });
    });

    it('should return D grade for scores 60-69', () => {
      expect(calculateGrade(60)).toEqual({ letter: 'D', description: 'Poor' });
      expect(calculateGrade(65)).toEqual({ letter: 'D', description: 'Poor' });
      expect(calculateGrade(69)).toEqual({ letter: 'D', description: 'Poor' });
    });

    it('should return F grade for scores below 60', () => {
      expect(calculateGrade(59)).toEqual({ letter: 'F', description: 'Critical' });
      expect(calculateGrade(50)).toEqual({ letter: 'F', description: 'Critical' });
      expect(calculateGrade(0)).toEqual({ letter: 'F', description: 'Critical' });
    });
  });

  describe('getGradeColor', () => {
    it('should return correct color for each grade letter', () => {
      expect(getGradeColor('A')).toBe(GRADE_COLORS.A);
      expect(getGradeColor('B')).toBe(GRADE_COLORS.B);
      expect(getGradeColor('C')).toBe(GRADE_COLORS.C);
      expect(getGradeColor('D')).toBe(GRADE_COLORS.D);
      expect(getGradeColor('F')).toBe(GRADE_COLORS.F);
    });

    it('should return default color for unknown grade', () => {
      expect(getGradeColor('X')).toBe('#888');
      expect(getGradeColor('')).toBe('#888');
      expect(getGradeColor(null)).toBe('#888');
    });

    it('should return valid hex colors', () => {
      const hexColorRegex = /^#[0-9a-f]{6}$/i;
      expect(getGradeColor('A')).toMatch(hexColorRegex);
      expect(getGradeColor('B')).toMatch(hexColorRegex);
      expect(getGradeColor('C')).toMatch(hexColorRegex);
      expect(getGradeColor('D')).toMatch(hexColorRegex);
      expect(getGradeColor('F')).toMatch(hexColorRegex);
    });
  });

  describe('GRADE_COLORS constant', () => {
    it('should have all required grade colors', () => {
      expect(GRADE_COLORS).toHaveProperty('A');
      expect(GRADE_COLORS).toHaveProperty('B');
      expect(GRADE_COLORS).toHaveProperty('C');
      expect(GRADE_COLORS).toHaveProperty('D');
      expect(GRADE_COLORS).toHaveProperty('F');
    });

    it('should have valid hex color values', () => {
      const hexColorRegex = /^#[0-9a-f]{6}$/i;
      Object.values(GRADE_COLORS).forEach(color => {
        expect(color).toMatch(hexColorRegex);
      });
    });
  });
});
