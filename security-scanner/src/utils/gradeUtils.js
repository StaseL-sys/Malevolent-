/**
 * Grade calculation and color utilities
 */

/**
 * Grade color mappings
 */
export const GRADE_COLORS = {
  A: '#16a34a',
  B: '#22c55e',
  C: '#ca8a04',
  D: '#ea580c',
  F: '#dc2626'
};

/**
 * Calculate letter grade from score
 */
export function calculateGrade(score) {
  if (score >= 90) return { letter: 'A', description: 'Excellent' };
  if (score >= 80) return { letter: 'B', description: 'Good' };
  if (score >= 70) return { letter: 'C', description: 'Fair' };
  if (score >= 60) return { letter: 'D', description: 'Poor' };
  return { letter: 'F', description: 'Critical' };
}

/**
 * Get color for a grade letter
 */
export function getGradeColor(letter) {
  return GRADE_COLORS[letter] || '#888';
}
