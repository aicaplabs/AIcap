import { describe, it, expect } from 'vitest';

import { HIGH_RISK_APPLIES, daysUntilHighRisk } from './deadline.js';

describe('daysUntilHighRisk', () => {
  // Pins the date itself. Regulation (EU) 2026/1744 moved the Annex III
  // high-risk regime from 2 August 2026 to 2 December 2027; the landing
  // page kept counting down to (and then announcing) the old date for
  // months. A change here should be a deliberate, sourced edit.
  it('targets 2 December 2027, the Annex III high-risk application date', () => {
    expect(HIGH_RISK_APPLIES.toISOString()).toBe('2027-12-02T00:00:00.000Z');
  });

  it('counts whole days remaining before the date', () => {
    expect(daysUntilHighRisk(new Date('2027-11-05T12:00:00Z'))).toBe(27);
  });

  it('reads 1 day on the eve of the date', () => {
    expect(daysUntilHighRisk(new Date('2027-12-01T09:00:00Z'))).toBe(1);
  });

  it('is zero or negative once the date has passed', () => {
    expect(daysUntilHighRisk(new Date('2027-12-02T00:00:00Z'))).toBe(0);
    expect(daysUntilHighRisk(new Date('2028-01-15T00:00:00Z'))).toBeLessThan(0);
  });
});
