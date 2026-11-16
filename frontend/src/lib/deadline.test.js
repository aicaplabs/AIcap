import { describe, it, expect } from 'vitest';

import {
  HIGH_RISK_APPLIES,
  MARKING_LEGACY_APPLIES,
  MILESTONES,
  daysUntilHighRisk,
  nextMilestone,
} from './deadline.js';

// These pin the dates themselves. Regulation (EU) 2026/1744 moved the
// Annex III high-risk regime from 2 August 2026 to 2 December 2027; the
// landing page kept counting down to (and then announcing) the old date
// for months. A change here should be a deliberate, sourced edit.
describe('AI Act dates', () => {
  it('high-risk (Annex III) applies 2 December 2027', () => {
    expect(HIGH_RISK_APPLIES.toISOString()).toBe('2027-12-02T00:00:00.000Z');
  });

  it('Article 50(2) marking for existing generative systems applies 2 December 2026', () => {
    expect(MARKING_LEGACY_APPLIES.toISOString()).toBe('2026-12-02T00:00:00.000Z');
  });

  it('milestones are in date order', () => {
    const times = MILESTONES.map(m => m.date.getTime());
    expect(times).toEqual([...times].sort((a, b) => a - b));
  });
});

describe('daysUntilHighRisk', () => {
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

describe('nextMilestone', () => {
  it('is the Article 50(2) marking date until it passes', () => {
    const m = nextMilestone(new Date('2026-11-16T10:00:00Z'));
    expect(m.label).toBe('2 December 2026');
    expect(m.days).toBe(16);
    expect(m.upcoming).toMatch(/Article 50\(2\)/);
  });

  it('moves on to the high-risk date the day the marking date arrives', () => {
    const m = nextMilestone(new Date('2026-12-02T00:00:00Z'));
    expect(m.label).toBe('2 December 2027');
    expect(m.days).toBe(365);
  });

  it('is null once every milestone has passed', () => {
    expect(nextMilestone(new Date('2027-12-02T00:00:00Z'))).toBeNull();
  });
});
