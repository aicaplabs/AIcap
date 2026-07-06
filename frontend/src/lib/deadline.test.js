import { describe, it, expect } from 'vitest';

import { daysUntilAIAct } from './deadline.js';

describe('daysUntilAIAct', () => {
  it('counts whole days remaining before the deadline', () => {
    expect(daysUntilAIAct(new Date('2026-07-06T12:00:00Z'))).toBe(27);
  });

  it('reads 1 day on the eve of the deadline', () => {
    expect(daysUntilAIAct(new Date('2026-08-01T09:00:00Z'))).toBe(1);
  });

  it('is zero or negative once the deadline has passed', () => {
    expect(daysUntilAIAct(new Date('2026-08-02T00:00:00Z'))).toBe(0);
    expect(daysUntilAIAct(new Date('2026-09-15T00:00:00Z'))).toBeLessThan(0);
  });
});
