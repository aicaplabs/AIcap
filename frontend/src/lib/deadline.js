// EU AI Act application date for the bulk of obligations, including
// high-risk system requirements (Art. 113): 2 August 2026. The landing
// page counts down to this date; once it passes, the urgency framing
// flips from "deadline approaching" to "obligations in force" so the
// copy never goes stale.
export const AI_ACT_DEADLINE = new Date('2026-08-02T00:00:00Z');

// Whole days remaining until the deadline (ceiling, so the morning of
// 1 August still reads "1 day"). Zero or negative means it has passed.
export function daysUntilAIAct(now = new Date()) {
  return Math.ceil((AI_ACT_DEADLINE - now) / 86400000);
}
