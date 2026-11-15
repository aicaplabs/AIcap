// EU AI Act application date for the high-risk regime (Chapter III,
// Sections 1-3 — which is where Article 11 and Annex IV live) for
// stand-alone Annex III systems: 2 December 2027.
//
// This was 2 August 2026 until Regulation (EU) 2026/1744 (the "Digital
// Omnibus on AI", OJ L 24.7.2026) amended Article 113. The same
// regulation set 2 August 2028 for Annex I systems (AI in regulated
// products). Article 50 transparency duties were NOT moved and have
// applied since 2 August 2026 — the landing copy says so separately,
// because "nothing applies until 2027" would be as wrong as the old
// "everything applies in 2026".
//
// If the date moves again, change it here and in the copy that quotes
// it: LandingAuth.jsx, index.html, public/og-image.svg (+ re-rasterise
// the PNG), and the guides under frontend/guides/.
export const HIGH_RISK_APPLIES = new Date('2027-12-02T00:00:00Z');

// Whole days remaining until the high-risk regime applies (ceiling, so
// the morning of 1 December still reads "1 day"). Zero or negative
// means it has passed.
export function daysUntilHighRisk(now = new Date()) {
  return Math.ceil((HIGH_RISK_APPLIES - now) / 86400000);
}
