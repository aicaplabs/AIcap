// EU AI Act application dates the landing page talks about, as amended by
// Regulation (EU) 2026/1744 (the "Digital Omnibus on AI", OJ L 24.7.2026).
//
// The Act applies in stages, and the page used to compress them into one
// "the deadline" — first 2 August 2026 for everything, which was never
// accurate, then a single high-risk date. The badge now counts down to
// whichever dated obligation comes next, and names it:
//
//   2 Dec 2026  Article 50(2) machine-readable marking, for generative
//               systems that were already on the market before 2 Aug 2026
//               (Article 111 transitional rule). New systems have had the
//               duty since 2 Aug 2026.
//   2 Dec 2027  High-risk regime (Chapter III, Sections 1-3 — Article 11
//               and Annex IV live here) for stand-alone Annex III systems.
//
// Article 5 (since 2 Feb 2025) and the rest of Article 50 (since 2 Aug
// 2026) are already in force and are stated in the hero copy rather than
// counted down to. Annex I high-risk systems follow on 2 Aug 2028.
//
// If a date moves again, change it here and in the copy that quotes it:
// LandingAuth.jsx, index.html, public/og-image.svg (+ re-rasterise the
// PNG), and the guides under frontend/guides/.
export const MARKING_LEGACY_APPLIES = new Date('2026-12-02T00:00:00Z');
export const HIGH_RISK_APPLIES = new Date('2027-12-02T00:00:00Z');

// In date order. `upcoming` completes "N days until …"; `passed` is the
// sentence shown once every milestone is behind us.
export const MILESTONES = [
  {
    date: MARKING_LEGACY_APPLIES,
    label: '2 December 2026',
    upcoming: 'content marking applies to existing generative AI systems (Article 50(2))',
  },
  {
    date: HIGH_RISK_APPLIES,
    label: '2 December 2027',
    upcoming: 'high-risk obligations apply',
    passed: 'High-risk obligations have applied since 2 December 2027',
  },
];

const DAY_MS = 86400000;

// Whole days from `now` until `date` (ceiling, so the morning of the day
// before still reads "1 day"). Zero or negative means it has passed.
function daysUntil(date, now) {
  return Math.ceil((date - now) / DAY_MS);
}

// Days until the high-risk regime applies.
export function daysUntilHighRisk(now = new Date()) {
  return daysUntil(HIGH_RISK_APPLIES, now);
}

// The next dated obligation still ahead of `now`, with the days left, or
// null once all of them have passed.
export function nextMilestone(now = new Date()) {
  for (const m of MILESTONES) {
    const days = daysUntil(m.date, now);
    if (days > 0) return { ...m, days };
  }
  return null;
}
