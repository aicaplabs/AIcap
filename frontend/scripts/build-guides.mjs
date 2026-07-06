// Build-time generator for the SEO guide pages (Wave 14).
//
// Reads frontend/guides/*.md (simple key: value frontmatter between ---
// fences), renders each to a fully static, crawlable HTML page in
// frontend/public/guides/, plus an index page. Runs before `vite build`
// (see package.json), so Vercel regenerates the pages on every deploy —
// no SPA hydration, no client JS, nothing for a crawler to miss.
//
// The markdown renderer is reused from src/lib/annexIVPdf.js — it is
// pure string code with no DOM dependency.

import { readdir, readFile, writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { markdownToHtml } from '../src/lib/annexIVPdf.js';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const srcDir = path.join(root, 'guides');
const outDir = path.join(root, 'public', 'guides');

const SITE = 'https://aicap.vercel.app';

function parseFrontmatter(raw) {
  const m = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/);
  if (!m) throw new Error('missing frontmatter');
  const meta = {};
  for (const line of m[1].split(/\r?\n/)) {
    const kv = line.match(/^(\w+):\s*(.*)$/);
    if (kv) meta[kv[1]] = kv[2].trim();
  }
  for (const key of ['title', 'description', 'date']) {
    if (!meta[key]) throw new Error(`frontmatter missing "${key}"`);
  }
  return { meta, body: m[2] };
}

const PAGE_CSS = `
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { font-family: "Segoe UI", system-ui, -apple-system, sans-serif; color: #1e293b;
         line-height: 1.65; margin: 0; background: #f8fafc; }
  header { background: #fff; border-bottom: 1px solid #e2e8f0; padding: 14px 24px;
           display: flex; justify-content: space-between; align-items: center; }
  header a.brand { font-weight: 800; color: #0f172a; text-decoration: none; font-size: 17px; }
  header a.brand span { color: #4f46e5; }
  header a.cta { background: #4f46e5; color: #fff; font-weight: 700; text-decoration: none;
                 padding: 8px 14px; border-radius: 8px; font-size: 14px; }
  main { max-width: 760px; margin: 0 auto; padding: 40px 24px 80px; }
  article { background: #fff; border: 1px solid #e2e8f0; border-radius: 16px; padding: 40px; }
  h1 { font-size: 28px; line-height: 1.25; color: #0f172a; margin: 0 0 8px; }
  h2 { font-size: 20px; color: #0f172a; margin: 32px 0 8px; }
  h3 { font-size: 16px; color: #1e293b; margin: 24px 0 6px; }
  p { margin: 10px 0; } ul { padding-left: 22px; } li { margin: 6px 0; }
  em { color: #64748b; }
  code { background: #f1f5f9; border: 1px solid #e2e8f0; border-radius: 4px;
         padding: 1px 5px; font-size: 13px; font-family: Consolas, monospace; }
  pre { background: #0f172a; color: #e2e8f0; border-radius: 10px; padding: 16px 18px;
        overflow-x: auto; font-size: 13px; }
  pre code { background: none; border: none; padding: 0; color: inherit; }
  table { border-collapse: collapse; width: 100%; font-size: 13px; margin: 14px 0; display: block; overflow-x: auto; }
  th, td { border: 1px solid #cbd5e1; padding: 6px 9px; text-align: left; }
  th { background: #eef2ff; }
  .meta { color: #64748b; font-size: 13px; margin-bottom: 24px; }
  .cta-box { margin-top: 36px; padding: 22px; background: #eef2ff; border-radius: 12px; }
  .cta-box p { margin: 0 0 12px; font-weight: 600; color: #312e81; }
  .cta-box a { background: #4f46e5; color: #fff; font-weight: 700; text-decoration: none;
               padding: 10px 16px; border-radius: 8px; font-size: 14px; display: inline-block; }
  ul.guide-list { list-style: none; padding: 0; }
  ul.guide-list li { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px;
                     padding: 18px 22px; margin: 12px 0; }
  ul.guide-list a { color: #0f172a; font-weight: 700; text-decoration: none; font-size: 17px; }
  ul.guide-list a:hover { color: #4f46e5; }
  ul.guide-list p { color: #475569; font-size: 14px; margin: 6px 0 0; }
`;

function pageShell({ title, description, canonical, jsonLd, bodyHtml }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeAttr(title)}</title>
<meta name="description" content="${escapeAttr(description)}">
<link rel="canonical" href="${canonical}">
<meta property="og:title" content="${escapeAttr(title)}">
<meta property="og:description" content="${escapeAttr(description)}">
<meta property="og:type" content="article">
<meta property="og:url" content="${canonical}">
<script type="application/ld+json">${JSON.stringify(jsonLd)}</script>
<style>${PAGE_CSS}</style>
</head>
<body>
<header>
  <a class="brand" href="/">🛡️ AI<span>cap</span></a>
  <a class="cta" href="/">Scan your repo free</a>
</header>
<main>
${bodyHtml}
</main>
</body>
</html>`;
}

function escapeAttr(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
}

const guides = [];
await mkdir(outDir, { recursive: true });

for (const file of (await readdir(srcDir)).filter(f => f.endsWith('.md')).sort()) {
  const slug = file.replace(/\.md$/, '');
  const { meta, body } = parseFrontmatter(await readFile(path.join(srcDir, file), 'utf8'));
  const canonical = `${SITE}/guides/${slug}.html`;
  const article = `<article>
<div class="meta">${meta.date} · AIcap Guides</div>
${markdownToHtml(body)}
<div class="cta-box">
  <p>AIcap generates your AI-BOM, risk register, and Annex IV draft from a single CI run — free CLI, EU-hosted ledger.</p>
  <a href="/">Get started free →</a>
</div>
</article>`;
  const html = pageShell({
    title: `${meta.title} | AIcap Guides`,
    description: meta.description,
    canonical,
    jsonLd: {
      '@context': 'https://schema.org',
      '@type': 'Article',
      headline: meta.title,
      description: meta.description,
      datePublished: meta.date,
      author: { '@type': 'Organization', name: 'AIcap' },
      mainEntityOfPage: canonical,
    },
    bodyHtml: article,
  });
  await writeFile(path.join(outDir, `${slug}.html`), html);
  guides.push({ slug, ...meta });
}

// Index page.
const indexHtml = pageShell({
  title: 'EU AI Act Compliance Guides | AIcap',
  description:
    'Practical, engineering-first guides to EU AI Act compliance: Annex IV documentation, AI-BOM generation, risk registers, and CI/CD automation.',
  canonical: `${SITE}/guides/`,
  jsonLd: {
    '@context': 'https://schema.org',
    '@type': 'CollectionPage',
    name: 'EU AI Act Compliance Guides',
    url: `${SITE}/guides/`,
  },
  bodyHtml: `<h1>EU AI Act Compliance Guides</h1>
<p class="meta">Engineering-first answers to the questions every AI team in the EU is asking right now.</p>
<ul class="guide-list">
${guides
    .map(
      g => `<li><a href="/guides/${g.slug}.html">${escapeAttr(g.title)}</a><p>${escapeAttr(g.description)}</p></li>`,
    )
    .join('\n')}
</ul>`,
});
await writeFile(path.join(outDir, 'index.html'), indexHtml);

// sitemap.xml + robots.txt at the site root — the landing page is an
// SPA, so the guides are the crawlable surface; make sure crawlers can
// enumerate them without depending on link discovery.
const urls = [
  { loc: `${SITE}/`, priority: '1.0' },
  { loc: `${SITE}/guides/`, priority: '0.8' },
  ...guides.map(g => ({
    loc: `${SITE}/guides/${g.slug}.html`,
    lastmod: g.date,
    priority: '0.7',
  })),
];
const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls
    .map(
      u => `  <url><loc>${u.loc}</loc>${u.lastmod ? `<lastmod>${u.lastmod}</lastmod>` : ''}<priority>${u.priority}</priority></url>`,
    )
    .join('\n')}
</urlset>
`;
await writeFile(path.join(root, 'public', 'sitemap.xml'), sitemap);
await writeFile(
  path.join(root, 'public', 'robots.txt'),
  `User-agent: *\nAllow: /\nSitemap: ${SITE}/sitemap.xml\n`,
);

console.log(`built ${guides.length} guide(s) + index + sitemap → public/`);
