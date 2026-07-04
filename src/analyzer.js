import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const db = JSON.parse(readFileSync(join(__dirname, '../data/patterns.json'), 'utf8'));

const compiled = db.patterns.map((p) => ({ ...p, re: new RegExp(p.regex, 'i') }));
const compiledUrl = db.urlSignals.map((p) => ({ ...p, re: new RegExp(p.regex, 'i') }));

const kisaDb = JSON.parse(readFileSync(join(__dirname, '../data/kisa_domains.json'), 'utf8'));
const kisaDomains = new Set(kisaDb.domains);

/** KISA 신고 이력 도메인 조회 — 정확 일치 + 상위 도메인 일치 */
export function kisaLookup(hostname) {
  if (!hostname) return null;
  const h = hostname.toLowerCase();
  const parts = h.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    const candidate = parts.slice(i).join('.');
    if (kisaDomains.has(candidate)) {
      return { matched_domain: candidate, source: kisaDb.source, note: 'KISA에 피싱사이트로 신고된 이력이 있는 도메인' };
    }
  }
  return null;
}

const URL_RE = /https?:\/\/[^\s"'<>]+/gi;

export function extractUrls(text) {
  return [...new Set(text.match(URL_RE) ?? [])];
}

export function extractPhones(text) {
  const re = /(\+?82[-\s]?1[0-9][-\s]?\d{3,4}[-\s]?\d{4}|01[016789][-\s]?\d{3,4}[-\s]?\d{4}|0\d{1,2}[-\s]?\d{3,4}[-\s]?\d{4}|1\d{3}[-\s]?\d{4})/g;
  return [...new Set((text.match(re) ?? []).map((p) => p.replace(/[-\s]/g, '')))];
}

/**
 * 스미싱 패턴 룰 엔진 — 문자 원문을 받아 위험도(0~100)와 매칭 근거를 반환.
 * LLM 판단과 독립적인 결정적(deterministic) 신호를 제공하는 것이 목적.
 */
export function analyzeMessage(text) {
  const hits = [];
  let score = 0;

  for (const p of compiled) {
    const m = text.match(p.re);
    if (m) {
      hits.push({ id: p.id, category: p.category, note: p.note, matched: m[0].slice(0, 60), weight: p.weight });
      score += p.weight;
    }
  }

  const urls = extractUrls(text);
  const urlHits = [];
  for (const u of compiledUrl) {
    const m = text.match(u.re);
    if (m) {
      urlHits.push({ id: u.id, note: u.note, matched: m[0].slice(0, 80), weight: u.weight });
      score += u.weight;
    }
  }
  // 사칭/사기 패턴과 링크가 결합되면 위험도 증폭
  if (urls.length > 0 && hits.some((h) => h.category !== '_signal')) score += 15;

  score = Math.min(100, score);

  const level = score >= 60 ? 'danger' : score >= 30 ? 'warning' : score >= 15 ? 'caution' : 'safe';
  const categories = [...new Set(hits.filter((h) => h.category !== '_signal').map((h) => db.categories[h.category] ?? h.category))];

  return {
    risk_score: score,
    risk_level: level,
    risk_level_ko: { danger: '위험 (사기 가능성 매우 높음)', warning: '경고 (사기 의심)', caution: '주의 (일부 의심 신호)', safe: '특이 신호 없음' }[level],
    matched_categories: categories,
    evidence: hits.map((h) => ({ pattern: h.note, matched_text: h.matched })),
    url_evidence: urlHits.map((h) => ({ signal: h.note, matched_text: h.matched })),
    urls_found: urls,
    phones_found: extractPhones(text),
    disclaimer: '룰 기반 판별 결과입니다. "특이 신호 없음"이 안전을 보장하지는 않습니다.'
  };
}

/** URL 자체에 대한 휴리스틱 검사 (Safe Browsing 결과와 별개로 항상 제공) */
export function heuristicUrlCheck(url) {
  const signals = [];
  for (const u of compiledUrl) {
    if (u.re.test(url)) signals.push({ id: u.id, note: u.note });
  }
  let hostname = null;
  try {
    hostname = new URL(url.startsWith('http') ? url : `http://${url}`).hostname;
    if (hostname.startsWith('xn--')) signals.push({ id: 'url-punycode', note: '퓨니코드 도메인 — 한글/유사문자 위장 가능성' });
    const officialLookalikes = ['korea.kr', 'gov.kr', 'go.kr', 'nhis.or.kr', 'hometax.go.kr', 'police.go.kr'];
    for (const off of officialLookalikes) {
      const bare = off.replace(/\./g, '');
      if (!hostname.endsWith(off) && hostname.replace(/[-.]/g, '').includes(bare)) {
        signals.push({ id: 'url-gov-lookalike', note: `공식 도메인(${off})을 흉내낸 것으로 의심` });
      }
    }
  } catch {
    signals.push({ id: 'url-malformed', note: 'URL 형식이 비정상' });
  }
  return { hostname, signals };
}

export function getPatternDbInfo() {
  return { version: db.version, pattern_count: db.patterns.length, url_signal_count: db.urlSignals.length };
}
