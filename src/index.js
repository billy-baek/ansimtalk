import express from 'express';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { analyzeMessage, heuristicUrlCheck, extractUrls, getPatternDbInfo, kisaLookup } from './analyzer.js';
import { safeBrowsingLookup, virusTotalLookup, phoneOfficialChannels, accountOfficialChannels } from './external.js';
import { GUIDES, SITUATIONS, EMERGENCY_CONTACTS } from './guides.js';

const PORT = process.env.PORT ?? 3020;

// PlayMCP 심사 요건: 모든 툴 description에 서비스명 포함 + annotations 정의
const SVC = '안심톡 - 스미싱·보이스피싱 판별';
// 모든 툴이 읽기 전용(데이터 변경 없음)이며 파괴적 동작 없음
const READONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true };

function buildServer() {
  const server = new McpServer({
    name: 'ansimtalk',
    version: '0.1.0'
  });

  server.registerTool(
    'analyze_message',
    {
      title: '문자 사기 여부 분석',
      description:
        `[${SVC}] 수상한 문자·카톡 메시지 원문을 넣으면 스미싱/보이스피싱 패턴 DB와 대조해 위험도 점수(0~100), 매칭된 사기 유형, 근거를 반환한다. 사기 여부가 궁금한 메시지는 항상 이 도구로 먼저 분석할 것.`,
      inputSchema: { message: z.string().min(1).max(5000).describe('의심스러운 문자/메시지 원문 전체') },
      annotations: { title: `${SVC} · 문자 사기 여부 분석`, ...READONLY, openWorldHint: true }
    },
    async ({ message }) => {
      const result = analyzeMessage(message);
      // 메시지 안에 URL이 있으면 KISA 블록리스트 + 평판 조회까지 한 번에
      if (result.urls_found.length > 0) {
        const kisaHits = result.urls_found
          .map((u) => kisaLookup(heuristicUrlCheck(u).hostname))
          .filter(Boolean);
        const sb = await safeBrowsingLookup(result.urls_found);
        result.url_reputation = { kisa_blocklist: kisaHits, safe_browsing: sb };
        if (kisaHits.length > 0 || (sb.available && sb.flagged?.length > 0)) {
          result.risk_score = 100;
          result.risk_level = 'danger';
          result.risk_level_ko = '위험 (사기 가능성 매우 높음)';
        }
      }
      result.recommended_action = GUIDES[result.risk_level];
      return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.registerTool(
    'check_url',
    {
      title: '링크(URL) 위험도 조회',
      description: `[${SVC}] 링크 주소가 피싱/악성 사이트로 신고되었는지 KISA 피싱 데이터·구글 세이프브라우징·VirusTotal 평판과 휴리스틱으로 검사한다.`,
      inputSchema: { url: z.string().min(4).max(2000).describe('검사할 URL (문자에 포함된 링크)') },
      annotations: { title: `${SVC} · 링크 위험도 조회`, ...READONLY, openWorldHint: true }
    },
    async ({ url }) => {
      const target = extractUrls(url)[0] ?? url;
      const heuristic = heuristicUrlCheck(target);
      const kisa = kisaLookup(heuristic.hostname);
      const [sb, vt] = await Promise.all([safeBrowsingLookup([target]), virusTotalLookup(target)]);
      const flagged = Boolean(kisa) || (sb.available && sb.flagged.length > 0) || (vt.available && vt.flagged === true);
      const suspicious = flagged || heuristic.signals.length > 0;
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            url: target,
            verdict: flagged ? 'danger' : suspicious ? 'warning' : 'no_signal',
            verdict_ko: flagged ? '신고된 위험 사이트' : suspicious ? '의심 신호 있음' : '알려진 위험 신호 없음',
            sources: { kisa_blocklist: kisa, safe_browsing: sb, virustotal: vt },
            heuristic_signals: heuristic.signals,
            disclaimer: '신호가 없다고 안전이 보장되지는 않습니다. 모르는 번호가 보낸 링크는 누르지 않는 것이 안전합니다.'
          }, null, 2)
        }]
      };
    }
  );

  server.registerTool(
    'check_phone',
    {
      title: '전화번호 신고 이력 조회',
      description: `[${SVC}] 전화번호가 사기(보이스피싱·스미싱)로 신고된 이력이 있는지 발신 패턴 휴리스틱으로 점검하고 경찰청 공식 조회 채널을 안내한다.`,
      inputSchema: { phone: z.string().min(4).max(20).describe('조회할 전화번호 (하이픈 유무 무관)') },
      annotations: { title: `${SVC} · 전화번호 신고 이력 조회`, ...READONLY, openWorldHint: false }
    },
    async ({ phone }) => {
      const normalized = phone.replace(/[-\s]/g, '');
      const signals = [];
      if (/^\+(?!82)/.test(phone.trim()) || /^00[0-9]/.test(normalized)) {
        signals.push('국제전화 발신 — 국내 기관·택배를 사칭하는 국제번호는 사기 가능성이 높음');
      }
      if (/^0507/.test(normalized)) signals.push('가상번호(0507) — 발신자를 특정할 수 없음');
      if (/^070/.test(normalized)) signals.push('인터넷전화(070) — 기관 사칭에 자주 쓰이는 번호대');
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            phone: normalized,
            heuristic_signals: signals,
            official_lookup: {
              note: '신고 이력은 경찰청 공식 서비스에서 무료로 즉시 확인할 수 있습니다. 아래 안내를 사용자에게 알기 쉽게 전달하세요.',
              channels: phoneOfficialChannels(normalized)
            }
          }, null, 2)
        }]
      };
    }
  );

  server.registerTool(
    'check_account',
    {
      title: '계좌번호 사기 이력 조회',
      description: `[${SVC}] 송금 전 계좌번호가 사기 이용 계좌로 신고되었는지 경찰청 공식 조회 채널을 안내하고 안전 수칙을 제공한다.`,
      inputSchema: { account: z.string().min(6).max(30).describe('조회할 계좌번호'), bank: z.string().optional().describe('은행명 (선택)') },
      annotations: { title: `${SVC} · 계좌번호 사기 이력 조회`, ...READONLY, openWorldHint: false }
    },
    async ({ account, bank }) => {
      const normalized = account.replace(/[-\s]/g, '');
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            account: normalized, bank: bank ?? null,
            official_lookup: {
              note: '사기 신고 이력은 경찰청 공식 서비스에서 무료로 즉시 확인할 수 있습니다. 아래 안내를 사용자에게 알기 쉽게 전달하세요.',
              channels: accountOfficialChannels(normalized)
            },
            advice: '모르는 사람에게 송금하기 전에는 반드시 상대를 전화·영상으로 직접 확인하세요. 이미 보냈다면 즉시 112 또는 1332로 지급정지를 신청하세요.'
          }, null, 2)
        }]
      };
    }
  );

  server.registerTool(
    'what_to_do',
    {
      title: '사기 대처 방법 안내',
      description:
        `[${SVC}] 상황별 대처법을 어르신 눈높이로 안내한다. situation: clicked_link(링크를 눌렀어요), sent_money(돈을 보냈어요), gave_info(개인정보를 알려줬어요), installed_app(앱을 설치했어요), general(일반 예방수칙)`,
      inputSchema: {
        situation: z.enum(['clicked_link', 'sent_money', 'gave_info', 'installed_app', 'general']).describe('현재 상황')
      },
      annotations: { title: `${SVC} · 사기 대처 방법 안내`, ...READONLY, openWorldHint: false }
    },
    async ({ situation }) => {
      const guide = situation === 'general'
        ? { title: '사기 예방 기본 수칙', steps: GUIDES.warning.steps }
        : SITUATIONS[situation];
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ ...guide, emergency_contacts: EMERGENCY_CONTACTS }, null, 2)
        }]
      };
    }
  );

  return server;
}

// ── Streamable HTTP (stateless) ────────────────────────────────────
const app = express();
app.use(express.json({ limit: '100kb' }));

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'ansimtalk-mcp', pattern_db: getPatternDbInfo() });
});

app.post('/mcp', async (req, res) => {
  // stateless: 요청마다 새 server/transport (세션 관리 불필요, 수평 확장 안전)
  try {
    const server = buildServer();
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => { transport.close(); server.close(); });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    console.error('MCP request error:', e);
    if (!res.headersSent) {
      res.status(500).json({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal server error' }, id: null });
    }
  }
});

// 세션 기반 GET/DELETE는 stateless 모드에서 미지원
app.get('/mcp', (_req, res) => res.status(405).json({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed' }, id: null }));
app.delete('/mcp', (_req, res) => res.status(405).json({ jsonrpc: '2.0', error: { code: -32000, message: 'Method not allowed' }, id: null }));

app.listen(PORT, () => {
  console.log(`안심톡 MCP 서버 실행 중 → http://localhost:${PORT}/mcp (health: /health)`);
});
