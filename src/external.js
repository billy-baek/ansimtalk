/**
 * 외부 데이터 소스 연동 (환경변수로 게이트).
 * 키가 없으면 { available: false }를 반환하고, 호출부는 로컬 신호(KISA·휴리스틱)만으로 응답한다.
 *
 * 리서치 결론(2026-07):
 * - URL 평판: Safe Browsing(무료·즉시발급) + VirusTotal(500회/일) + URLhaus — 모두 개인 무료
 * - 전화번호/계좌 실시간 조회 공개 API는 한국에 없음(더치트는 사업자 전용)
 *   → 공식 웹 조회 링크 안내로 대체 (counterscam112, 경찰청 사이버안전지킴이)
 */

const SAFE_BROWSING_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY ?? null;
const VIRUSTOTAL_KEY = process.env.VIRUSTOTAL_KEY ?? null;

/** Google Safe Browsing Lookup API v4 — 피싱/멀웨어 URL 평판 조회 */
export async function safeBrowsingLookup(urls) {
  if (!SAFE_BROWSING_KEY) return { available: false, source: 'Google Safe Browsing', reason: 'API 키 미설정' };
  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(5000),
        body: JSON.stringify({
          client: { clientId: 'ansimtalk-mcp', clientVersion: '0.1.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: urls.map((url) => ({ url }))
          }
        })
      }
    );
    if (!res.ok) return { available: false, source: 'Google Safe Browsing', reason: `HTTP ${res.status}` };
    const data = await res.json();
    return {
      available: true,
      source: 'Google Safe Browsing',
      flagged: (data.matches ?? []).map((m) => ({ url: m.threat?.url, threat_type: m.threatType }))
    };
  } catch (e) {
    return { available: false, source: 'Google Safe Browsing', reason: `조회 실패: ${e.message}` };
  }
}

/** VirusTotal URL 리포트 — 70+ 엔진 교차검증 (무료 500회/일, 4회/분) */
export async function virusTotalLookup(url) {
  if (!VIRUSTOTAL_KEY) return { available: false, source: 'VirusTotal', reason: 'API 키 미설정' };
  try {
    const id = Buffer.from(url).toString('base64url');
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { 'x-apikey': VIRUSTOTAL_KEY },
      signal: AbortSignal.timeout(6000)
    });
    if (res.status === 404) return { available: true, source: 'VirusTotal', flagged: false, note: '분석 이력 없음' };
    if (!res.ok) return { available: false, source: 'VirusTotal', reason: `HTTP ${res.status}` };
    const data = await res.json();
    const stats = data?.data?.attributes?.last_analysis_stats ?? {};
    const malicious = (stats.malicious ?? 0) + (stats.suspicious ?? 0);
    return {
      available: true,
      source: 'VirusTotal',
      flagged: malicious > 0,
      detections: { malicious: stats.malicious ?? 0, suspicious: stats.suspicious ?? 0, harmless: stats.harmless ?? 0 }
    };
  } catch (e) {
    return { available: false, source: 'VirusTotal', reason: `조회 실패: ${e.message}` };
  }
}

/** 공식 조회 채널 안내 — 전화번호 (실시간 공개 API 부재로 링크 안내) */
export function phoneOfficialChannels(phone) {
  return [
    {
      name: '전기통신금융사기 통합신고대응센터 (경찰청)',
      how: `counterscam112.go.kr 접속 → "피싱 전화번호 검색"에 ${phone} 입력`,
      url: 'https://www.counterscam112.go.kr/phishing/searchPhone.do'
    },
    {
      name: '경찰청 사이버안전지킴이 — 인터넷 사기 이력 조회',
      how: '전화번호·계좌번호로 최근 3개월 사기 신고 이력 조회',
      url: 'https://www.police.go.kr/www/security/cyber/cyber04.jsp'
    }
  ];
}

/** 공식 조회 채널 안내 — 계좌번호 */
export function accountOfficialChannels(account) {
  return [
    {
      name: '경찰청 사이버안전지킴이 — 인터넷 사기 이력 조회',
      how: `계좌번호 ${account}로 최근 3개월 사기 신고 이력 조회`,
      url: 'https://www.police.go.kr/www/security/cyber/cyber04.jsp'
    },
    {
      name: '금융감독원 보이스피싱지킴이',
      how: '피해 발생 시 지급정지·피해구제 절차 안내',
      url: 'https://www.fss.or.kr/fss/main/sub1.do?menuNo=200012'
    }
  ];
}
