# 안심톡 (Ansimtalk) MCP

어르신을 위한 스미싱·보이스피싱 판별 MCP 서버.
카카오 PlayMCP — AGENTIC PLAYER 10 출품작.

수상한 문자를 카카오톡에 붙여넣기만 하면, AI가 사기 여부를 근거와 함께 판별하고
어르신 눈높이로 대처법을 알려준다.

## 왜 MCP 서버가 필요한가

LLM 혼자서도 "사기 같다"는 감은 잡지만, **실제 데이터**가 없다.
이 서버는 LLM이 모르는 결정적(deterministic) 신호를 제공한다:

| 툴 | 역할 | 데이터 소스 |
|---|---|---|
| `analyze_message` | 문자 원문 → 위험도 0~100 + 유형 + 근거 | 자체 스미싱 패턴 룰 DB 40종 + KISA 블록리스트 + Safe Browsing |
| `check_url` | 링크 평판 3중 교차검증 | KISA 피싱 도메인 15,899건(공공데이터) + Google Safe Browsing + VirusTotal |
| `check_phone` | 전화번호 위험 신호 + 공식 조회 안내 | 발신 패턴 휴리스틱 + 경찰청 counterscam112 안내 |
| `check_account` | 계좌 사기 이력 공식 조회 안내 | 경찰청 사이버안전지킴이 / 금감원 안내 |
| `what_to_do` | 상황별 대처법 (링크 눌렀어요/돈 보냈어요/…) | 어르신 눈높이 가이드 + 긴급 연락처 |

## 실행

```bash
npm install
npm start          # PORT=3020 기본, 엔드포인트 POST /mcp (Streamable HTTP, stateless)
npm test           # 룰 엔진 단위 테스트
```

환경변수 (없어도 동작 — 로컬 신호만으로 판별):

- `GOOGLE_SAFE_BROWSING_KEY` — [발급](https://developers.google.com/safe-browsing/v4/get-started) (무료, 즉시)
- `VIRUSTOTAL_KEY` — [발급](https://www.virustotal.com/) (무료 500회/일)

## 배포 (PlayMCP in KC)

1. `docker build --platform linux/amd64 .` — **amd64 필수** (Apple Silicon 주의)
2. https://playmcp.kakaocloud.io 에서 Git 소스 빌드(루트 Dockerfile) 또는 이미지 등록
3. Active 상태 확인 후 Endpoint URL 복사
4. https://playmcp.kakao.com/console 에서 **임시 등록** → AI 채팅으로 테스트 → 심사 요청 → 승인 후 **전체 공개**
5. 공모전 페이지에서 예선 접수 (1회만 제출 가능)

## 데이터

- `data/patterns.json` — 스미싱 패턴 40종 (택배·정부지원금·부고장·자녀사칭·기관사칭 등 16개 카테고리) + URL 신호 5종. 의심 TLD 목록은 KISA 2024 피싱 데이터의 실제 TLD 분포로 도출.
- `data/kisa_domains.json` — KISA 피싱사이트 공공데이터(131,752 URL) → 유니크 도메인 15,899건.
  갱신: 공공데이터포털 [한국인터넷진흥원_피싱사이트](https://www.data.go.kr/data/15143094/fileData.do) 새 버전 CSV로 재생성.
