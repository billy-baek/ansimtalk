import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeMessage, heuristicUrlCheck, extractPhones } from '../src/analyzer.js';

const SAMPLES_DANGER = [
  '[CJ대한통운] 고객님의 택배가 주소 불일치로 배송 불가합니다. 주소 확인 http://bit.ly/3xk2 에서 확인하세요',
  '엄마 나 폰 액정이 깨져서 수리 맡겼어. 급한데 편의점에서 구글 기프트카드 30만원어치만 사서 핀 번호 찍어 보내줘',
  '[서울중앙지검] 귀하는 금융범죄 사건에 연루되어 계좌가 동결될 예정입니다. 즉시 안전 계좌로 자산을 이체하시기 바랍니다',
  '아버지께서 별세하셨기에 삼가 알려드립니다. 모바일 부고장 http://192.168.34.2/bugo.apk',
  '[국민건강보험공단] 환급금 184,300원 미수령 상태입니다. 오늘까지 신청하지 않으면 소멸됩니다. 신청: http://nhis-refund.top/kr',
  '엄마 나 폰 깨졌어, 문화상품권 30만원 사서 보내줘',
  '아빠 나 폰 액정 깨졌어 문상 사줘',
  '엄마 나야 편의점서 기프티콘 사서 핀번호 찍어 보내줘'
];

const SAMPLES_SAFE = [
  '내일 점심에 국밥 먹으러 갈래?',
  '어머니 생신 선물 뭐가 좋을까요',
  '[Web발신] 이번 주 토요일 동창회 오후 6시 종로3가입니다. 참석 여부 알려주세요'
];

test('명백한 스미싱 샘플은 warning 이상으로 판정', () => {
  for (const s of SAMPLES_DANGER) {
    const r = analyzeMessage(s);
    assert.ok(['danger', 'warning'].includes(r.risk_level), `미탐: [${r.risk_level} ${r.risk_score}] ${s.slice(0, 40)}`);
  }
});

test('일상 메시지는 safe/caution으로 판정 (오탐 방지)', () => {
  for (const s of SAMPLES_SAFE) {
    const r = analyzeMessage(s);
    assert.ok(['safe', 'caution'].includes(r.risk_level), `오탐: [${r.risk_level} ${r.risk_score}] ${s.slice(0, 40)}`);
  }
});

test('URL/전화번호 추출', () => {
  const r = analyzeMessage('확인 http://bit.ly/abc 문의 010-1234-5678');
  assert.equal(r.urls_found.length, 1);
  assert.deepEqual(r.phones_found, ['01012345678']);
  assert.deepEqual(extractPhones('1588-1234로 전화주세요'), ['15881234']);
});

test('URL 휴리스틱 — apk 직링크와 정부 위장 도메인 탐지', () => {
  assert.ok(heuristicUrlCheck('http://evil.top/app.apk').signals.length >= 2);
  const gov = heuristicUrlCheck('http://mobile-gov.kr/subsidy');
  assert.ok(gov.signals.some((s) => s.id === 'url-lookalike-kr' || s.id === 'url-gov-lookalike'));
  assert.equal(heuristicUrlCheck('https://www.gov.kr/portal').signals.length, 0);
});

test('위험 근거(evidence)가 항상 포함됨', () => {
  const r = analyzeMessage(SAMPLES_DANGER[0]);
  assert.ok(r.evidence.length > 0);
  assert.ok(r.recommended_action === undefined); // recommended_action은 툴 레이어에서 붙임
});
