import assert from 'node:assert/strict';
import { test } from 'node:test';
import { detectEntries, maskSecret, MAX_ENV_BYTES, parseDotenv } from '../web/src/lib/dotenv.ts';
import { PROVIDERS } from '../src/providers.ts';

const detect = (text: string) => detectEntries(text, PROVIDERS);
const one = (text: string) => {
  const r = detect(text);
  assert.equal(r.entries.length, 1, JSON.stringify(r.entries.map((e) => ({ ...e, apiKey: '' }))));
  return r.entries[0];
};
const val = (text: string, name = 'K') => parseDotenv(text).find((v) => v.name === name)?.value;

test('parse: quoting, export, comments, CRLF, blank lines', () => {
  assert.equal(val('K=abc'), 'abc');
  assert.equal(val('export K=abc'), 'abc');
  assert.equal(val('K = abc  '), 'abc');
  assert.equal(val('K="a b"'), 'a b');
  assert.equal(val('K=\'a "b"\''), 'a "b"');
  assert.equal(val('K="line1\\nline2"'), 'line1\nline2');
  assert.equal(val("K='raw\\n'"), 'raw\\n');
  assert.equal(val('K=abc # trailing'), 'abc');
  assert.equal(val('K=abc#notacomment'), 'abc#notacomment');
  assert.equal(val('K="a # b" # c'), 'a # b');
  assert.equal(val('K=#whole'), '');
  assert.equal(val('K='), '');
  assert.equal(val('# K=1\n\n   \nK=2'), '2');
  assert.equal(val('A=1\r\nK=2\r\n'), '2');
  assert.equal(val('﻿K=bom'), 'bom');
  assert.equal(val('K=1\nK=2'), '2', 'last assignment wins');
});

test('parse: lines that do not parse are ignored', () => {
  const vars = parseDotenv('just words\n=nokey\n1BAD=x\nK="unterminated\nJ="a" junk\nOK=1');
  assert.deepEqual(vars.map((v) => v.name), ['OK']);
});

test('parse: variable references are flagged unless single-quoted', () => {
  assert.equal(parseDotenv('K=${OTHER}')[0].interpolated, true);
  assert.equal(parseDotenv('K=$OTHER')[0].interpolated, true);
  assert.equal(parseDotenv('K="x-${OTHER}"')[0].interpolated, true);
  assert.equal(parseDotenv("K='$OTHER'")[0].interpolated, false);
  assert.equal(parseDotenv('K=pa$5word')[0].interpolated, false);
});

test('detect: known variable without a base URL gets the preset default', () => {
  const e = one('OPENAI_API_KEY=sk-proj-abcdef123456');
  assert.deepEqual([e.provider, e.baseUrl, e.status, e.name], ['openai', 'https://api.openai.com/v1', 'ready', 'openai']);
  const a = one('export ANTHROPIC_API_KEY="sk-ant-api03-xyz123456"');
  assert.deepEqual([a.provider, a.baseUrl, a.status], ['anthropic', 'https://api.anthropic.com', 'ready']);
  const o = one('OPENROUTER_API_KEY=sk-or-v1-abcdef123456');
  assert.deepEqual([o.provider, o.baseUrl, o.status], ['openrouter', 'https://openrouter.ai/api/v1', 'ready']);
});

test('detect: a base URL on a preset host selects that preset', () => {
  const e = one('OPENAI_API_KEY=sk-or-v1-abcdef123456\nOPENAI_BASE_URL=https://openrouter.ai/api/v1');
  assert.deepEqual([e.provider, e.baseUrl, e.status, e.name], ['openrouter', 'https://openrouter.ai/api/v1', 'ready', 'openrouter']);
  const alt = one('OPENAI_API_KEY=sk-proj-abcdef123456\nOPENAI_API_BASE=https://api.openai.com/v1/');
  assert.equal(alt.provider, 'openai');
  assert.equal(alt.status, 'ready');
});

test('detect: preset host with a different path needs review', () => {
  const e = one('ANTHROPIC_API_KEY=sk-ant-abcdef123456\nANTHROPIC_BASE_URL=https://api.anthropic.com/v1');
  assert.equal(e.provider, 'anthropic');
  assert.equal(e.status, 'review');
});

test('detect: known variable with an unknown host is a custom gateway to review', () => {
  const e = one('OPENAI_API_KEY=corp-key-1234567890\nOPENAI_BASE_URL=https://llm.corp.example/v1');
  assert.deepEqual([e.provider, e.baseUrl, e.status, e.authStyle], ['custom', 'https://llm.corp.example/v1', 'review', 'bearer']);
  assert.match(e.reason!, /llm\.corp\.example/);
  const a = one('ANTHROPIC_API_KEY=corp-key-1234567890\nANTHROPIC_BASE_URL=https://gw.example/anthropic');
  assert.equal(a.authStyle, 'x-api-key');
});

test('detect: a key prefix that contradicts the variable or host is unresolved', () => {
  for (const text of [
    'OPENAI_API_KEY=sk-ant-abcdef123456',
    'ANTHROPIC_API_KEY=sk-proj-abcdef123456',
    'OPENAI_API_KEY=sk-or-v1-abcdef123456',
    'OPENROUTER_API_KEY=sk-ant-abcdef123456',
    'OPENAI_API_KEY=sk-ant-abcdef123456\nOPENAI_BASE_URL=https://api.openai.com/v1',
  ]) {
    const e = one(text);
    assert.equal(e.status, 'unresolved', text);
    assert.equal(e.apiKey, '', 'an unusable entry does not hold the key');
    assert.match(e.reason!, /key prefix/);
  }
});

test('detect: generic <X>_API_KEY pairs', () => {
  const e = one('WORK_GW_API_KEY=abcdef123456\nWORK_GW_BASE_URL=https://gw.example/v1');
  assert.deepEqual([e.name, e.provider, e.baseUrl, e.status], ['work_gw', 'custom', 'https://gw.example/v1', 'ready']);
  assert.equal(one('X_API_KEY=abcdef123456\nX_API_BASE=https://x.example').baseUrl, 'https://x.example');
  const none = one('MYSTERY_API_KEY=abcdef123456');
  assert.equal(none.status, 'unresolved');
  assert.equal(none.reason, 'has no base URL');
  assert.match(one('Odd.Name_API_KEY=abcdef123456\nOdd.Name_BASE_URL=https://a.example').name, /^[A-Za-z0-9._-]{1,64}$/);
});

test('detect: wickey proxy keys, empty values and references are not importable', () => {
  const p = one('OPENAI_API_KEY=sk-wick-abcdef');
  assert.equal(p.status, 'skipped');
  assert.equal(p.reason, 'is a Wickey proxy key, not a provider key');
  assert.equal(p.apiKey, '');
  assert.equal(one('OPENAI_API_KEY=').status, 'skipped');
  const r = one('OPENAI_API_KEY=${REAL_KEY}');
  assert.deepEqual([r.status, r.reason], ['unresolved', 'uses a variable reference']);
  assert.equal(one('OPENAI_API_KEY=sk-proj-abcdef123456\nOPENAI_BASE_URL=${GW}').status, 'unresolved');
  assert.equal(one('OPENAI_API_KEY=sk-proj-abcdef123456\nOPENAI_BASE_URL=not a url').status, 'unresolved');
});

test('detect: unrelated variables are counted, never returned', () => {
  const r = detect('DATABASE_URL=postgres://u:hunter2@db/x\nSECRET_TOKEN=topsecret\nOPENAI_API_KEY=sk-proj-abcdef123456\nOPENAI_BASE_URL=https://api.openai.com/v1\nPORT=3000');
  assert.equal(r.entries.length, 1);
  assert.equal(r.ignored, 3);
  assert.ok(!JSON.stringify(r.entries).includes('hunter2'));
  assert.ok(!JSON.stringify(r.entries).includes('topsecret'));
});

test('detect: entry names are unique and valid', () => {
  const r = detect('A_API_KEY=abcdef123456\nA_BASE_URL=https://a.example\na_API_KEY=abcdef654321\na_BASE_URL=https://b.example');
  const names = r.entries.map((e) => e.name);
  assert.equal(new Set(names).size, names.length);
});

test('detect: oversized files are rejected', () => {
  const r = detect('A=' + 'x'.repeat(MAX_ENV_BYTES));
  assert.match(r.error!, /256 KB/);
  assert.equal(r.entries.length, 0);
});

test('maskSecret shows only the last four characters, nothing for short values', () => {
  assert.equal(maskSecret('sk-proj-abcdef123456'), '••••3456');
  assert.equal(maskSecret('short'), '••••');
  assert.ok(!maskSecret('sk-proj-abcdef123456').includes('abcdef'));
});
