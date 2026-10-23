import assert from 'node:assert/strict';
import { test } from 'node:test';
import { formatDuration, parseTtl } from '../src/ttl.ts';

test('parseTtl accepts seconds through days', () => {
  assert.equal(parseTtl('30'), 30);
  assert.equal(parseTtl('30s'), 30);
  assert.equal(parseTtl('5m'), 300);
  assert.equal(parseTtl('2h'), 7200);
  assert.equal(parseTtl('1d'), 86400);
  assert.equal(parseTtl(' 10M '), 600);
});

test('parseTtl rejects junk and zero', () => {
  for (const bad of ['', 'abc', '5x', '-5s', '1.5h', '0s']) assert.throws(() => parseTtl(bad), bad);
});

test('formatDuration', () => {
  assert.equal(formatDuration(45), '45s');
  assert.equal(formatDuration(90), '1m 30s');
  assert.equal(formatDuration(3660), '1h 1m');
  assert.equal(formatDuration(90000), '1d 1h');
});
