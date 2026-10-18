import test from 'node:test';
import assert from 'node:assert/strict';
import { escapeHtml, randomHex, truncate } from '../src/utils.js';
import { hashPassword, verifyPassword } from '../src/auth.js';
import { assertPublicUrl } from '../src/crawler.js';
import { buildFtsQuery } from '../src/search.js';

test('escapes HTML text and attribute content', () => {
  assert.equal(escapeHtml(`<script a="b">&'`), '&lt;script a=&quot;b&quot;&gt;&amp;&#39;');
});

test('generates requested random byte lengths as hex', () => {
  assert.equal(randomHex(16).length, 32);
});

test('truncates normalized text', () => {
  assert.equal(truncate('  one\n two  ', 20), 'one two');
  assert.equal(truncate('abcdef', 3), 'abc');
});

test('hashes and verifies passwords without storing plaintext', async () => {
  const encoded = await hashPassword('a-long-test-password');
  assert.match(encoded, /^pbkdf2\$210000\$/);
  assert.equal(await verifyPassword('a-long-test-password', encoded), true);
  assert.equal(await verifyPassword('wrong-password', encoded), false);
});

test('rejects unsafe schemes and private IP literals before making requests', async () => {
  await assert.rejects(assertPublicUrl('file:///etc/passwd'));
  await assert.rejects(assertPublicUrl('http://127.0.0.1/'));
  await assert.rejects(assertPublicUrl('http://[::1]/'));
});

test('builds safe FTS prefix expressions from search text', () => {
  assert.deepEqual(buildFtsQuery('Xin chào tiếng Việt').tokens, ['xin', 'chào', 'tiếng', 'việt']);
  assert.equal(buildFtsQuery('hello" OR *').match, '"hello"* AND "or"*');
  assert.equal(buildFtsQuery('***').match, '');
});
