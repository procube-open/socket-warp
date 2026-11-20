const assert = require('node:assert/strict');
const { test } = require('node:test');
const { getTags, planRelease } = require('./release.cjs');

test('plans stable and prerelease tags without overwriting existing versions', () => {
  assert.deepEqual(planRelease('v1.3.1', false, ['1.3.0', '1.3.1-rc.0']), {
    version: '1.3.1', exists: false, aliases: ['latest', '1', '1.3'],
  });
  assert.deepEqual(planRelease('v1.3.1-rc.0', true, ['1.3.1-rc.0']), {
    version: '1.3.1-rc.0', exists: true, aliases: [],
  });
  assert.deepEqual(planRelease('v1.3.1', false, ['1.3.1']), {
    version: '1.3.1', exists: true, aliases: ['latest', '1', '1.3'],
  });
  assert.deepEqual(planRelease('v1.0.0', false, []), {
    version: '1.0.0', exists: false, aliases: ['latest', '1', '1.0'],
  });
});

test('protects each shared tag independently when publishing older releases', () => {
  assert.deepEqual(planRelease('v1.3.2', false, ['2.0.0', '1.4.0']).aliases, ['1.3']);
  assert.deepEqual(planRelease('v1.3.2', false, ['1.3.10', '2.0.0-rc.0']).aliases, []);
  assert.deepEqual(planRelease('v2.0.0', false, ['1.99.99', '2.0.1-rc.0']).aliases,
    ['latest', '2', '2.0']);
});

test('rejects invalid tags and mismatched GitHub prerelease settings', () => {
  for (const [tag, prerelease] of [
    ['1.3.1', false], ['v01.3.1', false], ['v1.3.1+build', false],
    ['v1.3.1-rc.01', true], ['v1.3.1-', true], ['v1.3.1', true],
    ['v1.3.1-rc.0', false], [`v1.3.1-${'a'.repeat(123)}`, true],
  ]) {
    assert.throws(() => planRelease(tag, prerelease, []), tag);
  }
});

function response(status, body, link = null) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    headers: { get: () => link },
  };
}

test('retrieves all GHCR tag pages using registry authentication', async () => {
  const calls = [];
  const request = async (url, options) => {
    calls.push({ url: String(url), authorization: options.headers.Authorization });
    if (calls.length === 1) return response(200, { token: 'registry-token' });
    if (calls.length === 2) {
      return response(200, { tags: ['1.2.0'] }, '</v2/owner/socket-warp/tags/list?n=100&last=1.2.0>; rel="next"');
    }
    return response(200, { tags: ['1.3.0'] });
  };
  assert.deepEqual(await getTags('owner/socket-warp', 'actor', 'secret', request), ['1.2.0', '1.3.0']);
  assert.match(calls[0].url, /scope=repository%3Aowner%2Fsocket-warp%3Apull/);
  assert.equal(calls[0].authorization, `Basic ${Buffer.from('actor:secret').toString('base64')}`);
  assert.equal(calls[1].authorization, 'Bearer registry-token');
  assert.match(calls[2].url, /last=1.2.0/);
});

test('fails closed on registry errors, invalid tag lists and unsafe pagination', async () => {
  await assert.rejects(getTags('owner/socket-warp', 'actor', 'secret', async () => response(403, {})), /token request failed/);
  for (const page of [
    response(404, {}),
    response(200, {}),
    response(200, { tags: [] }, 'invalid pagination link'),
    response(200, { tags: [] }, '<https://example.com/v2/owner/socket-warp/tags/list>; rel="next"'),
    response(200, { tags: [] }, '</v2/owner/socket-warp/tags/list?n=100>; rel="next"'),
  ]) {
    let count = 0;
    await assert.rejects(getTags('owner/socket-warp', 'actor', 'secret', async () =>
      count++ === 0 ? response(200, { token: 'registry-token' }) : page));
  }
});
