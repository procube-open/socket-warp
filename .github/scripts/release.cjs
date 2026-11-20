const fs = require('node:fs');

function parseVersion(value) {
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(value);
  if (!match || value.length > 128 ||
      (match[4] && match[4].split('.').some(part => /^\d+$/.test(part) && part.length > 1 && part[0] === '0'))) {
    return null;
  }
  return {
    major: BigInt(match[1]),
    minor: BigInt(match[2]),
    patch: BigInt(match[3]),
    prerelease: Boolean(match[4]),
  };
}

function compareStable(a, b) {
  for (const key of ['major', 'minor', 'patch']) {
    if (a[key] !== b[key]) return a[key] > b[key] ? 1 : -1;
  }
  return 0;
}

function planRelease(tag, prerelease, tags) {
  if (!tag.startsWith('v')) throw new Error('Release tag must start with v');
  const version = tag.slice(1);
  const current = parseVersion(version);
  if (!current || current.prerelease !== prerelease) {
    throw new Error('Release tag must be valid SemVer and match the GitHub prerelease setting');
  }
  const exists = tags.includes(version);
  if (prerelease) return { version, exists, aliases: [] };

  const newer = tags.map(parseVersion).filter(other =>
    other && !other.prerelease && compareStable(other, current) > 0);
  const aliases = [];
  if (!newer.length) aliases.push('latest');
  if (!newer.some(other => other.major === current.major)) aliases.push(String(current.major));
  if (!newer.some(other => other.major === current.major && other.minor === current.minor)) {
    aliases.push(`${current.major}.${current.minor}`);
  }
  return { version, exists, aliases };
}

async function getTags(repository, actor, token, request = fetch) {
  const tokenUrl = new URL('https://ghcr.io/token');
  tokenUrl.searchParams.set('service', 'ghcr.io');
  tokenUrl.searchParams.set('scope', `repository:${repository}:pull`);
  const auth = Buffer.from(`${actor}:${token}`).toString('base64');
  const tokenResponse = await request(tokenUrl, {
    headers: { Authorization: `Basic ${auth}` },
  });
  if (!tokenResponse.ok) throw new Error(`GHCR token request failed: ${tokenResponse.status}`);
  const { token: registryToken } = await tokenResponse.json();
  if (!registryToken) throw new Error('GHCR token response did not contain a token');

  const path = `/v2/${repository}/tags/list`;
  let next = new URL(`https://ghcr.io${path}?n=100`);
  const tags = [];
  const visited = new Set();
  while (next) {
    if (next.origin !== 'https://ghcr.io' || next.pathname !== path || visited.has(next.href)) {
      throw new Error('Invalid GHCR pagination link');
    }
    visited.add(next.href);
    const response = await request(next, {
      headers: { Authorization: `Bearer ${registryToken}` },
    });
    if (!response.ok) throw new Error(`GHCR tag list request failed: ${response.status}`);
    const body = await response.json();
    if (body.tags !== null && (!Array.isArray(body.tags) || body.tags.some(tag => typeof tag !== 'string'))) {
      throw new Error('Invalid GHCR tag list');
    }
    tags.push(...(body.tags || []));
    const link = response.headers.get('link');
    const match = link && /<([^>]+)>\s*;\s*rel="?next"?/i.exec(link);
    if (link && !match) throw new Error('Invalid GHCR pagination link');
    next = match ? new URL(match[1], next) : null;
  }
  return tags;
}

async function main() {
  const { RELEASE_TAG, RELEASE_PRERELEASE, GITHUB_REPOSITORY_OWNER, GITHUB_ACTOR, GITHUB_TOKEN, GITHUB_OUTPUT } = process.env;
  if (!RELEASE_TAG || !['true', 'false'].includes(RELEASE_PRERELEASE) ||
      !GITHUB_REPOSITORY_OWNER || !GITHUB_ACTOR || !GITHUB_TOKEN || !GITHUB_OUTPUT) {
    throw new Error('Missing or invalid release environment');
  }
  const owner = GITHUB_REPOSITORY_OWNER.toLowerCase();
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(owner)) throw new Error('Invalid repository owner');
  // Validate before making any registry requests.
  planRelease(RELEASE_TAG, RELEASE_PRERELEASE === 'true', []);
  const repository = `${owner}/socket-warp`;
  const tags = await getTags(repository, GITHUB_ACTOR, GITHUB_TOKEN);
  const plan = planRelease(RELEASE_TAG, RELEASE_PRERELEASE === 'true', tags);
  fs.appendFileSync(GITHUB_OUTPUT, [
    `image=ghcr.io/${repository}`,
    `version=${plan.version}`,
    `exists=${plan.exists}`,
    `aliases=${JSON.stringify(plan.aliases)}`,
    '',
  ].join('\n'));
}

if (require.main === module) {
  main().catch(error => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

module.exports = { getTags, parseVersion, planRelease };
