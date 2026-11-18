import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { TextDecoder } from 'node:util';
import { sanitize, requestDraft, RefreshError } from './refresh-admin-knowledge.mjs';
import { parseDocument, publicationContentHash, validateDocument, validateRepository, validateAnswerScope, anchors } from './validate.mjs';

export const sourceRepository = 'almbrand/cloudops-openai-hub-knowledge-source';
export const hubRepository = 'almbrand/cloudops-openai-hub';
export const hash = value => crypto.createHash('sha256').update(value).digest('hex');
export const encode = value => `${JSON.stringify(value, null, 2)}\n`;
const sha = value => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value);
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const repo = value => typeof value === 'string' && /^almbrand\/[a-zA-Z0-9_.-]+$/.test(value);
class PipelineError extends Error {}
// Unreadable whole-repository entries are recorded with a fix instead of blocking intake.
class SkippedSource extends PipelineError {
  constructor(message, fix) { super(message); this.fix = fix; }
}
const fail = message => { throw new PipelineError(message); };
const skip = (message, fix) => { throw new SkippedSource(message, fix); };
const emptyRepository = { status: 'excluded: empty', reason: 'empty repository' };
const emptyTree = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';
const unreadableRepository = { status: 'excluded: no readable files', reason: 'every tracked file was skipped; see SKIPPED.md' };
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const safePath = value => typeof value === 'string' && /^[a-zA-Z0-9_./ -]+$/.test(value)
  && value.split('/').every(part => part && part.trim() === part && part !== '.' && part !== '..');
const read = (root, file) => {
  if (!safePath(file)) fail('Unsafe local path');
  let current = root;
  for (const part of file.split('/')) {
    current = path.join(current, part);
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) fail('Symlink forbidden');
  }
  return fs.readFileSync(current, 'utf8');
};
const optionalRead = (root, file) => fs.existsSync(path.join(root, file)) ? read(root, file) : null;
const write = (root, file, text) => {
  if (!safePath(file)) fail('Unsafe write path');
  // Check all existing ancestors, not just the leaf.
  let current = root;
  for (const part of file.split('/')) {
    current = path.join(current, part);
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) fail('Symlink forbidden');
  }
  fs.mkdirSync(path.dirname(current), { recursive: true });
  fs.writeFileSync(current, text);
};
const git = (root, ...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const configurationPath = (audience, intake = 'upstream') => `sources/${audience}/${intake === 'migration' ? 'migrations' : 'sources'}.json`;
const baselinePath = (audience, intake = 'upstream') => `sources/${audience}/${intake === 'migration' ? 'migration-checkpoint' : 'checkpoint'}.json`;
const exceptionStatePath = audience => `sources/${audience}/exceptions.json`;
// Exceptions never block other stages. Derived-output failures keep the previous output; only an
// unresolved answer-content exception stops automatic recovery of that same merged proposal.
const derivedPhases = new Set(['glossary', 'graph', 'ontology', 'publication', 'dispatch', 'workflow']);
const reviewPath = (file, audience) => `reviews/${audience}/drafts/${file}`;
const reviewFields = ['review_target', 'review_context', 'review_evidence', 'review_base_version', 'review_base_sha256'];
const audienceCheck = audience => { if (!['shared', 'admin'].includes(audience)) fail('Invalid audience'); };
const extensions = { markdown: '.md', json: '.json', powershell: '.ps1', terraform: '.tf', workflow: '.yml', bicep: '.bicep' };
const maxInputs = 20_000;
const inventorySource = { repository: 'almbrand/corp-cloudops-platform-repositories', ref: 'main', path: 'OIDC_github_repos.json' };
const screen = (text, audience, maxBytes = 512_000) => sanitize(text, { maxBytes, redactInfrastructure: audience !== 'shared' });
const wholeRepository = source => source.include === 'tracked-files';
const inferredType = file => /^\.github\/workflows\/[^/]+\.ya?ml$/i.test(file) ? 'workflow'
  : Object.entries(extensions).find(([type, extension]) => type !== 'workflow' && file.toLowerCase().endsWith(extension))?.[0] ?? 'text';
const matchesSource = (source, input) => source.repository === input.repository && source.ref === input.ref
  && (wholeRepository(source) ? safePath(input.path) && input.type === inferredType(input.path)
    : source.files.some(file => file.path === input.path && file.type === input.type));

function validateInputInventory(configuration, inputs) {
  if (!Array.isArray(inputs) || inputs.length > maxInputs || new Set(inputs.map(identity)).size !== inputs.length
    || inputs.some(input => !sha(input.commit) || !digest(input.sha256)
      || !configuration.sources.some(source => matchesSource(source, input)))
    || configuration.sources.some(source => wholeRepository(source)
      ? !inputs.some(input => input.repository === source.repository)
      : source.files.some(file => !inputs.some(input => matchesSource(source, input) && input.path === file.path)))) {
    fail('Input inventory differs from configured repository selection');
  }
}

export function validateConfiguration(value, audience) {
  audienceCheck(audience);
  const fields = ['schema_version', 'audience', 'sources', ...(Object.hasOwn(value, 'inventory') ? ['inventory'] : [])];
  if (!exact(value, fields)
    || value.schema_version !== 1 || value.audience !== audience || !Array.isArray(value.sources) || value.sources.length > 100) fail('Invalid intake configuration');
  if (Object.hasOwn(value, 'inventory') && (audience !== 'shared' || encode(value.inventory) !== encode(inventorySource))) {
    fail('Only the approved shared OIDC inventory at main may expand source repositories');
  }
  const keys = new Set();
  for (const source of value.sources) {
    const registry = Object.hasOwn(source, 'origin') || Object.hasOwn(source, 'status');
    const fields = ['repository', 'ref', wholeRepository(source) ? 'include' : 'files',
      ...(registry ? ['origin', 'status'] : []), ...['reason', 'retired_reason', 'retired_at', 'retired_by'].filter(key => Object.hasOwn(source, key))];
    if (!exact(source, fields)
      || (registry && (!['explicit', 'inventory'].includes(source.origin) || !['active', 'retired'].includes(source.status)))
      || (source.status === 'retired' && (audience !== 'shared' || !value.inventory
        || typeof source.reason !== 'string' || source.reason.trim().length < 10 || source.reason.length > 300))
      || (Object.hasOwn(source, 'retired_by') && (source.status !== 'retired'
        || !['automatic', 'manual'].includes(source.retired_by)
        || typeof source.retired_reason !== 'string' || source.retired_reason !== source.reason
        || typeof source.retired_at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(source.retired_at)
        || !Number.isFinite(Date.parse(source.retired_at))))
      || (['retired_reason', 'retired_at'].some(key => Object.hasOwn(source, key)) && !Object.hasOwn(source, 'retired_by'))
      || (source.origin === 'inventory' && !value.inventory)
      || (Object.hasOwn(source, 'reason') && (typeof source.reason !== 'string' || source.reason.length > 300 || screen(source.reason, audience) !== source.reason))
      || !repo(source.repository)
      || (source.ref !== null && (typeof source.ref !== 'string' || !/^[a-zA-Z0-9_./-]+$/.test(source.ref)))
      || (!wholeRepository(source) && (!Array.isArray(source.files) || !source.files.length || source.files.length > 30))
      || keys.has(source.repository)) fail('Invalid or duplicate configured repository');
    keys.add(source.repository);
    if (source.repository === 'almbrand/landingzone-service-catalog-code' && source.ref !== 'release') fail('Implementation source must use release');
    const paths = new Set();
    for (const file of source.files ?? []) {
      if (!exact(file, ['path', 'type']) || !safePath(file.path) || !extensions[file.type]
        || !file.path.endsWith(extensions[file.type]) || paths.has(file.path)
        || /(?:^|\/)(?:\.git|node_modules|vendor|logs|outputs|\.terraform)(?:\/|$)|(?:secret|credential|tfstate|tfplan|tfvars|\.env)/i.test(file.path)
        || (file.type === 'workflow' && !/^\.github\/workflows\/[^/]+\.yml$/.test(file.path))) fail('Unsupported or unsafe source path/type');
      paths.add(file.path);
    }
  }
  return value;
}

function collectionSource(source, ref) {
  return { repository: source.repository, ref,
    ...(wholeRepository(source) ? { include: 'tracked-files' } : { files: source.files }) };
}

export async function github(apiPath, token, { method = 'GET', body, fetcher = fetch, redirect = 'error' } = {}) {
  if (!token) fail('Required scoped GitHub credential is unavailable');
  const response = await fetcher(`https://api.github.com${apiPath}`, {
    method, redirect, signal: AbortSignal.timeout(60_000),
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (!response.ok) {
    // File paths and user names are never echoed; repository and endpoint identify the failing call.
    const endpoint = apiPath.split('?')[0].replace(/^(\/repos\/[^/]+\/[^/]+\/contents)\/.*$/, '$1/<file>')
      .replace(/\/collaborators\/[^/]+/, '/collaborators/<user>');
    const error = new PipelineError(`GitHub ${method} ${endpoint} failed (${response.status}); no checkpoint advanced`);
    error.status = response.status;
    throw error;
  }
  return response.status === 204 ? null : response.json();
}

async function remoteText(repository, file, commit, token, fetcher = fetch, allowEmpty = false, maxBytes = 512_000) {
  if (!sha(commit) || !safePath(file)) fail('Source reads require immutable commit and exact safe path');
  const value = await github(`/repos/${repository}/contents/${file.split('/').map(encodeURIComponent).join('/')}?ref=${commit}`, token, { fetcher });
  if (value.type === 'file' && (value.encoding === 'none' || (Number.isSafeInteger(value.size) && value.size > maxBytes))) {
    skip(`File is oversized: larger than the ${maxBytes}-byte intake limit`,
      'Split it into smaller files below 500 KB, or move generated or bulk data out of the repository.');
  }
  if (value.type !== 'file' || value.encoding !== 'base64' || typeof value.content !== 'string'
    || !Number.isSafeInteger(value.size) || value.size < (allowEmpty ? 0 : 1)) fail('Unsupported, empty or oversized input');
  const bytes = Buffer.from(value.content, 'base64');
  if (bytes.length !== value.size) fail('Truncated input');
  return utf8Text(bytes);
}

function utf8Text(bytes) {
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { skip('Not valid UTF-8 text', 'Save the file with UTF-8 encoding, or remove it if it is not documentation or configuration.'); }
}

// One shallow fetch per repository keeps whole-repository intake off the per-user REST rate limit.
// Git verifies every object against the pinned commit, so content integrity matches the contents API.
function gitSnapshot(remote, commit, token) {
  if (!sha(commit)) fail('Source reads require immutable commit');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-source-'));
  // The credential is scoped to github.com and passed through the environment, never argv.
  const env = { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_COUNT: '2',
    GIT_CONFIG_KEY_0: 'credential.helper', GIT_CONFIG_VALUE_0: '',
    GIT_CONFIG_KEY_1: 'http.https://github.com/.extraheader',
    GIT_CONFIG_VALUE_1: `AUTHORIZATION: basic ${Buffer.from(`x-access-token:${token}`).toString('base64')}` };
  for (const key of ['GIT_DIR', 'GIT_COMMON_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_CONFIG_PARAMETERS']) delete env[key];
  const run = (args, encoding = 'buffer') => execFileSync('git', ['-C', dir, ...args],
    { env, encoding, maxBuffer: 256 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
  const close = () => fs.rmSync(dir, { recursive: true, force: true });
  let listing;
  try {
    run(['init', '-q', '--bare']);
    run(['fetch', '-q', '--depth=1', '--no-tags', remote, commit]);
    listing = run(['ls-tree', '-r', '-l', '-z', '--full-tree', commit], 'utf8');
  } catch (error) {
    close();
    fail(`Git fetch of the pinned source commit failed (exit ${error.status ?? 'unknown'}); no checkpoint advanced`);
  }
  const tree = listing.split('\0').filter(Boolean).map(line => {
    const match = line.match(/^(\d{6}) (blob|commit|tree) ([a-f0-9]{40}) +(\d+|-)\t([\s\S]+)$/);
    if (!match) { close(); fail('Unreadable source tree listing'); }
    return { mode: match[1], type: match[2], sha: match[3], size: match[4] === '-' ? null : Number(match[4]), path: match[5] };
  });
  if (tree.length > 100_000 || new Set(tree.map(item => item.path)).size !== tree.length) {
    close();
    fail('Source tree is oversized or has duplicate paths');
  }
  const text = (entry, allowEmpty = false, maxBytes = 512_000) => {
    if (entry.size > maxBytes) {
      skip(`File is oversized: larger than the ${maxBytes}-byte intake limit`,
        'Split it into smaller files below 500 KB, or move generated or bulk data out of the repository.');
    }
    if (!Number.isSafeInteger(entry.size) || entry.size < (allowEmpty ? 0 : 1)) fail('Unsupported, empty or oversized input');
    const bytes = run(['cat-file', 'blob', entry.sha]);
    if (bytes.length !== entry.size) fail('Truncated input');
    return utf8Text(bytes);
  };
  return { tree, text, close };
}

export const gitSourceReader = (base = 'https://github.com/') => ({
  open: async (repository, commit, token) => gitSnapshot(`${base}${repository}.git`, commit, token),
});
const apiSourceReader = fetcher => ({
  open: async (repository, commit, token) => ({ tree: await sourceTree(repository, commit, token, fetcher),
    text: (entry, allowEmpty) => remoteText(repository, entry.path, commit, token, fetcher, allowEmpty), close() {} }),
});
// Injected or replaced fetchers (tests) read through the API; production intake fetches with git.
const nativeFetch = globalThis.fetch;
const defaultReader = fetcher => fetcher === nativeFetch ? gitSourceReader() : apiSourceReader(fetcher);

async function sourceTree(repository, commit, token, fetcher) {
  const tree = await github(`/repos/${repository}/git/trees/${commit}?recursive=1`, token, { fetcher });
  if (tree.truncated !== false || !Array.isArray(tree.tree) || tree.tree.length > 100_000) fail('Source tree is unavailable, oversized or truncated');
  if (new Set(tree.tree.map(item => item.path)).size !== tree.tree.length) fail('Duplicate source tree paths');
  return tree.tree;
}

async function regularPaths(repository, commit, paths, token, fetcher = fetch) {
  const tree = await sourceTree(repository, commit, token, fetcher);
  for (const file of paths) {
    const entry = tree.find(item => item.path === file);
    if (!entry || entry.type !== 'blob' || !['100644', '100755'].includes(entry.mode)) fail('Configured source must be a regular file, not a symlink or submodule');
  }
}

export function inventoryRepositories(text) {
  let value;
  try { value = JSON.parse(text.replace(/^\uFEFF/, '')); } catch { fail('Invalid OIDC inventory JSON'); }
  const entries = value?.github?.instances;
  if (!Array.isArray(entries) || !entries.length || entries.length > 100) fail('OIDC inventory requires 1-100 github.instances');
  const names = entries.map((item, index) => {
    if (typeof item?.name !== 'string') fail(`OIDC inventory entry ${index + 1} has no repository name`);
    const name = item.name.toLowerCase();
    const qualified = name.includes('/') ? name : `almbrand/${name}`;
    if (!/^almbrand\/[a-z0-9][a-z0-9_.-]*$/.test(qualified)
      || ['.', '..'].includes(qualified.split('/')[1])) fail(`OIDC inventory entry ${index + 1} has an invalid or non-almbrand repository name`);
    return qualified;
  });
  return [...new Set(names)].sort();
}

export function sourceRegistryMarkdown(configuration) {
  validateConfiguration(configuration, 'shared');
  return `# Shared source registry\n\nGenerated from \`sources/shared/sources.json\` during the shared stage workflow.\n`
    + `Inventory membership is re-read every run; status is not proof of deployed resources.\n`
    + `Retired content is withdrawn only through the approved answer/publication flow.\n\n`
    + `| Repository | Status | Reason | Retired at (UTC) | Retired by | Origin | Ref |\n| --- | --- | --- | --- | --- | --- | --- |\n`
    + configuration.sources.map(source => `| ${source.repository} | ${source.status ?? 'active'} | ${
      (source.reason ?? '').replaceAll('|', '\\|').replace(/[\r\n]/g, ' ')} | ${source.retired_at ?? ''} | ${source.retired_by ?? ''} | ${
      source.origin ?? 'explicit'} | ${source.ref ?? 'unresolved'} |`).join('\n') + '\n';
}

export async function planSourceRegistry(configuration, token, fetcher = fetch, now = new Date().toISOString()) {
  validateConfiguration(configuration, 'shared');
  if (!configuration.inventory) fail('Shared registry synchronization requires the configured inventory');
  const revision = await github(`/repos/${inventorySource.repository}/commits/main`, token, { fetcher });
  if (!sha(revision.sha)) fail('Inventory ref did not resolve to an immutable commit');
  await regularPaths(inventorySource.repository, revision.sha, [inventorySource.path], token, fetcher);
  const original = await remoteText(inventorySource.repository, inventorySource.path, revision.sha, token, fetcher);
  screen(original, 'shared');
  const names = inventoryRepositories(original);
  const sources = new Map(configuration.sources.map(source => [source.repository, {
    ...source, origin: source.origin ?? 'explicit', status: source.status ?? 'active',
  }]));
  const drift = [];
  for (const repository of names) if (!sources.has(repository)) {
    sources.set(repository, { repository, ref: repository === 'almbrand/landingzone-service-catalog-code' ? 'release' : null,
      include: 'tracked-files', origin: 'inventory', status: 'active' });
    drift.push(repository);
  }
  if (sources.size > 100) fail('Registry synchronization exceeds 100 repositories; no registry changed');
  const changes = [], issues = [];
  let notFound = 0;
  for (const source of sources.values()) {
    let metadata;
    try {
      metadata = await github(`/repos/${source.repository}`, token, { fetcher, redirect: 'manual' });
    } catch (error) {
      if (!(error instanceof PipelineError)) throw error;
      if (error.status === 404) {
        notFound++;
        issues.push(`${source.repository}: access/deletion ambiguity (404); not retired without confirmed deletion evidence`);
      } else if ([301, 302, 307, 308].includes(error.status)) {
        issues.push(`${source.repository}: renamed/transferred redirect; not retired and no unapproved repository followed`);
      } else throw error;
      continue;
    }
    if (metadata.full_name?.toLowerCase() !== source.repository) {
      issues.push(`${source.repository}: renamed/transferred identity; not retired and no unapproved repository followed`);
      continue;
    }
    if (typeof metadata.default_branch !== 'string' || !/^[a-zA-Z0-9_./-]+$/.test(metadata.default_branch)) {
      issues.push(`${source.repository}: no usable default branch; not retired`);
      continue;
    }
    if (source.ref === null) source.ref = source.repository === 'almbrand/landingzone-service-catalog-code' ? 'release' : metadata.default_branch;
    if (source.status === 'retired' && source.retired_by !== 'automatic') continue;
    if (metadata.archived === true) {
      if (source.status !== 'retired' || source.retired_reason !== 'archived on GitHub') {
        Object.assign(source, { status: 'retired', reason: 'archived on GitHub', retired_reason: 'archived on GitHub',
          retired_at: now, retired_by: 'automatic' });
        changes.push(`${source.repository}: retired (archived on GitHub)`);
      }
    } else if (metadata.archived === false && source.status === 'retired' && source.retired_by === 'automatic') {
      source.status = 'active';
      for (const key of ['reason', 'retired_reason', 'retired_at', 'retired_by']) delete source[key];
      changes.push(`${source.repository}: reactivated (restored/unarchived on GitHub)`);
    } else if (typeof metadata.archived !== 'boolean') {
      issues.push(`${source.repository}: missing archive state; not retired or reactivated`);
    }
  }
  if (notFound > 3 || notFound / sources.size > 0.2) {
    fail(`Source-read access failure guard: ${notFound}/${sources.size} repositories returned 404; no registry changed or source retired`);
  }
  const next = { ...configuration, sources: [...sources.values()] };
  validateConfiguration(next, 'shared');
  return { configuration: next, changes, issues, drift,
    inventory: { ...inventorySource, commit: revision.sha, sha256: hash(original) } };
}

export async function refreshSourceRegistry(root, env = process.env, fetcher = fetch) {
  if (!env.SOURCE_READ_TOKEN || !env.SOURCE_PUBLICATION_TOKEN) {
    fail('Registry synchronization requires source-read and publication credentials');
  }
  if (git(root, 'status', '--porcelain')) fail('Registry synchronization requires a clean trusted-main checkout');
  const configPath = configurationPath('shared'), tablePath = 'sources/shared/SOURCES.md';
  let plan;
  try {
    plan = await planSourceRegistry(JSON.parse(read(root, configPath)), env.SOURCE_READ_TOKEN, fetcher);
  } catch (error) {
    if (env.GITHUB_STEP_SUMMARY) fs.appendFileSync(env.GITHUB_STEP_SUMMARY,
      '## Retired / reactivated this run\n\nRegistry synchronization failed; no status writes or retirements were committed. Inspect the failed step and failure review.\n');
    throw error;
  }
  const summary = `## Retired / reactivated this run\n\n${plan.changes.join('\n\n') || 'No status transitions.'}\n\n`
    + `### Full retired list\n\n${plan.configuration.sources.filter(source => source.status === 'retired')
      .map(source => `${source.repository}: ${source.reason} (${source.retired_at ?? 'manual historical retirement'})`).join('\n\n') || 'None.'}\n\n`
    + `${plan.drift.map(repository => `${repository}: add to sources/shared/sources.json (automatically recorded this run)`).join('\n\n')}\n\n`
    + `${plan.issues.join('\n\n')}\n\nInventory commit: \`${plan.inventory.commit}\`.\n`;
  if (env.GITHUB_STEP_SUMMARY) fs.appendFileSync(env.GITHUB_STEP_SUMMARY, summary);
  else console.log(summary);
  const files = { [configPath]: encode(plan.configuration), [tablePath]: sourceRegistryMarkdown(plan.configuration) };
  const changed = Object.entries(files).filter(([file, text]) => optionalRead(root, file) !== text);
  if (changed.length) {
    for (const [file, text] of changed) write(root, file, text);
    commitState(root, changed.map(([file]) => file), 'Synchronize shared source retirement registry');
  }
  if (plan.issues.length) console.warn(`::warning::Source registry issues need attention; collection continues with the configured sources: ${plan.issues.join(' ').slice(0, 6800)}`);
  return plan;
}

export async function resolveSources(configuration, token, fetcher = fetch, reviewedScope = null) {
  validateConfiguration(configuration, configuration.audience);
  if (!configuration.inventory) return { configuration, scope: null };
  const revision = reviewedScope === null
    ? await github(`/repos/${inventorySource.repository}/commits/main`, token, { fetcher })
    : { sha: reviewedScope.inventory?.commit };
  if (!sha(revision.sha)) fail('Inventory ref did not resolve to an immutable commit');
  await regularPaths(inventorySource.repository, revision.sha, [inventorySource.path], token, fetcher);
  const original = await remoteText(inventorySource.repository, inventorySource.path, revision.sha, token, fetcher);
  screen(original, configuration.audience);
  const names = inventoryRepositories(original);
  const sources = new Map(configuration.sources.filter(source => source.status !== 'retired'
    && (source.origin !== 'inventory' || names.includes(source.repository))).map(source => [source.repository, source]));
  const retired = new Map(configuration.sources.filter(source => source.status === 'retired').map(source => [source.repository, source]));
  const excluded = [...retired.values()].map(source => ({
    repository: source.repository, status: 'excluded: retired', reason: source.reason, origin: 'configuration', default_branch: null,
  }));
  for (const source of configuration.sources.filter(source => source.origin === 'inventory' && source.status !== 'retired'
    && !names.includes(source.repository))) {
    excluded.push({ repository: source.repository, status: 'excluded: removed from inventory',
      reason: 'No longer listed in the pinned OIDC inventory.', origin: 'inventory', default_branch: null });
  }
  for (const repository of names) if (!sources.has(repository)) sources.set(repository, { repository, include: 'tracked-files' });
  if (new Set([...configuration.sources.map(source => source.repository), ...names]).size > 100) fail('Expanded inventory exceeds 100 repositories; no partial source set accepted');
  const drift = names.filter(repository => !configuration.sources.some(source => source.repository === repository))
    .map(repository => ({ repository, note: 'add to sources/shared/sources.json' }));
  const resolved = [], blocked = [];
  for (const source of [...sources.values()].sort((a, b) => a.repository < b.repository ? -1 : 1)) {
    if (retired.has(source.repository)) continue;
    try {
      const previous = reviewedScope?.repositories?.find(item => item.repository === source.repository);
      const previousExclusion = reviewedScope?.excluded?.find(item => item.repository === source.repository);
      // Promotion re-verifies inputs at pinned commits; an unreadable-only repository contributes none.
      if (previousExclusion?.status === unreadableRepository.status) {
        excluded.push({ ...previousExclusion });
        continue;
      }
      let defaultBranch, ref, commit;
      if (reviewedScope !== null && !previousExclusion) {
        if (!previous) fail('Reviewed inventory omitted a repository');
        ({ default_branch: defaultBranch, ref, commit } = previous);
      } else {
        const metadata = await github(`/repos/${source.repository}`, token, { fetcher });
        if (metadata.full_name?.toLowerCase() !== source.repository) fail('Source repository metadata differs from configured identity');
        if (metadata.archived === true) {
          excluded.push({ repository: source.repository, status: 'excluded: retired', reason: 'archived',
            origin: 'github', default_branch: typeof metadata.default_branch === 'string' ? metadata.default_branch : null });
          continue;
        }
        if (previousExclusion?.status === 'excluded: retired') fail('Reviewed archived source is no longer archived; collect and review the new scope');
        if (metadata.disabled
          || typeof metadata.default_branch !== 'string' || !/^[a-zA-Z0-9_./-]+$/.test(metadata.default_branch)) {
          fail('Source repository is disabled, missing or has no usable default branch');
        }
        defaultBranch = metadata.default_branch;
        ref = source.ref ?? (source.repository === 'almbrand/landingzone-service-catalog-code' ? 'release' : defaultBranch);
        let pinned;
        try {
          pinned = source.repository === inventorySource.repository && ref === 'main'
            ? revision : await github(`/repos/${source.repository}/commits/${encodeURIComponent(ref)}`, token, { fetcher });
        } catch (error) {
          // GitHub answers 409 for a repository without any commit.
          if (!(error instanceof PipelineError) || error.status !== 409 || !wholeRepository(source)) throw error;
          excluded.push({ repository: source.repository, ...emptyRepository, origin: 'github', default_branch: defaultBranch });
          continue;
        }
        // A commit without files points at Git's empty tree, which GitHub's tree API answers with 404.
        if (pinned.commit?.tree?.sha === emptyTree && wholeRepository(source)) {
          excluded.push({ repository: source.repository, ...emptyRepository, origin: 'github', default_branch: defaultBranch });
          continue;
        }
        if (previousExclusion) fail('Reviewed empty source now has commits; collect and review the new scope');
        commit = pinned.sha;
      }
      if (!sha(commit)) fail('Source repository is empty or ref did not resolve to an immutable commit');
      resolved.push({ repository: source.repository, default_branch: defaultBranch, ref, commit });
    } catch (error) {
      if (!(error instanceof PipelineError)) throw error;
      blocked.push(`${source.repository}: ${error.message}`);
    }
  }
  if (blocked.length) {
    const error = new PipelineError(`Inventory expansion incomplete: ${sources.size} repositories, ${blocked.length} blocked. ${blocked.join('\n').slice(0, 6800)}`);
    error.coverage = { complete: false, inventory: { ...inventorySource, commit: revision.sha, sha256: hash(original) },
      inventory_repositories: names, resolved_repositories: resolved, blocked_repositories: blocked, excluded };
    error.report = { inventory_commit: revision.sha, excluded, skipped: [], blocked: blocked.map(line => {
      const [item, ...problem] = line.split(': ');
      return { item, problem: problem.join(': ') };
    }) };
    throw error;
  }
  excluded.sort((a, b) => a.repository.localeCompare(b.repository));
  const scope = { inventory: { ...inventorySource, commit: revision.sha, sha256: hash(original) },
    inventory_repositories: names, repositories: resolved,
    ...(excluded.length || Object.hasOwn(reviewedScope ?? {}, 'excluded') ? { excluded } : {}),
    ...(drift.length || Object.hasOwn(reviewedScope ?? {}, 'drift') ? { drift } : {}) };
  const expanded = { schema_version: 1, audience: configuration.audience,
    sources: resolved.map(item => collectionSource(sources.get(item.repository), item.ref)) };
  validateConfiguration(expanded, configuration.audience);
  if (reviewedScope !== null && encode(scope) !== encode(reviewedScope)) fail('Reviewed inventory expansion differs from immutable OIDC evidence');
  return { configuration: expanded, scope };
}

function scopedConfiguration(configuration, scope, inputs) {
  if (!configuration.inventory) {
    if (scope) fail('Unexpected dynamic source scope');
    return configuration;
  }
  if (!exact(scope, ['inventory', 'inventory_repositories', 'repositories',
      ...(Object.hasOwn(scope ?? {}, 'excluded') ? ['excluded'] : []), ...(Object.hasOwn(scope ?? {}, 'drift') ? ['drift'] : [])])
    || !exact(scope.inventory, ['repository', 'ref', 'path', 'commit', 'sha256'])
    || !Object.entries(inventorySource).every(([key, value]) => scope.inventory[key] === value)
    || !sha(scope.inventory.commit) || !digest(scope.inventory.sha256)
    || !Array.isArray(scope.inventory_repositories) || !scope.inventory_repositories.length || scope.inventory_repositories.length > 100
    || scope.inventory_repositories.some(name => !repo(name) || name !== name.toLowerCase())
    || encode([...new Set(scope.inventory_repositories)].sort()) !== encode(scope.inventory_repositories)
    || !Array.isArray(scope.repositories) || scope.repositories.length > 100) fail('Invalid immutable inventory scope');
  const excluded = scope.excluded ?? [];
  const retired = configuration.sources.filter(source => source.status === 'retired');
  const collectable = name => {
    const source = configuration.sources.find(item => item.repository === name);
    return source ? source.status !== 'retired' && wholeRepository(source)
      && (source.origin !== 'inventory' || scope.inventory_repositories.includes(name))
      : scope.inventory_repositories.includes(name);
  };
  if (!Array.isArray(excluded) || excluded.length > 100
    || excluded.some(item => !exact(item, ['repository', 'status', 'reason', 'origin', 'default_branch'])
      || !/^almbrand\/[a-z0-9][a-z0-9_.-]*$/.test(item.repository)
      || typeof item.reason !== 'string'
      || (item.origin === 'configuration'
        ? !retired.some(source => source.repository === item.repository && source.reason === item.reason)
          || item.default_branch !== null || item.status !== 'excluded: retired'
        : item.origin === 'inventory'
          ? item.status !== 'excluded: removed from inventory' || item.default_branch !== null
            || item.reason !== 'No longer listed in the pinned OIDC inventory.'
            || scope.inventory_repositories.includes(item.repository)
            || !configuration.sources.some(source => source.repository === item.repository && source.origin === 'inventory' && source.status === 'active')
          : [emptyRepository, unreadableRepository].some(kind => kind.status === item.status)
            ? item.origin !== 'github' || ![emptyRepository, unreadableRepository].some(kind =>
              kind.status === item.status && kind.reason === item.reason)
              || !collectable(item.repository) || retired.some(source => source.repository === item.repository)
              || typeof item.default_branch !== 'string' || !/^[a-zA-Z0-9_./-]+$/.test(item.default_branch)
            : item.origin !== 'github' || item.status !== 'excluded: retired' || item.reason !== 'archived'
          || !scope.inventory_repositories.includes(item.repository)
          || retired.some(source => source.repository === item.repository)
          || !(item.default_branch === null || /^[a-zA-Z0-9_./-]+$/.test(item.default_branch))))
    || encode(excluded.map(item => item.repository)) !== encode([...new Set(excluded.map(item => item.repository))].sort())
    || retired.some(item => !excluded.some(source => source.repository === item.repository && source.origin === 'configuration'))) {
    fail('Invalid retired-source exclusion provenance');
  }
  const expectedDrift = scope.inventory_repositories.filter(repository => !configuration.sources.some(source => source.repository === repository))
    .map(repository => ({ repository, note: 'add to sources/shared/sources.json' }));
  if (encode(scope.drift ?? []) !== encode(expectedDrift)) fail('Invalid source-registry drift provenance');
  const expected = [...new Set([...configuration.sources.filter(source => source.status !== 'retired'
    && source.origin !== 'inventory').map(item => item.repository), ...scope.inventory_repositories])]
    .filter(repository => !excluded.some(item => item.repository === repository)).sort();
  if (encode(scope.repositories.map(item => item.repository)) !== encode(expected)) fail('Resolved repository union differs from inventory and explicit overrides');
  for (const item of scope.repositories) {
    const explicit = configuration.sources.find(source => source.repository === item.repository);
    if (!exact(item, ['repository', 'default_branch', 'ref', 'commit']) || !sha(item.commit)
      || !/^[a-zA-Z0-9_./-]+$/.test(item.default_branch)
      || item.ref !== (explicit?.ref ?? (item.repository === 'almbrand/landingzone-service-catalog-code' ? 'release' : item.default_branch))
      || !inputs.some(input => input.repository === item.repository && input.commit === item.commit && input.ref === item.ref)) {
      fail('Invalid resolved repository provenance');
    }
  }
  if (!inputs.some(input => sameEvidence(input, scope.inventory) && input.ref === 'main')) fail('Missing pinned OIDC inventory evidence');
  return { schema_version: 1, audience: configuration.audience, sources: scope.repositories.map(item => collectionSource(
    configuration.sources.find(source => source.repository === item.repository) ?? { repository: item.repository, include: 'tracked-files' }, item.ref)) };
}

export async function collectSnapshot(configuration, token, fetcher = fetch, reviewedScope = null, reader = defaultReader(fetcher)) {
  const resolved = await resolveSources(configuration, token, fetcher, reviewedScope);
  const report = { inventory_commit: resolved.scope?.inventory.commit ?? null,
    excluded: resolved.scope?.excluded ?? [], skipped: [], blocked: [] };
  try {
    const collected = await collectConfiguredInputs(resolved.configuration, token, fetcher,
      resolved.scope === null ? null : new Map(resolved.scope.repositories.map(item => [item.repository, item.commit])), reader);
    report.skipped = collected.skipped;
    let scope = resolved.scope;
    if (collected.unreadable.length) {
      if (!scope) fail(`No readable tracked file in ${collected.unreadable.join(', ')}; fix the skipped files`);
      const { excluded = [], drift, ...base } = scope;
      const branches = new Map(scope.repositories.map(item => [item.repository, item.default_branch]));
      scope = { ...base, repositories: scope.repositories.filter(item => !collected.unreadable.includes(item.repository)),
        excluded: [...excluded, ...collected.unreadable.map(repository => ({ repository, ...unreadableRepository,
          origin: 'github', default_branch: branches.get(repository) }))].sort((a, b) => a.repository.localeCompare(b.repository)),
        ...(Object.hasOwn(resolved.scope, 'drift') ? { drift } : {}) };
      report.excluded = scope.excluded;
    }
    if (scope) scopedConfiguration(configuration, scope, collected.inputs);
    return { inputs: collected.inputs, scope, skipped: collected.skipped, report };
  } catch (error) {
    if (error instanceof PipelineError && !error.report) {
      error.report = { ...report, skipped: error.skipped ?? report.skipped, blocked: error.blocked ?? [] };
    }
    throw error;
  }
}

export async function collectInputs(configuration, token, fetcher = fetch) {
  return (await collectSnapshot(configuration, token, fetcher)).inputs;
}

const credentialFix = 'Remove the value, rotate it if it is a real secret and use a secret reference instead. '
  + 'If it is not a secret (for example a hash or encoded data), move it out of the tracked file.';

function skipReason(error) {
  if (error instanceof SkippedSource) return { problem: error.message, fix: error.fix };
  if (error instanceof RefreshError) {
    if (/binary or exceeds/.test(error.message)) {
      return { problem: 'Binary content or larger than the safe input limit', fix: 'Convert it to UTF-8 text below 500 KB, or remove it.' };
    }
    return { problem: /Opaque/.test(error.message) ? 'Opaque credential-like value' : 'Possible hardcoded credential', fix: credentialFix };
  }
  if (error?.message === 'Unsafe credential or executable content signature') {
    return { problem: 'Credential or executable content signature', fix: credentialFix };
  }
  return null;
}

// Reports never echo unsafe or credential-like paths; entry-N is the sorted Git tree position.
function reportLabel(file, index) {
  const escaped = file.path.replace(/[^a-zA-Z0-9_./ -]/g, '?').slice(0, 200);
  try { return sanitize(escaped) === escaped ? escaped : `entry-${index + 1}`; }
  catch (error) { if (error instanceof RefreshError) return `entry-${index + 1}`; throw error; }
}

async function collectConfiguredInputs(configuration, token, fetcher = fetch, pinnedCommits = null, reader = defaultReader(fetcher)) {
  const opened = [];
  const tracked = { open: async (...args) => { const snapshot = await reader.open(...args); opened.push(snapshot); return snapshot; } };
  try { return await collectSourceInputs(configuration, token, fetcher, pinnedCommits, tracked); }
  finally { for (const snapshot of opened) snapshot.close(); }
}

async function collectSourceInputs(configuration, token, fetcher, pinnedCommits, reader) {
  validateConfiguration(configuration, configuration.audience);
  const inputs = [], blocked = [], skipped = [], unreadable = [];
  let entries = 0;
  let size = 0;
  for (const source of configuration.sources) {
    if (!source.ref) fail(`Configure an authoritative ref for ${source.repository} before collection`);
    const revision = pinnedCommits === null
      ? await github(`/repos/${source.repository}/commits/${encodeURIComponent(source.ref)}`, token, { fetcher })
      : { sha: pinnedCommits.get(source.repository) };
    if (!sha(revision.sha)) fail('Source ref did not resolve to an immutable commit');
    const snapshot = await reader.open(source.repository, revision.sha, token);
    const tree = snapshot.tree;
    const files = wholeRepository(source)
      ? tree.filter(item => item.type !== 'tree' || item.mode !== '040000').sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0)
        .map(item => ({ path: item.path, type: inferredType(item.path), entry: item }))
      : source.files.map(file => ({ ...file, entry: tree.find(item => item.path === file.path) }));
    entries += files.length;
    if ((!files.length && !wholeRepository(source)) || entries > maxInputs) {
      fail('Complete intake must contain 1-20000 tracked files; no partial inventory accepted');
    }
    const before = inputs.length;
    for (const [index, file] of files.entries()) {
      try {
        if (!safePath(file.path)) {
          skip('Unsafe path: uses characters outside letters, digits, space, _ . / - or has empty or dot segments',
            'Rename the file or folder using only letters, digits, spaces, _, ., / and -.');
        }
        if (!file.entry || file.entry.type !== 'blob' || !['100644', '100755'].includes(file.entry.mode)) {
          if (!wholeRepository(source)) fail('Source must be a regular file, not a symlink or submodule');
          skip('Symbolic link or submodule, not a regular file',
            'Replace it with a regular file, or add the submodule repository as its own source.');
        }
        if (/(?:^|\/)[^/]*\.(?:tfstate|tfplan)(?:\.|$)|(?:^|\/)(?:logs|outputs|\.terraform)(?:\/|$)/i.test(file.path)) {
          skip('Raw Terraform state or plan, logs or unrestricted output', 'Remove it from the repository and add the pattern to .gitignore.');
        }
        if (/\.(?:pdf|docx?|xlsx?|pptx?|zip|gz|bz2|7z|png|jpe?g|gif|webp|ico|exe|dll|pfx|p12)$/i.test(file.path)) {
          skip('Binary, image, archive, Office or PDF file', 'Provide the content as Markdown or text, or remove the file if it is not needed.');
        }
        const original = await snapshot.text(file.entry, wholeRepository(source));
        if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(original)) {
          skip('Contains binary control characters', 'Remove the control characters or convert the file to plain UTF-8 text.');
        }
        if (/^(?:\uFEFF)?(?:%PDF-|GIF8[79]a)/.test(original)) {
          skip('PDF or GIF content in a text file', 'Convert it to Markdown or text, or remove it.');
        }
        if (/^(?:\uFEFF)?version https:\/\/git-lfs.github.com\/spec\/v1(?:\r?\n|$)/.test(original)) {
          skip('Git LFS pointer, not file content', 'Store documentation as regular Git text, or add a Markdown or text version.');
        }
        if (file.type === 'json') {
          try { JSON.parse(original.replace(/^\uFEFF/, '')); } catch { skip('Invalid JSON', 'Fix the JSON syntax.'); }
        }
        const content = screen(original, configuration.audience);
        size += Buffer.byteLength(original);
        if (size > 128_000_000) fail('Complete intake exceeds the 128000000-byte collection budget');
        inputs.push({ repository: source.repository, ref: source.ref, commit: revision.sha,
          path: file.path, type: file.type, sha256: hash(original), content });
      } catch (error) {
        const reason = skipReason(error);
        if (!(error instanceof PipelineError) && !reason) throw error;
        const label = reportLabel(file, index);
        if (reason && wholeRepository(source)) {
          skipped.push({ repository: source.repository, commit: revision.sha, path: label, ...reason,
            source_key: safePath(file.path) ? `${source.repository}:${file.path}` : null,
            link: label === file.path
              ? `https://github.com/${source.repository}/blob/${revision.sha}/${file.path.split('/').map(encodeURIComponent).join('/')}` : null });
        } else {
          blocked.push({ item: `${source.repository}:${label}`, problem: reason?.problem ?? error.message });
        }
      }
    }
    if (wholeRepository(source) && inputs.length === before) unreadable.push(source.repository);
    snapshot.close();
  }
  if (blocked.length) {
    const lines = blocked.map(item => `${item.item}: ${item.problem}`).join('\n');
    const error = new PipelineError(`Collection incomplete: ${entries} tracked entries, ${inputs.length} screened, ${blocked.length} blocked. No drafting or checkpoint advance. ${
      lines.slice(0, 7400)}${lines.length > 7400 ? '\nAdditional blocked entries omitted from this bounded error; coverage is NOT complete.' : ''}`);
    Object.assign(error, { skipped, blocked });
    throw error;
  }
  validateInputInventory({ ...configuration, sources: configuration.sources.filter(source => !unreadable.includes(source.repository)) }, inputs);
  return { inputs, skipped, unreadable };
}

const identity = input => `${input.repository}:${input.path}`;
const evidence = ({ repository, path: file, commit, sha256 }) => ({ repository, path: file, commit, sha256 });
const sameEvidence = (input, item) => ['repository', 'path', 'commit', 'sha256'].every(key => input[key] === item[key]);
const serialize = (metadata, body) => `---\n${Object.entries(metadata).map(([key, value]) => `${key}: ${JSON.stringify(value)}`).join('\n')}\n---\n${body}`;

function frontmatter(text, values) {
  const match = text.match(/^(---\r?\n)([\s\S]*?)(\r?\n---\r?\n)([\s\S]*)$/);
  if (!match) fail('Missing restricted review frontmatter');
  const newline = match[1].includes('\r\n') ? '\r\n' : '\n';
  const remaining = { ...values };
  const lines = match[2].split(/\r?\n/).flatMap(line => {
    const key = line.slice(0, line.indexOf(':'));
    if (!Object.hasOwn(remaining, key)) return [line];
    const value = remaining[key];
    delete remaining[key];
    return value === undefined ? [] : [`${key}: ${JSON.stringify(value)}`];
  });
  for (const [key, value] of Object.entries(remaining)) if (value !== undefined) lines.push(`${key}: ${JSON.stringify(value)}`);
  return match[1] + lines.join(newline) + match[3] + match[4];
}

function contentVersion(text) {
  return text === null ? 0 : parseDocument(text).metadata.version ?? 0;
}

function sameAnswer(left, right) {
  return publicationContentHash(frontmatter(left, { version: undefined }))
    === publicationContentHash(frontmatter(right, { version: undefined }));
}

// Review-only provenance is never accepted by the published-document parser.
export function parseReview(text) {
  const metadata = {};
  const header = text.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n/);
  if (!header) fail('Missing restricted review frontmatter');
  for (const [, key, value] of header[1].matchAll(/^(review_target|review_context|review_evidence|review_base_version|review_base_sha256|review_remove): (.+)\r?$/gm)) {
    if (Object.hasOwn(metadata, key)) fail('Duplicate review provenance');
    try { metadata[key] = JSON.parse(value); } catch { fail('Invalid review provenance'); }
  }
  if (!reviewFields.every(key => Object.hasOwn(metadata, key))
    || (Object.hasOwn(metadata, 'review_remove') && metadata.review_remove !== true)) fail('Missing or invalid review provenance');
  const content = frontmatter(text, Object.fromEntries([...reviewFields, 'review_remove'].map(key => [key, undefined])));
  return { ...metadata, content, document: parseDocument(content) };
}

export function reviewMarkdown(root, result) {
  const { updates, ...context } = result.proposal.payload;
  return Object.fromEntries(updates.map(update => {
    const text = frontmatter(result.files[update.draft_path], {
      review_target: update.path, review_context: context, review_evidence: update.evidence,
      review_base_version: contentVersion(optionalRead(root, update.path)), review_base_sha256: update.before_sha256,
      ...(update.remove ? { review_remove: true } : {}),
    });
    if (Buffer.byteLength(text) > 512_000) fail('Complete review Markdown exceeds immutable read limit; human scope review required');
    return [update.draft_path, text];
  }));
}

export function proposalFromMarkdown(root, audience, markdown) {
  let context;
  const files = {}, updates = [];
  for (const [file, text] of Object.entries(markdown).sort(([a], [b]) => a.localeCompare(b))) {
    const item = parseReview(text);
    if (!destination(item.review_target, audience) || file !== reviewPath(item.review_target, audience)
      || !Number.isSafeInteger(item.review_base_version) || item.review_base_version < 0
      || item.document.metadata.version !== item.review_base_version + 1
      || (item.review_base_sha256 !== null && !digest(item.review_base_sha256))
      || contentVersion(optionalRead(root, item.review_target)) !== item.review_base_version) fail('Invalid or stale review content version');
    if (context && encode(context) !== encode(item.review_context)) fail('Conflicting review provenance');
    context = item.review_context;
    files[file] = item.content;
    updates.push({ path: item.review_target, draft_path: file, before_sha256: item.review_base_sha256,
      sha256: hash(item.content), evidence: item.review_evidence, ...(item.review_remove ? { remove: true } : {}) });
  }
  if (!context || context.audience !== audience) fail('Missing audience-bound review content');
  const payload = { ...context, updates };
  const proposal = { proposal_id: hash(encode(payload)), payload };
  validateProposal(root, proposal, files);
  return { proposal, files };
}

function destination(file, audience) {
  return safePath(file) && (audience === 'shared'
    ? /^(?:guides|reference|known-errors)\/[a-z0-9-]+\.md$/.test(file)
    : /^admin\/(?:guides|reference|known-errors)\/[a-z0-9-]+\.md$/.test(file));
}

export function validateAnswer(text, file, audience, status = 'pending-review') {
  if (!destination(file, audience)) fail('Proposal crosses audience or destination boundary');
  const document = validateDocument(text, file);
  if (document.metadata.review_status !== status || (status === 'pending-review'
    && (document.metadata.verification_status !== 'unverified' || document.metadata.reviewed_by || document.metadata.reviewed_at))) {
    fail('Draft must remain pending-review/unverified without approval attribution');
  }
  if (screen(text, audience) !== text) fail('Draft contains personal or restricted identifying values');
  if (/<(?:script|iframe|object|embed|img|svg|style)\b/i.test(document.body)) fail('Executable/raw source output is not guidance');
  const fences = [...document.body.matchAll(/^ {0,3}(`{3,}|~{3,})([^\n]*)$/gm)];
  for (let index = 0; index < fences.length; index += 2) {
    if (!['json', 'text'].includes(fences[index][2].trim())) fail('Executable/raw source output is not guidance');
  }
  // New conversions must explicitly account for every FAQ; runtime routes remain optional.
  if (['guide', 'reference'].includes(document.metadata.document_type)
    && document.metadata.answer_presentation_version !== 1) fail('Answer presentation coverage is required');
  return document;
}

function preserve(original, updated) {
  const old = parseDocument(original), next = parseDocument(updated);
  if (old.metadata.id !== next.metadata.id || old.metadata.title !== next.metadata.title
    || JSON.stringify(old.metadata.answers ?? []) !== JSON.stringify(next.metadata.answers ?? [])) fail('Stable IDs, title and answer routes must be preserved');
  for (const heading of old.body.match(/^#{1,6} .+$/gm) ?? []) {
    if (!next.body.split('\n').includes(heading)) fail('Existing question/display headings must be preserved');
  }
  for (const anchor of anchors(old.body)) if (!anchors(next.body).has(anchor)) fail('Existing anchors must be preserved');
}

function rejectSourceWrapper(texts, content) {
  const source = content.replace(/\r\n/g, '\n').trim();
  if (source.length > 256 && texts.some(text => text.replace(/\r\n/g, '\n').includes(source))) {
    fail('Raw source wrappers are not converted question-and-answer guidance');
  }
}

function sourceRemovals(root, audience, configuration, scope, previous, inputs) {
  const missing = previous.filter(item => !inputs.some(input => identity(input) === identity(item)));
  if (!missing.length) return { inputs: [], documents: [] };
  if (!configuration.inventory || !scope || missing.some(item => scope.repositories.some(source => source.repository === item.repository))) {
    fail('Previously observed source paths were removed; human scope review is required');
  }
  const repositories = new Set(missing.map(item => item.repository));
  const documents = validateRepository(root).documents.filter(doc => destination(doc.path, audience)).map(doc => ({
    path: doc.path, ...parseDocument(read(root, doc.path)),
  })).filter(doc => {
    const text = read(root, doc.path);
    return repositories.has(doc.metadata.source_repository)
      || [...repositories].some(repository => text.includes(`https://github.com/${repository}/blob/`));
  });
  if (!documents.length && [...repositories].some(repository => !scope.excluded?.some(item => item.repository === repository))) {
    fail(`Inventory removed ${[...repositories].join(', ')}; human review must acknowledge removal with no derived answers before checkpoint advance`);
  }
  return { inputs: missing, documents };
}

export function makeProposal(root, audience, inputs, draft, baseCommit, scope = null) {
  audienceCheck(audience);
  if (!sha(baseCommit)) fail('Proposal requires immutable base commit');
  const configText = read(root, configurationPath(audience));
  const configuration = validateConfiguration(JSON.parse(configText), audience);
  const baselineText = optionalRead(root, baselinePath(audience));
  const baseline = baselineText ? JSON.parse(baselineText) : { inputs: [] };
  validateInputInventory(scopedConfiguration(configuration, scope, inputs), inputs);
  const removals = sourceRemovals(root, audience, configuration, scope, baseline.inputs, inputs);
  const changed = inputs.filter(input => baseline.inputs.find(previous => identity(previous) === identity(input))?.sha256 !== input.sha256);
  if (!changed.length && !removals.inputs.length) return null;
  const contextPaths = new Set(draftingDocuments(root, audience, inputs).documents.map(doc => doc.path));
  if (!exact(draft, ['updates', 'dispositions']) || !Array.isArray(draft.updates) || !Array.isArray(draft.dispositions)
    || draft.updates.length > 30) fail('Invalid converter response');
  const files = {}, updates = [], seen = new Set();
  for (const doc of removals.documents) {
    const original = read(root, doc.path);
    const content = frontmatter(original, { version: contentVersion(original) + 1,
      review_status: 'pending-review', verification_status: 'unverified', reviewed_by: undefined, reviewed_at: undefined });
    const draftPath = reviewPath(doc.path, audience);
    const used = removals.inputs.filter(item => doc.metadata.source_repository === item.repository
      || doc.body.includes(`https://github.com/${item.repository}/blob/${item.commit}/${item.path}`));
    files[draftPath] = content;
    updates.push({ path: doc.path, draft_path: draftPath, before_sha256: hash(original), sha256: hash(content),
      evidence: used.map(evidence), remove: true });
    seen.add(doc.path);
  }
  for (const update of draft.updates) {
    if (!exact(update, ['path', 'content', 'evidence']) || !destination(update.path, audience)
      || seen.has(update.path) || !Array.isArray(update.evidence) || !update.evidence.length
      || typeof update.content !== 'string') fail('Invalid converter update');
    seen.add(update.path);
    const doc = validateAnswer(update.content, update.path, audience);
    for (const item of update.evidence) {
      if (!exact(item, ['repository', 'path', 'commit', 'sha256'])
        || !inputs.some(input => sameEvidence(input, item))) fail('Missing or uncollected immutable evidence');
      const citation = `https://github.com/${item.repository}/blob/${item.commit}/${item.path}`;
      if (!doc.body.includes(citation)) fail('Answer must cite each immutable source');
    }
    if (!update.evidence.some(item => item.repository === doc.metadata.source_repository
      && item.path === doc.metadata.source_path && item.commit === doc.metadata.source_commit)) fail('Primary provenance differs from collected evidence');
    const original = optionalRead(root, update.path);
    if (original !== null && !contextPaths.has(update.path)) fail('Existing answer context is unavailable; explicit context review is required');
    if (original) preserve(original, update.content);
    if (original !== null && sameAnswer(original, update.content)) continue;
    const draftPath = reviewPath(update.path, audience);
    const content = frontmatter(update.content, { version: contentVersion(original) + 1 });
    files[draftPath] = content;
    updates.push({ path: update.path, draft_path: draftPath, before_sha256: original === null ? null : hash(original),
      sha256: hash(content), evidence: update.evidence });
  }
  const dispositions = new Set();
  for (const item of draft.dispositions) {
    if (!exact(item, ['source', 'disposition', 'reason']) || !changed.some(input => identity(input) === item.source)
      || dispositions.has(item.source) || !['updated', 'no-guidance-change'].includes(item.disposition)
      || typeof item.reason !== 'string' || item.reason.trim().length < 20 || item.reason.length > 1000
      || screen(item.reason, audience) !== item.reason) fail('Missing disposition, evidence gap or unsafe reason');
    if (item.disposition === 'updated' && !updates.some(update => update.evidence.some(input => identity(input) === item.source))) fail('Updated disposition has no changed answer');
    dispositions.add(item.source);
  }
  if (dispositions.size !== changed.length) fail('Every changed source needs a human-reviewable disposition');
  const removedDispositions = removals.inputs.map(item => ({ source: identity(item), disposition: 'removed',
    reason: 'The reviewed source scope removed or retired this repository; withdraw any affected derived answers after exact-head human approval.' }));
  if (updates.length > 30) fail('Complete answer update/removal review exceeds 30 destinations; human scope review required');
  const payload = { schema_version: 1, audience, intake: 'upstream', base_commit: baseCommit, configuration_sha256: hash(configText),
    baseline_sha256: baselineText === null ? null : hash(baselineText),
    inputs: inputs.map(({ content, ...input }) => input), updates, dispositions: [...draft.dispositions, ...removedDispositions], ...(scope ? { scope } : {}) };
  const proposal = { proposal_id: hash(encode(payload)), payload };
  for (const input of inputs) if (typeof input.content === 'string') rejectSourceWrapper(Object.values(files), input.content);
  validateProposal(root, proposal, files);
  return { proposal, files };
}

export function validateProposal(root, proposal, files) {
  if (!exact(proposal, ['proposal_id', 'payload']) || !digest(proposal.proposal_id)
    || hash(encode(proposal.payload)) !== proposal.proposal_id) fail('Proposal hash mismatch');
  const p = proposal.payload;
  const payloadFields = ['schema_version', 'audience', 'intake', 'base_commit', 'configuration_sha256', 'baseline_sha256', 'inputs', 'updates', 'dispositions'];
  if (!(exact(p, payloadFields) || exact(p, [...payloadFields, 'scope']))
    || p.schema_version !== 1 || !sha(p.base_commit) || !Array.isArray(p.inputs)
    || p.inputs.length > maxInputs || !['upstream', 'migration'].includes(p.intake)
    || !Array.isArray(p.updates) || p.updates.length > 30
    || !Array.isArray(p.dispositions) || p.dispositions.length > maxInputs) fail('Invalid proposal envelope');
  audienceCheck(p.audience);
  if (hash(read(root, configurationPath(p.audience, p.intake))) !== p.configuration_sha256) fail('Stale source configuration');
  const baseline = optionalRead(root, baselinePath(p.audience, p.intake));
  if ((baseline === null ? null : hash(baseline)) !== p.baseline_sha256) fail('Stale approved baseline');
  const seen = new Set();
  const savedPrevious = baseline === null ? [] : JSON.parse(baseline).inputs;
  const removalConfiguration = p.intake === 'upstream'
    ? validateConfiguration(JSON.parse(read(root, configurationPath(p.audience))), p.audience) : null;
  const removals = removalConfiguration
    ? sourceRemovals(root, p.audience, removalConfiguration, p.scope, savedPrevious, p.inputs) : { inputs: [], documents: [] };
  const contextPaths = p.intake === 'upstream'
    ? new Set(draftingDocuments(root, p.audience, p.inputs).documents.map(doc => doc.path)) : null;
  for (const update of p.updates) {
    const updateFields = ['path', 'draft_path', 'before_sha256', 'sha256', 'evidence'];
    if (!(exact(update, updateFields) || (exact(update, [...updateFields, 'remove']) && update.remove === true))
      || !destination(update.path, p.audience) || update.draft_path !== `reviews/${p.audience}/drafts/${update.path}`
      || seen.has(update.path) || !digest(update.sha256)
      || (update.before_sha256 !== null && !digest(update.before_sha256))
      || !Object.hasOwn(files, update.draft_path) || hash(files[update.draft_path]) !== update.sha256) fail('Invalid update or draft hash');
    seen.add(update.path);
    const current = optionalRead(root, update.path);
    if (!update.remove && current !== null && contextPaths && !contextPaths.has(update.path)) fail('Existing answer context is unavailable; explicit context review is required');
    if ((current === null ? null : hash(current)) !== update.before_sha256) fail('Stale destination baseline');
    if (update.remove) {
      if (!removals.documents.some(doc => doc.path === update.path) || current === null) fail('Deletion is not bound to a removed inventory repository');
      validateDocument(files[update.draft_path], update.path);
      preserve(current, files[update.draft_path]);
    } else validateAnswer(files[update.draft_path], update.path, p.audience);
    if (parseDocument(files[update.draft_path]).metadata.version !== contentVersion(current) + 1) fail('Invalid review content version');
    if (!update.remove && current !== null && sameAnswer(current, files[update.draft_path])) fail('Unchanged answer is not a review delta');
    if (current) preserve(current, files[update.draft_path]);
  }
  if (removals.documents.some(doc => !p.updates.some(update => update.remove && update.path === doc.path))) fail('Removed repository still has derived answers not reviewed for withdrawal');
  if (Object.keys(files).sort().join('\n') !== p.updates.map(update => update.draft_path).sort().join('\n')) fail('Unexpected draft inventory');
  // Repeat input and evidence checks at promotion; never trust a staged hash alone.
  const migration = p.intake === 'migration' ? migrationQueue(root, p.audience) : null;
  const configuration = migration ? null : validateConfiguration(JSON.parse(read(root, configurationPath(p.audience))), p.audience);
  if (p.inputs.some(input => !exact(input, ['repository', 'ref', 'commit', 'path', 'type', 'sha256'])
    || !sha(input.commit) || !digest(input.sha256))) fail('Invalid proposal input inventory');
  if (migration) {
    if (p.scope) fail('Migration cannot expand source scope');
    if (p.inputs.length !== migration.inputs.length || new Set(p.inputs.map(identity)).size !== p.inputs.length
      || p.inputs.some(input => !migration.inputs.some(item => matchesSource({
        repository: item.repository, ref: item.ref, files: [item],
      }, input)))) fail('Invalid migration input inventory');
  } else validateInputInventory(scopedConfiguration(configuration, p.scope, p.inputs), p.inputs);
  const revisions = new Map();
  for (const input of p.inputs) {
    if (!migration && revisions.has(input.repository) && revisions.get(input.repository) !== input.commit) fail('Source repository must use one immutable snapshot');
    revisions.set(input.repository, input.commit);
  }
  if (migration && (migration.updates.length !== p.updates.length || p.updates.some(update =>
    !migration.updates.some(expected => expected.path === update.path
      && expected.before_sha256 === update.before_sha256
      && encode(expected.evidence) === encode(update.evidence))))) fail('Migration differs from frozen draft queue');
  const previous = baseline === null ? [] : JSON.parse(baseline).inputs;
  if (!Array.isArray(previous)) fail('Invalid checkpoint');
  const changed = [...p.inputs.filter(input => previous.find(item => identity(item) === identity(input))?.sha256 !== input.sha256), ...removals.inputs];
  if (!changed.length || p.dispositions.length !== changed.length || new Set(p.dispositions.map(item => item.source)).size !== changed.length) fail('Invalid changed-source dispositions');
  for (const item of p.dispositions) {
    if (!exact(item, ['source', 'disposition', 'reason']) || !changed.some(input => identity(input) === item.source)
      || !(removals.inputs.some(input => identity(input) === item.source) ? item.disposition === 'removed'
        : ['updated', 'no-guidance-change'].includes(item.disposition)) || typeof item.reason !== 'string'
      || item.reason.trim().length < 20 || item.reason.length > 1000 || screen(item.reason, p.audience) !== item.reason
      || (item.disposition === 'updated' && !p.updates.some(update => update.evidence.some(input => identity(input) === item.source)))) fail('Invalid disposition or evidence gap');
  }
  for (const update of p.updates) {
    if (!Array.isArray(update.evidence) || !update.evidence.length) fail('Missing evidence');
    const doc = parseDocument(files[update.draft_path]);
    for (const item of update.evidence) {
      if (!exact(item, ['repository', 'path', 'commit', 'sha256'])
        || !(update.remove ? removals.inputs : p.inputs).some(input => sameEvidence(input, item))
        || (!update.remove && !doc.body.includes(`https://github.com/${item.repository}/blob/${item.commit}/${item.path}`))) fail('Invalid immutable citation');
    }
    if (!update.remove && !update.evidence.some(item => item.repository === doc.metadata.source_repository
      && item.path === doc.metadata.source_path && item.commit === doc.metadata.source_commit)) fail('Invalid primary provenance');
  }
  const documents = validateRepository(root).documents.filter(doc => !seen.has(doc.path)).map(doc => {
    const value = parseDocument(read(root, doc.path));
    return { ...value, path: doc.path };
  });
  for (const update of p.updates.filter(update => !update.remove)) documents.push({ ...parseDocument(files[update.draft_path]), path: update.path });
  validateAnswerScope(documents);
  if (new Set(documents.map(doc => doc.metadata.id)).size !== documents.length) fail('Duplicate stable document ID');
  return proposal;
}

function migrationQueue(root, audience) {
  const value = JSON.parse(read(root, configurationPath(audience, 'migration')));
  if (!exact(value, ['schema_version', 'audience', 'drafts']) || value.schema_version !== 1
    || audience !== 'shared' || value.audience !== audience || !Array.isArray(value.drafts)
    || value.drafts.length !== 7) fail('Invalid frozen shared decision migration queue');
  const files = {}, updates = [], inputs = new Map(), destinations = new Set();
  for (const entry of value.drafts) {
    if (!exact(entry, ['path', 'draft_path', 'sha256', 'evidence']) || !destination(entry.path, audience)
      || !/^reviews\/shared\/migrations\/[a-z0-9-]+\.md$/.test(entry.draft_path)
      || destinations.has(entry.path) || !digest(entry.sha256) || !Array.isArray(entry.evidence)
      || !entry.evidence.length) fail('Invalid frozen migration draft');
    destinations.add(entry.path);
    for (const item of entry.evidence) {
      if (!exact(item, ['repository', 'path', 'commit', 'sha256']) || item.repository !== sourceRepository
        || !safePath(item.path) || !sha(item.commit) || !digest(item.sha256)) fail('Invalid frozen migration evidence');
      const key = identity(item);
      if (inputs.has(key) && !sameEvidence(inputs.get(key), item)) fail('Conflicting migration provenance');
      inputs.set(key, { ...item, ref: item.commit, type: 'markdown' });
    }
    const content = read(root, entry.draft_path);
    if (hash(content) !== entry.sha256) fail('Frozen migration draft changed; regenerate and review queue configuration');
    validateAnswer(content, entry.path, audience);
    const draftPath = reviewPath(entry.path, audience);
    const versioned = frontmatter(content, { version: 1 });
    files[draftPath] = versioned;
    updates.push({ path: entry.path, draft_path: draftPath, before_sha256: null, sha256: hash(versioned), evidence: entry.evidence });
  }
  return { files, updates, inputs: [...inputs.values()] };
}

export function makeMigrationProposal(root, baseCommit) {
  if (!sha(baseCommit)) fail('Migration proposal requires immutable base');
  const audience = 'shared', intake = 'migration';
  if (optionalRead(root, baselinePath(audience, intake)) !== null) fail('Migration already promoted');
  const queue = migrationQueue(root, audience);
  const payload = { schema_version: 1, audience, intake, base_commit: baseCommit,
    configuration_sha256: hash(read(root, configurationPath(audience, intake))), baseline_sha256: null,
    inputs: queue.inputs, updates: queue.updates,
    dispositions: queue.inputs.map(input => ({ source: identity(input), disposition: 'updated',
      reason: 'Convert the preserved proposed decision evidence into a pending shared question-and-answer guide, without approval or live-state claims.' })) };
  const proposal = { proposal_id: hash(encode(payload)), payload };
  validateProjection(root, proposal, queue.files);
  return { proposal, files: queue.files };
}

// Validate the full projected repository, including relative links and answer inventory,
// without writing draft content into publication roots.
export function validateProjection(root, proposal, files, attribution) {
  validateProposal(root, proposal, files);
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'knowledge-projection-'));
  try {
    for (const name of ['guides', 'reference', 'known-errors', 'run-records', 'assets', 'admin', 'decisions',
      'engineering-contract', 'scripts', 'README.md', '_SCHEMA.md', 'AGENTS.md']) {
      if (fs.existsSync(path.join(root, name))) fs.cpSync(path.join(root, name), path.join(temporary, name), { recursive: true });
    }
    for (const update of proposal.payload.updates) {
      if (update.remove) fs.unlinkSync(path.join(temporary, update.path));
      else write(temporary, update.path, attribution ? approvedText(files[update.draft_path], attribution) : files[update.draft_path]);
    }
    updateMigrationPublication(temporary, proposal.payload.updates.filter(update => !update.remove).map(update => update.path));
    validateRepository(temporary);
  } finally { fs.rmSync(temporary, { recursive: true, force: true }); }
}

function updateMigrationPublication(root, updatedPaths) {
  const file = 'assets/migration-map.json';
  const value = JSON.parse(read(root, file));
  let changed = false;
  for (const entry of [...value.entries, ...(value.derived_documents ?? [])]) {
    if (!updatedPaths.includes(entry.destination_path)) continue;
    const text = read(root, entry.destination_path), { metadata } = parseDocument(text);
    // Original migration hashes/provenance remain immutable historical evidence.
    entry.publication = { source_repository: metadata.source_repository, source_path: metadata.source_path,
      source_commit: metadata.source_commit, content_sha256: publicationContentHash(text) };
    changed = true;
  }
  if (changed) write(root, file, encode(value));
}

function approvedText(text, attribution) {
  return frontmatter(text, { review_status: 'approved', verification_status: 'verified',
    reviewed_by: attribution.login, reviewed_at: attribution.submitted_at });
}

export function verifyApproval(pr, reviews, changedFiles, audience, expectedHead) {
  audienceCheck(audience);
  if (!Number.isSafeInteger(pr.number) || pr.number < 1 || !sha(expectedHead) || pr.head?.sha !== expectedHead
    || pr.head?.repo?.full_name !== sourceRepository || pr.base?.repo?.full_name !== sourceRepository
    || pr.base?.ref !== 'main' || !pr.merged || !sha(pr.merge_commit_sha)) fail('Review must be a merged same-repository proposal PR');
  if (!Array.isArray(changedFiles) || !changedFiles.length
    || changedFiles.some(file => !safePath(file) || !file.endsWith('.md')
      || !file.startsWith(`reviews/${audience}/`))) fail('Review PR contains non-Markdown or cross-audience changes');
  const latest = new Map();
  for (const review of [...reviews].sort((a, b) => a.id - b.id)) {
    if (!review.user?.login || review.state === 'COMMENTED') continue;
    latest.set(review.user.login, review);
  }
  if ([...latest.values()].some(review => review.state === 'CHANGES_REQUESTED')) fail('Outstanding requested changes');
  const human = user => user?.type === 'User' && typeof user.login === 'string' && user.login && !user.login.endsWith('[bot]');
  const validTime = value => typeof value === 'string' && Number.isFinite(Date.parse(value));
  const approval = [...latest.values()].find(review => review.state === 'APPROVED'
    && review.commit_id === expectedHead && human(review.user) && validTime(review.submitted_at));
  // GitHub never lets a PR author approve their own PR, so a human merge of the exact head also counts.
  const decision = approval ? { login: approval.user.login, at: approval.submitted_at }
    : human(pr.merged_by) && validTime(pr.merged_at) ? { login: pr.merged_by.login, at: pr.merged_at } : null;
  if (!decision) fail('A human approval or human merge of the exact PR head is required');
  return { login: decision.login, submitted_at: new Date(decision.at).toISOString().replace(/\.\d{3}Z$/, 'Z') };
}

async function paginate(apiPath, token) {
  const result = [];
  for (let page = 1; page <= 20; page++) {
    const values = await github(`${apiPath}${apiPath.includes('?') ? '&' : '?'}per_page=100&page=${page}`, token);
    if (!Array.isArray(values)) fail('Invalid GitHub collection');
    result.push(...values);
    if (values.length < 100) return result;
  }
  fail('GitHub collection exceeds safe pagination bound');
}

async function approvedProposal(root, audience, number, token, requireInput = true) {
  if (!/^[1-9]\d*$/.test(number)) fail('A review PR number is required');
  const prefix = `/repos/${sourceRepository}/pulls/${number}`;
  const pr = await github(prefix, token);
  const reviews = await paginate(`${prefix}/reviews`, token);
  const changes = await paginate(`${prefix}/files`, token);
  const attribution = verifyApproval(pr, reviews, changes.map(file => file.filename), audience, pr.head.sha);
  const permission = await github(`/repos/${sourceRepository}/collaborators/${encodeURIComponent(attribution.login)}/permission`, token);
  if (!['admin', 'maintain', 'write'].includes(permission.permission)) fail('Reviewer must have repository write/maintain/admin permission');
  const markdown = await changedMarkdown(changes, audience, pr.head.sha, token);
  if (git(root, 'merge-base', '--is-ancestor', pr.merge_commit_sha, 'HEAD') !== '') fail('Review merge not in current main');
  if (Object.keys(markdown).some(file => file.startsWith(`reviews/${audience}/items/`))) {
    if (changes.length !== 1) fail('An exception review changes exactly one Markdown review item');
    const [file, text] = Object.entries(markdown)[0];
    return { exception: parseException(text, file, audience, requireInput), attribution, pr };
  }
  const { proposal, files } = proposalFromMarkdown(root, audience, markdown);
  validateProjection(root, proposal, files, attribution);
  git(root, 'merge-base', '--is-ancestor', proposal.payload.base_commit, 'HEAD');
  return { proposal, files, attribution, pr };
}

async function changedMarkdown(changes, audience, head, token) {
  if (!changes.length || changes.length > 30 || changes.some(file => !safePath(file.filename)
    || !file.filename.startsWith(`reviews/${audience}/`) || !file.filename.endsWith('.md')
    || !['added', 'modified'].includes(file.status))) fail('Unexpected review PR files; only changed audience Markdown is permitted');
  const markdown = {};
  for (const file of changes) markdown[file.filename] = await remoteText(sourceRepository, file.filename, head, token);
  return markdown;
}

export async function checkReview(root, audience, number, token) {
  audienceCheck(audience);
  if (!/^[1-9]\d*$/.test(number)) fail('A review PR number is required');
  const prefix = `/repos/${sourceRepository}/pulls/${number}`;
  const pr = await github(prefix, token);
  if (pr.head?.repo?.full_name !== sourceRepository || pr.base?.repo?.full_name !== sourceRepository
    || pr.base?.ref !== 'main' || !sha(pr.head?.sha)) fail('Review requires same-repository proposal PR into main');
  const changes = await paginate(`${prefix}/files`, token);
  const markdown = await changedMarkdown(changes, audience, pr.head.sha, token);
  if (Object.keys(markdown).some(file => file.startsWith(`reviews/${audience}/items/`))) {
    if (changes.length !== 1) fail('An exception review changes exactly one Markdown review item');
    const [file, text] = Object.entries(markdown)[0];
    parseException(text, file, audience, true);
    console.log('Human exception input is structurally valid; human approval or merge is still required.');
    return;
  }
  const { proposal, files } = proposalFromMarkdown(root, audience, markdown);
  validateProjection(root, proposal, files);
  git(root, 'merge-base', '--is-ancestor', proposal.payload.base_commit, 'HEAD');
  console.log('Projected answers pass schema/content checks; no human approval is implied.');
}

export function draftingDocuments(root, audience, inputs) {
  const all = validateRepository(root).documents.filter(doc => destination(doc.path, audience)).map(doc => {
    const content = read(root, doc.path);
    return { path: doc.path, content, metadata: parseDocument(content).metadata };
  });
  const selected = new Set(all.filter(doc => inputs.some(input =>
    input.repository === doc.metadata.source_repository || doc.content.includes(input.repository))).map(doc => doc.path));
  // Follow declared local provenance, including the deliberate admin-to-guides
  // move. This selects existing answer context, never additional upstream inputs.
  let added;
  do {
    added = false;
    for (const doc of all) {
      if (selected.has(doc.path) || doc.metadata.source_repository !== sourceRepository) continue;
      const sourceName = path.posix.basename(doc.metadata.source_path);
      if ([...selected].some(file => path.posix.basename(file) === sourceName)) {
        selected.add(doc.path);
        added = true;
      }
    }
  } while (added);
  return {
    documents: all.filter(doc => selected.has(doc.path)).map(({ path: file, content }) => ({
      path: file, content: screen(content, audience),
    })),
    document_index: all.map(doc => ({
      path: doc.path, id: doc.metadata.id, title: doc.metadata.title,
      source_repository: doc.metadata.source_repository, source_path: doc.metadata.source_path,
    })),
  };
}

export async function draftBatches(root, audience, inputs, changed, env, requester = requestDraft) {
  const updates = new Map(), contexts = new Map(), dispositions = [];
  const instructions = read(root, 'sources/AGENTS.md');
  const contracts = { schema: read(root, '_SCHEMA.md'), intake_contract: read(root, 'sources/SCHEMA.md') };
  let offset = 0;
  while (offset < changed.length) {
    let batch = [], payload;
    for (const input of changed.slice(offset, offset + 20)) {
      const candidate = [...batch, input];
      const key = [...new Set(candidate.map(input => input.repository))].sort().join('\n');
      if (!contexts.has(key)) contexts.set(key, draftingDocuments(root, audience, candidate));
      const context = contexts.get(key);
      const documents = new Map(context.documents.map(doc => [doc.path, doc]));
      for (const update of updates.values()) documents.set(update.path, { path: update.path, content: update.content });
      const next = JSON.stringify({ audience, ...contracts, document_index: context.document_index,
        documents: [...documents.values()], previous_updates: [...updates.values()].map(({ content, ...item }) => item),
        input_inventory: inputs.map(({ content, ...item }) => item),
        inputs: candidate.map(({ content, ...item }) => ({ ...item,
          chunks: Array.from({ length: Math.max(1, Math.ceil(content.length / 16_000)) }, (_, index) => ({
            index, content: content.slice(index * 16_000, (index + 1) * 16_000),
          })),
        })) });
      if (candidate.reduce((sum, item) => sum + Buffer.byteLength(item.content), 0) > 750_000
        || Buffer.byteLength(next) + Buffer.byteLength(instructions) > 1_000_000) break;
      batch = candidate;
      payload = next;
    }
    if (!batch.length) fail('Complete source file plus answer context exceeds bounded drafting request; human review required');
    const requested = new Map();
    let draft;
    for (let round = 0; round <= 4; round++) {
      const request = JSON.parse(payload);
      request.context_inputs = [...requested.values()].map(({ content, ...item }) => ({ ...item,
        chunks: Array.from({ length: Math.max(1, Math.ceil(content.length / 16_000)) }, (_, index) => ({
          index, content: content.slice(index * 16_000, (index + 1) * 16_000),
        })),
      }));
      const serialized = JSON.stringify(request);
      if (Buffer.byteLength(serialized) + Buffer.byteLength(instructions) > 1_000_000) {
        fail('Required cross-file source context exceeds complete request limit; human review required');
      }
      draft = await requester(serialized, instructions, env);
      if (!exact(draft, ['context_requests'])) break;
      if (round === 4 || !Array.isArray(draft.context_requests) || !draft.context_requests.length
        || draft.context_requests.length > 20 || new Set(draft.context_requests).size !== draft.context_requests.length) {
        fail('Incomplete or excessive cross-file context request; human review required');
      }
      for (const id of draft.context_requests) {
        const source = inputs.find(item => identity(item) === id);
        if (!source || requested.has(id) || batch.some(item => identity(item) === id)) {
          fail('Cross-file context must name a new already-collected immutable input; no repository traversal');
        }
        requested.set(id, source);
      }
    }
    if (!exact(draft, ['updates', 'dispositions']) || !Array.isArray(draft.updates) || draft.updates.length > 30
      || !Array.isArray(draft.dispositions) || draft.dispositions.length !== batch.length
      || new Set(draft.dispositions.map(item => item.source)).size !== batch.length
      || draft.dispositions.some(item => !batch.some(input => identity(input) === item.source))) {
      fail('Incomplete converter batch coverage; no proposal or checkpoint advanced');
    }
    const seen = new Set();
    const available = inputs.filter(input => requested.has(identity(input)) || !changed.some(item => identity(item) === identity(input))
      || changed.slice(0, offset + batch.length).some(item => identity(item) === identity(input)));
    for (const update of draft.updates) {
      if (!exact(update, ['path', 'content', 'evidence']) || seen.has(update.path)
        || !Array.isArray(update.evidence) || !update.evidence.length
        || update.evidence.some(item => !available.some(input => sameEvidence(input, item)))) {
        fail('Invalid batched update or unprocessed evidence');
      }
      seen.add(update.path);
      validateAnswer(update.content, update.path, audience);
      const previous = updates.get(update.path);
      if (previous) {
        preserve(previous.content, update.content);
        if (previous.evidence.some(item => !update.evidence.some(next => sameEvidence(next, item)))) {
          fail('Later batch discarded earlier evidence; human context review required');
        }
      }
      updates.set(update.path, update);
    }
    if (updates.size > 30) fail('Complete conversion exceeds 30 answer updates; human scope review required');
    dispositions.push(...draft.dispositions);
    offset += batch.length;
  }
  return { updates: [...updates.values()], dispositions };
}

function commitState(root, paths, message) {
  git(root, 'add', '--', ...paths);
  git(root, '-c', 'user.name=knowledge-review[bot]', '-c', 'user.email=knowledge-review[bot]@users.noreply.github.com',
    'commit', '-m', message, '-m', 'Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>');
  git(root, 'push', 'origin', 'HEAD:main');
}

const skippedReportPath = audience => `sources/${audience}/SKIPPED.md`;
const repositoryFixes = {
  [emptyRepository.status]: 'Push at least one commit with documentation or configuration, or retire the repository in sources/shared/sources.json if it is not used.',
  [unreadableRepository.status]: 'Fix the files listed for this repository under Files so at least one of them can be read.',
};
const blockedFix = problem => /\(403\)/.test(problem) ? 'Give the source-read PAT (KNOWLEDGE_PAT) read access to this repository.'
  : /\(404\)/.test(problem) ? 'Check that the repository or file exists and the PAT can read it; retire a deleted repository in sources.json.'
    : /\((?:429|5\d\d)\)/.test(problem) ? 'GitHub was unavailable or rate-limited; rerun intake.'
      : 'Fix the source or configuration described in the problem, then rerun intake.';

export function skippedMarkdown(audience, report) {
  const cell = value => String(value ?? '').replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();
  const table = (head, rows) => rows.length ? `| ${head.join(' | ')} |\n| ${head.map(() => '---').join(' | ')} |\n${
    rows.map(row => `| ${row.map(cell).join(' | ')} |`).join('\n')}\n` : 'None.\n';
  const repositories = report.excluded.filter(item => repositoryFixes[item.status]);
  return `# Skipped ${audience} source items

Generated by \`scripts/reviewed-sources.mjs\` during source intake. Do not edit it; every intake run rewrites it.

Intake skips these items so that the readable sources can still be drafted for review. Skipped items are not sent
to drafting and are not recorded in the source baseline. Fix them in the source repository and run intake again;
fixed files are then collected as new changes.

Intake result: ${report.failure ? `stopped. ${cell(report.failure)}` : 'completed with the readable sources.'}

Inventory commit: ${report.inventory_commit ? `\`${report.inventory_commit}\`` : 'not used'}.

## Blocked items

These stop intake completely; fix them first.

${table(['Item', 'Problem', 'How to fix'], report.blocked.map(item => [item.item, item.problem, blockedFix(item.problem)]))}
## Repositories

${table(['Repository', 'Default branch', 'Status', 'How to fix'],
    repositories.map(item => [item.repository, item.default_branch, item.status, repositoryFixes[item.status]]))}
## Files

A path is shown as \`entry-N\` when it cannot be shown safely; N is its position in the repository's sorted Git tree.
Characters that are not allowed in a path are shown as \`?\`.

${table(['Repository', 'Commit', 'Path', 'Problem', 'How to fix'], report.skipped.map(item => [
    item.repository, item.commit.slice(0, 12), item.link ? `[${item.path}](${item.link})` : item.path, item.problem, item.fix]))}`;
}

function saveSkippedReport(root, audience, report, env) {
  const file = skippedReportPath(audience);
  const repositories = report.excluded.filter(item => repositoryFixes[item.status]).length;
  if (!report.skipped.length && !report.blocked.length && !repositories && optionalRead(root, file) === null) return;
  const markdown = skippedMarkdown(audience, report);
  console.log(`Skipped ${report.skipped.length} source files and ${repositories} repositories`
    + `${report.blocked.length ? `; ${report.blocked.length} items blocked intake` : ''}. Details: ${file}`);
  if (env.GITHUB_STEP_SUMMARY) fs.appendFileSync(env.GITHUB_STEP_SUMMARY, `${markdown.replace(/^# /, '## ')}\n`);
  if (optionalRead(root, file) === markdown) return;
  write(root, file, markdown);
  commitState(root, [file], `Record skipped ${audience} source items`);
}

export function seedReviewCopies(root, result) {
  const copied = [];
  for (const update of result.proposal.payload.updates) {
    const original = optionalRead(root, update.path);
    if (original === null) continue;
    // The persistent copy is the published file byte for byte, not a pending rewrite.
    if (optionalRead(root, update.draft_path) !== original) {
      write(root, update.draft_path, original);
      copied.push(update.draft_path);
    }
  }
  return copied;
}

export async function stage(root, audience, env = process.env) {
  const configuration = validateConfiguration(JSON.parse(read(root, configurationPath(audience))), audience);
  const migrate = audience === 'shared' && fs.existsSync(path.join(root, configurationPath(audience, 'migration')))
    && !fs.existsSync(path.join(root, baselinePath(audience, 'migration')));
  if (!configuration.sources.length && !migrate) {
    console.log('No configured sources for this audience; no collection or checkpoint.');
    return;
  }
  if (!env.SOURCE_READ_TOKEN || !env.SOURCE_PUBLICATION_TOKEN) fail('Source-read and publication credentials are required');
  const pending = await paginate(`/repos/${sourceRepository}/pulls`, env.SOURCE_PUBLICATION_TOKEN);
  // Exception PRs never hold back intake; an older open proposal is superseded by a newer draft.
  const openProposals = pending.filter(pr => pr.state === 'open' && pr.head?.repo?.full_name === sourceRepository
    && pr.head?.ref?.startsWith(`knowledge-review/${audience}-`)
    && !pr.head.ref.startsWith(`knowledge-review/${audience}-exception-`));
  const applied = JSON.parse(optionalRead(root, `sources/${audience}/applied-reviews.json`) ?? '{"reviews":[]}');
  if (!Array.isArray(applied.reviews)) fail('Invalid applied review audit');
  // A review that already failed recovery in this run is retried by the next run, never blocking intake.
  const skip = new Set(String(env.KNOWLEDGE_RECOVERY_SKIP ?? '').split(',').filter(Boolean).map(Number));
  const closed = await paginate(`/repos/${sourceRepository}/pulls?state=closed&sort=updated&direction=desc`, env.SOURCE_PUBLICATION_TOKEN);
  const missed = closed.filter(pr => pr.merged_at && pr.base?.ref === 'main'
    && pr.head?.repo?.full_name === sourceRepository && pr.head?.ref?.startsWith(`knowledge-review/${audience}-`)
    && !applied.reviews.some(item => item.pull_request === pr.number && item.head_commit === pr.head.sha)
    && !skip.has(pr.number))
    .sort((a, b) => Date.parse(a.merged_at) - Date.parse(b.merged_at))[0];
  if (missed && env.KNOWLEDGE_SKIP_RECOVERY !== '1') {
    console.log(`Recovering merged Markdown review ${missed.number} automatically.`);
    return { recovery_pr: missed.number };
  }
  validateRepository(root);
  let result, skippedCount = 0;
  if (migrate) {
    result = makeMigrationProposal(root, git(root, 'rev-parse', 'HEAD'));
  } else {
    let snapshot;
    try {
      snapshot = await collectSnapshot(configuration, env.SOURCE_READ_TOKEN);
    } catch (error) {
      if (error.report) {
        try { saveSkippedReport(root, audience, { ...error.report, failure: error.message.split('\n')[0].slice(0, 300) }, env); }
        catch (reportError) { console.error(`Could not save ${skippedReportPath(audience)}: ${reportError.message}`); }
      }
      throw error;
    }
    const { inputs, scope, skipped } = snapshot;
    saveSkippedReport(root, audience, snapshot.report, env);
    skippedCount = skipped.length + snapshot.report.excluded.filter(item => repositoryFixes[item.status]).length;
    for (const item of scope?.excluded ?? []) console.log(`${item.repository}: ${item.status} (${item.reason}; ${item.origin})`);
    for (const item of scope?.drift ?? []) console.log(`${item.repository}: ${item.note} (collected automatically from pinned inventory)`);
    const baselineText = optionalRead(root, baselinePath(audience));
    if (baselineText === null && !configuration.sources.some(wholeRepository)) {
      // Activation observes source fingerprints; it does not regenerate or approve existing answers.
      write(root, baselinePath(audience), encode({ schema_version: 1, initial_observation: true,
        published_commit: git(root, 'rev-parse', 'HEAD'), inputs: inputs.map(({ content, ...item }) => item) }));
      commitState(root, [baselinePath(audience)], `Observe initial ${audience} source fingerprints; preserve published answers`);
      console.log('Recorded initial source fingerprints; existing published answers remain the unchanged content baseline.');
      return;
    }
    const baseline = baselineText === null ? { inputs: [] } : JSON.parse(baselineText);
    const unreadable = new Set((scope?.excluded ?? []).filter(item => repositoryFixes[item.status]).map(item => item.repository));
    const lost = baseline.inputs.filter(item => unreadable.has(item.repository)
      || skipped.some(entry => entry.source_key === identity(item)));
    if (lost.length) {
      fail(`Previously collected sources are now unreadable in ${[...new Set(lost.map(item => item.repository))].join(', ')}. `
        + `Fix the items in ${skippedReportPath(audience)} and run intake again; no answer was withdrawn.`);
    }
    const removals = sourceRemovals(root, audience, configuration, scope, baseline.inputs, inputs);
    await validateSourceContinuity(inputs, baseline.inputs, env.SOURCE_READ_TOKEN);
    if (!removals.inputs.length && inputs.every(input => baseline.inputs.some(item => identity(item) === identity(input) && item.sha256 === input.sha256))) {
      console.log('No configured source content changed; no drafting or baseline advance.');
      return;
    }
    const changed = inputs.filter(input => baseline.inputs.find(previous => identity(previous) === identity(input))?.sha256 !== input.sha256);
    const draft = await draftBatches(root, audience, inputs, changed, env);
    result = makeProposal(root, audience, inputs, draft, git(root, 'rev-parse', 'HEAD'), scope);
  }
  if (!result) return;
  validateProjection(root, result.proposal, result.files);
  if (!result.proposal.payload.updates.length) {
    write(root, baselinePath(audience), encode({ schema_version: 1, inputs: result.proposal.payload.inputs,
      ...(result.proposal.payload.scope ? { scope: result.proposal.payload.scope } : {}),
      dispositions: result.proposal.payload.dispositions, unchanged_published_commit: git(root, 'rev-parse', 'HEAD') }));
    commitState(root, [baselinePath(audience)], `Record ${audience} source changes with no answer-content delta`);
    console.log('No answer content changed; preserved published Markdown and recorded validated dispositions without a review gate.');
    return;
  }
  const markdown = reviewMarkdown(root, result);
  const branch = `knowledge-review/${audience}-${result.proposal.proposal_id.slice(0, 20)}`;
  if (openProposals.some(pr => pr.head.ref === branch)) {
    console.log('The identical answer proposal is already open for review; nothing new to stage.');
    return;
  }
  const seeds = seedReviewCopies(root, result);
  if (seeds.length) commitState(root, seeds, `Seed exact published ${audience} answer copies for incremental review`);
  git(root, 'checkout', '-b', branch);
  for (const [file, content] of Object.entries(markdown)) write(root, file, content);
  git(root, 'add', '--', ...Object.keys(markdown));
  git(root, '-c', 'user.name=knowledge-review[bot]', '-c', 'user.email=knowledge-review[bot]@users.noreply.github.com',
    'commit', '-m', `Review changed ${audience} answer content`,
    '-m', 'Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>');
  // Publication identity is used by checkout's persisted credential, never the source-read token.
  git(root, 'push', 'origin', `HEAD:refs/heads/${branch}`);
  const baselineLinks = result.proposal.payload.updates.map(update => `| \`${update.path}\` | ${
    update.before_sha256 === null ? 'New answer' : `[Exact baseline](https://github.com/${sourceRepository}/blob/${result.proposal.payload.base_commit}/${update.path})`
  } | \`${update.sha256}\` |`).join('\n');
  const created = await github(`/repos/${sourceRepository}/pulls`, env.SOURCE_PUBLICATION_TOKEN, { method: 'POST', body: {
    title: `Review ${audience} source answers`, head: branch, base: 'main',
    body: `Review the changed Markdown content only; provenance, content version and stale-base hashes are in its frontmatter. Existing answers are line diffs against byte-identical published copies. Approve the exact latest head as a human with repository write permission, then merge. Promotion, validation, glossary, graph, publication and Hub notification then run automatically without another approval.\n\n${skippedCount ? `Intake skipped ${skippedCount} unreadable source items; see [${skippedReportPath(audience)}](https://github.com/${sourceRepository}/blob/main/${skippedReportPath(audience)}) to fix them.\n\n` : ''}${(result.proposal.payload.scope?.excluded ?? []).map(item => `${item.repository}: ${item.status} (${item.reason}; ${item.origin})`).join('\n')}\n\n| Changed destination | Comparison source | Draft SHA-256 |\n| --- | --- | --- |\n${baselineLinks}`,
  } });
  // The new draft is computed from the same approved baseline, so it contains every older pending change.
  for (const old of openProposals) {
    await github(`/repos/${sourceRepository}/issues/${old.number}/comments`, env.SOURCE_PUBLICATION_TOKEN, { method: 'POST',
      body: { body: `Superseded by #${created?.number}, drafted from newer sources against the same approved baseline.` } });
    await github(`/repos/${sourceRepository}/pulls/${old.number}`, env.SOURCE_PUBLICATION_TOKEN, { method: 'PATCH', body: { state: 'closed' } });
  }
  console.log('Staged schema-validated answer deltas in a review PR; publication baseline unchanged.');
}

function markApplied(root, audience, pr) {
  const file = `sources/${audience}/applied-reviews.json`;
  const value = JSON.parse(optionalRead(root, file) ?? '{"schema_version":1,"reviews":[]}');
  if (!Array.isArray(value.reviews)) fail('Invalid applied review audit');
  if (!value.reviews.some(item => item.pull_request === pr.number && item.head_commit === pr.head.sha)) {
    value.reviews.push({ pull_request: pr.number, head_commit: pr.head.sha });
  }
  write(root, file, encode(value));
  return file;
}

async function validateSourceContinuity(inputs, previous, token) {
  const seen = new Set();
  for (const input of inputs) {
    const before = previous.find(item => identity(item) === identity(input));
    if (!before || before.commit === input.commit) continue;
    const key = `${input.repository}:${before.commit}:${input.commit}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (!sha(before.commit)) fail('Invalid observed source baseline');
    const comparison = await github(`/repos/${input.repository}/compare/${before.commit}...${input.commit}`, token);
    if (!['ahead', 'identical'].includes(comparison.status)) fail('Source history diverged or moved backwards; human input is required');
  }
}

// Only declarative, already-validated compiler inputs may be supplied in an exception.
// No code, workflow, audience boundary, output file or source allow-list is writable here.
const curationPaths = new Set([
  'glossary/retrieval-synonyms.json',
  'knowledge-graph/config/section-assessments.json',
  'knowledge-graph/config/assessment-gap-review.json',
  'knowledge-graph/config/curated-operational.json',
]);

export function exceptionMarkdown(audience, phase, originalPr, baseCommit, message, affected = [], baselines = {}) {
  audienceCheck(audience);
  if (!sha(baseCommit) || !/^[a-z-]{1,60}$/.test(phase)
    || (originalPr !== null && (!Number.isSafeInteger(originalPr) || originalPr < 1))) fail('Invalid exception identity');
  const item = { audience, phase, original_pr: originalPr, base_commit: baseCommit, affected,
    message, curation_baselines: baselines };
  return serialize({ version: 1, review_item: item, review_resolution: null }, `# Review pipeline exception

## What happened

${message}

## Affected answers

${affected.length ? affected.map(file => `- \`${file}\``).join('\n') : 'The configured audience snapshot; no proposed answer or failed checkpoint has been published.'}

## Why it matters

This failure does not block intake, Markdown promotion or any other stage. The affected stage keeps its last good output until it succeeds again.

## Options

- Fix the unavailable dependency or conflicting authoring input, then choose \`retry-original\`.
- Choose \`regenerate\` to prepare fresh incremental Markdown against current approved answers. Changed answers will need content review.
- For a failed notification after publication, choose \`retry-dispatch\` to retry the unchanged complete handoff automatically.
- For a compiler conflict, choose \`apply-curation\` with the exact current hashes and replacement declarative JSON for the allowed authoring inputs recorded above. Missing graph facts require supported evidence, not a status override.

## Human input

Explain the selected correction here. Set the frontmatter \`review_resolution\` to
\`{"action":"retry-original"}\`, \`{"action":"regenerate"}\`, \`{"action":"retry-dispatch"}\`, or
\`{"action":"apply-curation","updates":[{"path":"<allowed authoring path>","sha256":"<exact current hash>","value":{}}]}\`.
Then approve this exact Markdown head and merge. The workflow applies the input and continues automatically.
`);
}

function exceptionDocument(text) {
  const match = text.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/);
  if (!match) fail('Missing exception frontmatter');
  const metadata = {};
  for (const line of match[1].split(/\r?\n/)) {
    const field = line.match(/^([a-z_]+): (.+)$/);
    if (!field || Object.hasOwn(metadata, field[1])) fail('Invalid exception frontmatter');
    try { metadata[field[1]] = JSON.parse(field[2]); } catch { fail('Invalid exception JSON value'); }
  }
  return { metadata, body: match[2] };
}

export function parseException(text, file, audience, requireInput = false) {
  const { metadata, body } = exceptionDocument(text);
  if (!safePath(file) || !new RegExp(`^reviews/${audience}/items/[a-z0-9-]+\\.md$`).test(file)
    || !exact(metadata, ['version', 'review_item', 'review_resolution']) || !Number.isSafeInteger(metadata.version) || metadata.version < 1
    || !exact(metadata.review_item, ['audience', 'phase', 'original_pr', 'base_commit', 'affected', 'message', 'curation_baselines'])
    || metadata.review_item.audience !== audience || !sha(metadata.review_item.base_commit)
    || !/^[a-z-]{1,60}$/.test(metadata.review_item.phase)
    || (metadata.review_item.original_pr !== null && (!Number.isSafeInteger(metadata.review_item.original_pr) || metadata.review_item.original_pr < 1))
    || !Array.isArray(metadata.review_item.affected) || metadata.review_item.affected.some(target => !destination(target, audience))
    || typeof metadata.review_item.message !== 'string'
    || !metadata.review_item.curation_baselines || Array.isArray(metadata.review_item.curation_baselines)
    || Object.entries(metadata.review_item.curation_baselines).some(([target, value]) => !curationPaths.has(target) || !digest(value))
    || !['## What happened', '## Affected answers', '## Why it matters', '## Options', '## Human input'].every(heading => body.includes(heading))) fail('Invalid or unsafe exception review item');
  const screenedMetadata = structuredClone(metadata);
  screenedMetadata.review_item.curation_baselines = {};
  for (const update of screenedMetadata.review_resolution?.updates ?? []) delete update.sha256;
  const screened = serialize(screenedMetadata, body);
  if (sanitize(screened, { maxBytes: 512_000 }) !== screened) fail('Unsafe exception content');
  const input = metadata.review_resolution;
  if (input === null && !requireInput) return { ...metadata.review_item, input, file, text };
  if (!input || !['retry-original', 'regenerate', 'retry-dispatch', 'apply-curation'].includes(input.action)
    || !exact(input, input.action === 'apply-curation' ? ['action', 'updates'] : ['action'])) fail('Explicit supported human input is required');
  if (!['regenerate', 'retry-dispatch'].includes(input.action) && metadata.review_item.original_pr === null) fail('Initial intake exception requires regeneration after correction');
  if (input.action === 'retry-dispatch' && !['workflow', 'dispatch'].includes(metadata.review_item.phase)) fail('Dispatch retry requires a notification/workflow exception');
  if (input.action === 'apply-curation') {
    if (!Array.isArray(input.updates) || !input.updates.length || input.updates.length > 10
      || new Set(input.updates.map(update => update.path)).size !== input.updates.length) fail('Invalid curation correction inventory');
    for (const update of input.updates) {
      if (!exact(update, ['path', 'sha256', 'value']) || !curationPaths.has(update.path)
        || !digest(update.sha256) || metadata.review_item.curation_baselines[update.path] !== update.sha256
        || !update.value || typeof update.value !== 'object' || Array.isArray(update.value)) fail('Invalid or stale declarative curation input');
      if (update.path === 'glossary/retrieval-synonyms.json'
        && (update.value.version !== 1 || encode(update.value.groups) !== encode([]))) fail('Glossary corrections must preserve the scoped version-1 contract');
    }
  }
  return { ...metadata.review_item, input, file, text };
}

async function resolveException(root, audience, reviewed, env, trail) {
  const item = reviewed.exception;
  git(root, 'merge-base', '--is-ancestor', item.base_commit, 'HEAD');
  if (['regenerate', 'retry-dispatch'].includes(item.input.action)) {
    const ancestors = item.input.action === 'regenerate'
      ? await exceptionAncestors(root, audience, item.original_pr, env, trail) : [];
    const state = exceptionState(optionalRead(root, exceptionStatePath(audience)));
    const pendingAncestors = ancestors.filter(prior => state.items.some(entry =>
      entry.review_pr === prior.pr.number && !entry.resolved));
    if (pendingAncestors.some(prior => prior.exception.input !== null)) {
      fail('An earlier approved exception action is unresolved; resolve it before regenerating');
    }
    if (item.input.action === 'retry-dispatch') manifest(root, { check: true });
    write(root, item.file, frontmatter(item.text, { review_status: 'approved', verification_status: 'verified',
      reviewed_by: reviewed.attribution.login, reviewed_at: reviewed.attribution.submitted_at }));
    if (item.original_pr !== null) {
      const superseded = await github(`/repos/${sourceRepository}/pulls/${item.original_pr}`, env.SOURCE_PUBLICATION_TOKEN);
      if (superseded.head?.repo?.full_name !== sourceRepository || !sha(superseded.head?.sha)) fail('Invalid superseded proposal identity');
      markApplied(root, audience, superseded);
    }
    const resolvedFiles = [];
    // A human-approved regeneration supersedes only inputless failures on this exact PR ancestry.
    for (const prior of pendingAncestors) {
      write(root, prior.exception.file, frontmatter(prior.exception.text, { review_status: 'approved',
        verification_status: 'verified', reviewed_by: reviewed.attribution.login, reviewed_at: reviewed.attribution.submitted_at }));
      markApplied(root, audience, prior.pr);
      resolveExceptionState(root, audience, prior.pr.number);
      resolvedFiles.push(prior.exception.file);
    }
    const appliedFile = markApplied(root, audience, reviewed.pr);
    resolveExceptionState(root, audience, reviewed.pr.number);
    commitState(root, [...new Set([item.file, ...resolvedFiles, appliedFile, exceptionStatePath(audience)])],
      'Apply approved exception input: regenerate changed answer review');
    if (item.input.action === 'retry-dispatch') return { retry_dispatch: true };
    if (env.AZURE_OPENAI_ACCESS_TOKEN || env.AZURE_OPENAI_API_KEY) {
      await stage(root, audience, env);
    } else {
      // The keyless promotion job cannot draft; the Azure-enabled Hub stage job collects from current baselines.
      await github(`/repos/${hubRepository}/actions/workflows/knowledge-review-${audience}.yml/dispatches`,
        env.SOURCE_PUBLICATION_TOKEN, { method: 'POST', body: { ref: 'main', inputs: { mode: 'stage' } } });
      console.log('Dispatched Hub collection and drafting against current approved baselines.');
    }
    return { staged: true };
  }
  if (String(item.original_pr) === String(reviewed.pr.number)) fail('Exception cannot retry itself');
  for (const update of item.input.updates ?? []) {
    if (hash(read(root, update.path)) !== update.sha256) fail('Stale curation baseline; regenerate the exception');
  }
  // Input on this exception supplies the missing input of earlier exceptions that were merged without one.
  const inputless = [];
  let target = item.original_pr;
  for (let prior; (prior = await inputlessException(root, audience, target, env, [...trail, ...inputless.map(entry => entry.pr.number)]));) {
    inputless.push(prior);
    target = prior.exception.original_pr;
  }
  // Markdown publishes independently; an already-published original is not promoted again.
  const published = JSON.parse(optionalRead(root, `sources/${audience}/applied-reviews.json`) ?? '{"reviews":[]}');
  if (!published.reviews?.some(entry => entry.pull_request === target)) {
    await promote(root, audience, String(target), env, [...trail, ...inputless.map(entry => entry.pr.number)]);
  }
  for (const update of item.input.updates ?? []) {
    write(root, update.path, encode(update.value));
  }
  const audit = JSON.parse(read(root, 'publication/review.json'));
  audit.proposal_id = hash(encode({ original: audit.proposal_id, exception_head: reviewed.pr.head.sha }));
  audit.review = { pull_request: reviewed.pr.number, head_commit: reviewed.pr.head.sha };
  audit.approval = reviewed.attribution;
  write(root, 'publication/review.json', encode(audit));
  for (const resolved of [...inputless.map(entry => entry.exception), item]) {
    write(root, resolved.file, frontmatter(resolved.text, { review_status: 'approved', verification_status: 'verified',
      reviewed_by: reviewed.attribution.login, reviewed_at: reviewed.attribution.submitted_at }));
  }
  for (const entry of inputless) {
    markApplied(root, audience, entry.pr);
    resolveExceptionState(root, audience, entry.pr.number);
  }
  markApplied(root, audience, reviewed.pr);
  resolveExceptionState(root, audience, reviewed.pr.number);
  console.log('Applied approved human exception input; continuing ordinary compilation and publication.');
}

async function inputlessException(root, audience, number, env, trail) {
  if (number === null || !exceptionState(optionalRead(root, exceptionStatePath(audience))).items
    .some(entry => !entry.resolved && entry.review_pr === number)) return null;
  if (trail.includes(number) || trail.length >= 10) fail('Cyclic or excessive exception retry chain');
  const prior = await approvedProposal(root, audience, String(number), env.SOURCE_PUBLICATION_TOKEN, false);
  if (!prior.exception || prior.exception.input !== null) return null;
  if (prior.exception.original_pr === null) fail('Initial intake exception requires regeneration after correction');
  git(root, 'merge-base', '--is-ancestor', prior.exception.base_commit, 'HEAD');
  return prior;
}

async function exceptionAncestors(root, audience, number, env, trail) {
  if (number === null) return [];
  if (trail.includes(number) || trail.length >= 10) fail('Cyclic or excessive exception retry chain');
  const token = env.SOURCE_PUBLICATION_TOKEN;
  const entries = exceptionState(optionalRead(root, exceptionStatePath(audience))).items
    .filter(entry => entry.review_pr === number);
  const prefix = `/repos/${sourceRepository}/pulls/${number}`;
  const sourcePr = await github(prefix, token);
  const changes = await paginate(`${prefix}/files`, token);
  const exceptionFiles = changes.filter(change => /^reviews\/(?:shared|admin)\/items\/.+\.md$/.test(change.filename ?? ''));
  if (!exceptionFiles.length) {
    if (entries.length || !changes.length || changes.some(change => !safePath(change.filename)
      || !change.filename.endsWith('.md')
      || !(change.filename.startsWith(`reviews/${audience}/drafts/`)
        || change.filename.startsWith(`reviews/${audience}/migrations/`)))) {
      fail('Missing or ambiguous exception ancestry');
    }
    const attribution = verifyApproval(sourcePr, await paginate(`${prefix}/reviews`, token),
      changes.map(change => change.filename), audience, sourcePr.head?.sha);
    const permission = await github(`/repos/${sourceRepository}/collaborators/${encodeURIComponent(attribution.login)}/permission`, token);
    if (!['admin', 'maintain', 'write'].includes(permission.permission)) fail('Reviewer must have repository write/maintain/admin permission');
    git(root, 'merge-base', '--is-ancestor', sourcePr.merge_commit_sha, 'HEAD');
    return [];
  }
  if (entries.length !== 1 || changes.length !== 1 || exceptionFiles.length !== 1
    || !exceptionFiles[0].filename.startsWith(`reviews/${audience}/items/`)) {
    fail('Missing or ambiguous exception ancestry');
  }
  const prior = await approvedProposal(root, audience, String(number), token, false);
  if (!prior.exception || prior.exception.original_pr !== entries[0].original_pr
    || prior.exception.file !== exceptionFiles[0].filename) fail('Exception ancestry does not match published state');
  return [...await exceptionAncestors(root, audience, prior.exception.original_pr, env, [...trail, number]), prior];
}

function exceptionState(text) {
  const value = JSON.parse(text ?? '{"schema_version":1,"items":[]}');
  if (!exact(value, ['schema_version', 'items']) || value.schema_version !== 1 || !Array.isArray(value.items)
    || value.items.some(item => !exact(item, ['id', 'review_pr', 'original_pr', 'resolved',
      ...(Object.hasOwn(item ?? {}, 'phase') ? ['phase'] : [])])
      || (Object.hasOwn(item, 'phase') && !/^[a-z-]{1,60}$/.test(item.phase ?? ''))
      || !/^[a-f0-9]{20}$/.test(item.id) || !Number.isSafeInteger(item.review_pr) || item.review_pr < 1
      || (item.original_pr !== null && (!Number.isSafeInteger(item.original_pr) || item.original_pr < 1))
      || typeof item.resolved !== 'boolean')) fail('Invalid exception publication state');
  return value;
}

function resolveExceptionState(root, audience, reviewPr) {
  const value = exceptionState(optionalRead(root, exceptionStatePath(audience)));
  const item = value.items.find(item => item.review_pr === reviewPr && !item.resolved);
  if (!item) fail('Exception no longer matches the pending issue; refresh human review');
  item.resolved = true;
  write(root, exceptionStatePath(audience), encode(value));
}

// Source-repository workflows only check and forward; the Hub workflows stage, promote and notify.
const failureWorkflows = {
  'Review shared sources': { audience: 'shared', repository: sourceRepository },
  'Review admin sources': { audience: 'admin', repository: sourceRepository },
  'Review shared knowledge sources': { audience: 'shared', repository: hubRepository },
  'Review admin knowledge sources': { audience: 'admin', repository: hubRepository },
};

export async function recordWorkflowFailure(root, env = process.env) {
  const failed = Object.hasOwn(failureWorkflows, env.FAILED_WORKFLOW) ? failureWorkflows[env.FAILED_WORKFLOW] : null;
  const audience = failed?.audience;
  if (!audience || !/^[1-9]\d*$/.test(env.FAILED_RUN_ID ?? '')
    || !['failure', 'cancelled', 'timed_out', 'action_required', 'startup_failure', 'neutral', 'stale'].includes(env.FAILED_CONCLUSION)) {
    fail('Invalid failed audience workflow identity');
  }
  const message = `Knowledge pipeline run ${env.FAILED_RUN_ID} ended with ${env.FAILED_CONCLUSION}. `
    + 'This includes collection, conversion, validation, promotion, glossary, graph, publication and dispatch, '
    + 'ontology/model/schema/SHACL/reference validation, as well as checkout, setup, timeout or cancellation failures. '
    + `Inspect https://github.com/${failed.repository}/actions/runs/${env.FAILED_RUN_ID}, `
    + 'correct the failing dependency or input, and provide human input on this Markdown. '
    + 'Other stages keep running; this record does not block them.';
  return recordException(root, audience, 'workflow', null, message, env);
}

export async function recordException(root, audience, phase, originalPr, message, env = process.env) {
  audienceCheck(audience);
  if (!env.SOURCE_PUBLICATION_TOKEN) fail('Cannot create exception review: publication credential unavailable');
  const prefix = `/repos/${sourceRepository}`;
  const pending = await paginate(`${prefix}/pulls`, env.SOURCE_PUBLICATION_TOKEN);
  const localIssues = exceptionState(optionalRead(root, exceptionStatePath(audience)));
  // One open record per derived stage (and per proposal for content failures); repeats reuse it.
  const blocking = pending.find(pr => localIssues.items.some(item => !item.resolved && item.review_pr === pr.number
    && (phase === 'workflow' || (derivedPhases.has(phase) ? item.phase === phase : item.original_pr === originalPr))));
  if (blocking) {
    console.error(`Existing exception review PR ${blocking.number} already records this ${phase} failure; preserved its edits.`);
    return blocking.number;
  }
  const id = hash(encode({ audience, phase, originalPr })).slice(0, 20);
  const branchPrefix = `knowledge-review/${audience}-exception-${id}-`;
  const existing = pending.find(pr => pr.state === 'open' && pr.head?.ref?.startsWith(branchPrefix));
  if (existing) {
    console.error(`Existing exception review PR ${existing.number} requires human input; preserved its edits.`);
    return existing.number;
  }
  const base = await github(`${prefix}/git/ref/heads/main`, env.SOURCE_PUBLICATION_TOKEN);
  if (!sha(base.object?.sha)) fail('Cannot resolve trusted main for exception review');
  const baselines = {};
  const affected = [];
  if (originalPr) {
    const changes = await paginate(`${prefix}/pulls/${originalPr}/files`, env.SOURCE_PUBLICATION_TOKEN);
    for (const change of changes) {
      const target = change.filename?.replace(`reviews/${audience}/drafts/`, '');
      if (destination(target, audience)) affected.push(target);
    }
  }
  const file = `reviews/${audience}/items/exception-${id}.md`;
  const branch = `${branchPrefix}${base.object.sha.slice(0, 12)}`;
  await github(`${prefix}/git/refs`, env.SOURCE_PUBLICATION_TOKEN, { method: 'POST',
    body: { ref: `refs/heads/${branch}`, sha: base.object.sha } });
  let previous;
  const tree = await github(`${prefix}/git/trees/${base.object.sha}?recursive=1`, env.SOURCE_PUBLICATION_TOKEN);
  if (tree.truncated !== false || !Array.isArray(tree.tree)) fail('Cannot verify exception review tree');
  for (const target of curationPaths) if (tree.tree.some(entry => entry.path === target)) {
    // Curation files are only hashed, never drafted, and some exceed the 512 KB model-input limit.
    baselines[target] = hash(await remoteText(sourceRepository, target, base.object.sha, env.SOURCE_PUBLICATION_TOKEN,
      fetch, false, 1_000_000));
  }
  const stateFile = exceptionStatePath(audience);
  const stateEntry = tree.tree.find(entry => entry.path === stateFile);
  const state = exceptionState(stateEntry
    ? await remoteText(sourceRepository, stateFile, base.object.sha, env.SOURCE_PUBLICATION_TOKEN) : null);
  previous = tree.tree.find(entry => entry.path === file);
  let text = exceptionMarkdown(audience, phase, originalPr, base.object.sha, message, affected, baselines);
  if (previous) {
    const old = exceptionDocument(await remoteText(sourceRepository, file, base.object.sha, env.SOURCE_PUBLICATION_TOKEN));
    if (!Number.isSafeInteger(old.metadata.version) || old.metadata.version < 1) fail('Invalid prior exception content version');
    text = frontmatter(text, { version: old.metadata.version + 1 });
  }
  await github(`${prefix}/contents/${file}`, env.SOURCE_PUBLICATION_TOKEN, { method: 'PUT', body: {
    branch, message: `Review ${audience} pipeline exception\n\nCo-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>`,
    content: Buffer.from(text).toString('base64'), ...(previous ? { sha: previous.sha } : {}),
  } });
  const pr = await github(`${prefix}/pulls`, env.SOURCE_PUBLICATION_TOKEN, { method: 'POST', body: {
    head: branch, base: 'main', title: `Resolve ${audience} knowledge ${phase} exception`,
    body: `Only the exception Markdown requires human input. Correct the documented issue, fill in review_resolution, approve the exact head and merge; the pipeline then applies the input and continues automatically.`,
  } });
  state.items = state.items.filter(item => item.id !== id
    && (item.resolved || item.original_pr !== originalPr || pending.some(pr => pr.number === item.review_pr)));
  state.items.push({ id, review_pr: pr.number, original_pr: originalPr, resolved: false, phase });
  await github(`${prefix}/contents/${stateFile}`, env.SOURCE_PUBLICATION_TOKEN, { method: 'PUT', body: {
    branch: 'main', message: `Record ${phase} exception ${pr.number}; other stages continue\n\nCo-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>`,
    content: Buffer.from(encode(state)).toString('base64'), ...(stateEntry ? { sha: stateEntry.sha } : {}),
  } });
  console.error(`Created exception review PR ${pr.number}; the failed stage kept its last good output.`);
  return pr.number;
}

export async function verifyCollectedEvidence(configuration, inputs, token, fetcher = fetch, scope = null, reader = defaultReader(fetcher)) {
  const expanded = scopedConfiguration(configuration, scope, inputs);
  validateInputInventory(expanded, inputs);
  const commits = new Map(inputs.map(input => [input.repository, input.commit]));
  if (inputs.some(input => input.commit !== commits.get(input.repository))) fail('Mixed source snapshots');
  const resolution = scope ? await resolveSources(configuration, token, fetcher, scope) : { configuration: expanded };
  const { inputs: collected, unreadable } = await collectConfiguredInputs(resolution.configuration, token, fetcher, commits, reader);
  if (unreadable.length || collected.length !== inputs.length || collected.some(input => !inputs.some(item =>
    item.ref === input.ref && item.type === input.type && sameEvidence(input, item)))) {
    fail('Reviewed inventory differs from complete immutable tracked-file inventory');
  }
  return collected;
}

export async function promote(root, audience, number, env = process.env, trail = []) {
  if (!env.SOURCE_PUBLICATION_TOKEN || !env.SOURCE_READ_TOKEN) fail('Publication and source-read credentials required');
  if (trail.includes(Number(number)) || trail.length >= 10) fail('Cyclic or excessive exception retry chain');
  const chain = [...trail, Number(number)];
  const reviewed = await approvedProposal(root, audience, number, env.SOURCE_PUBLICATION_TOKEN);
  if (reviewed.exception) return resolveException(root, audience, reviewed, env, chain);
  const { proposal, files, attribution, pr } = reviewed;
  if (proposal.payload.intake === 'upstream') {
    const configuration = validateConfiguration(JSON.parse(read(root, configurationPath(audience))), audience);
    const collected = await verifyCollectedEvidence(configuration, proposal.payload.inputs, env.SOURCE_READ_TOKEN, fetch, proposal.payload.scope);
    for (const input of collected) rejectSourceWrapper(Object.values(files), input.content);
  } else {
    for (const input of proposal.payload.inputs) {
      await regularPaths(input.repository, input.commit, [input.path], env.SOURCE_PUBLICATION_TOKEN);
      const original = await remoteText(input.repository, input.path, input.commit, env.SOURCE_PUBLICATION_TOKEN);
      sanitize(original, { maxBytes: 512_000 });
      if (hash(original) !== input.sha256) fail('Reviewed evidence hash differs from immutable source');
    }
  }
  for (const update of proposal.payload.updates) {
    if (update.remove) {
      fs.unlinkSync(path.join(root, update.path));
      if (fs.existsSync(path.join(root, update.draft_path))) fs.unlinkSync(path.join(root, update.draft_path));
      continue;
    }
    const approved = approvedText(files[update.draft_path], attribution);
    write(root, update.path, approved);
    write(root, update.draft_path, approved);
  }
  updateMigrationPublication(root, proposal.payload.updates.filter(update => !update.remove).map(update => update.path));
  write(root, baselinePath(audience, proposal.payload.intake), encode({ schema_version: 1, proposal_id: proposal.proposal_id,
    ...(proposal.payload.scope ? { scope: proposal.payload.scope } : {}),
    inputs: proposal.payload.inputs, review: { pull_request: pr.number, head_commit: pr.head.sha } }));
  write(root, 'publication/review.json', encode({ schema_version: 1, audience, proposal_id: proposal.proposal_id,
    review: { pull_request: pr.number, head_commit: pr.head.sha }, approval: attribution }));
  markApplied(root, audience, pr);
  validateRepository(root);
  console.log('Prepared human-approved promotion; commit before compiling graph/glossary.');
}

export function manifest(root, { check = false } = {}) {
  const review = JSON.parse(read(root, 'publication/review.json'));
  if (!exact(review, ['schema_version', 'audience', 'proposal_id', 'review', 'approval']) || review.schema_version !== 1
    || !digest(review.proposal_id) || !exact(review.review, ['pull_request', 'head_commit'])
    || !Number.isSafeInteger(review.review.pull_request) || review.review.pull_request < 1
    || !sha(review.review.head_commit)) fail('Invalid approved publication audit');
  audienceCheck(review.audience);
  const report = validateRepository(root);
  const graph = JSON.parse(read(root, 'knowledge-graph/manifest.json'));
  if (graph.status !== 'complete' || graph.source_extraction_status !== 'complete'
    || graph.source_markdown_verification_status !== 'verified' || graph.review_status !== 'approved'
    || graph.verification_status !== 'verified' || encode(graph.publication_review) !== encode(review)
    || graph.reviewed_by !== review.approval?.login || graph.reviewed_at !== review.approval?.submitted_at) {
    fail('Incomplete or unattributed graph requires human exception review before publication');
  }
  // The graph may be compiled at any later commit, as long as published Markdown and its audit are unchanged since.
  const snapshot = graph.source_snapshot_commit;
  if (!sha(snapshot)) fail('Graph provenance does not match published Markdown');
  try {
    git(root, 'merge-base', '--is-ancestor', snapshot, 'HEAD');
    git(root, 'diff', '--quiet', snapshot, 'HEAD', '--', 'guides', 'reference', 'known-errors', 'admin', 'publication/review.json');
  } catch { fail('Graph provenance does not match published Markdown'); }
  if (git(root, 'status', '--porcelain', '--', 'guides', 'reference', 'known-errors', 'admin')) fail('Compile only from committed Markdown');
  const glossaryFiles = ['retrieval-synonyms.json', 'glossary-source-coverage.json', 'review-candidates.json', 'evaluation-status.json']
    .map(file => `glossary/${file}`);
  if (!Array.isArray(graph.outputs) || graph.outputs.some(file => !safePath(file))) fail('Invalid graph output inventory');
  const paths = [...report.documents.filter(doc => doc.eligible || doc.admin_eligible).map(doc => doc.path),
    'knowledge-graph/manifest.json', ...graph.outputs.map(file => `knowledge-graph/${file}`), ...glossaryFiles];
  if (new Set(paths).size !== paths.length) fail('Duplicate publication inventory');
  const value = { schema_version: 1, source_repository: sourceRepository, audience: review.audience,
    proposal_id: review.proposal_id, review: review.review,
    files: paths.sort().map(file => ({ path: file, sha256: hash(fs.readFileSync(path.join(root, file))) })) };
  if (check) {
    if (read(root, 'publication/manifest.json') !== encode(value)) fail('Publication manifest is not the complete current compiled snapshot');
  } else write(root, 'publication/manifest.json', encode(value));
  return value;
}

export async function authorizePublication(root, env = process.env) {
  const audit = JSON.parse(read(root, 'publication/review.json'));
  const prefix = `/repos/${sourceRepository}/pulls/${audit.review.pull_request}`;
  const pr = await github(prefix, env.SOURCE_PUBLICATION_TOKEN);
  const reviews = await paginate(`${prefix}/reviews`, env.SOURCE_PUBLICATION_TOKEN);
  const changes = await paginate(`${prefix}/files`, env.SOURCE_PUBLICATION_TOKEN);
  const approval = verifyApproval(pr, reviews, changes.map(file => file.filename), audit.audience, audit.review.head_commit);
  if (encode(approval) !== encode(audit.approval)) fail('Human approval changed during compilation; regenerate publication');
  const permission = await github(`/repos/${sourceRepository}/collaborators/${encodeURIComponent(approval.login)}/permission`, env.SOURCE_PUBLICATION_TOKEN);
  if (!['admin', 'maintain', 'write'].includes(permission.permission)) fail('Reviewer no longer has publication review permission');
}

export async function dispatch(root, env = process.env) {
  const commit = git(root, 'rev-parse', 'HEAD');
  if (git(root, 'status', '--porcelain')) fail('Dispatch requires a clean immutable publication checkout');
  const text = read(root, 'publication/manifest.json');
  manifest(root, { check: true });
  const value = JSON.parse(text);
  for (const file of value.files) if (hash(fs.readFileSync(path.join(root, file.path))) !== file.sha256) fail('Publication artifact hash mismatch');
  await github(`/repos/${hubRepository}/actions/workflows/knowledge-adopt.yml/dispatches`,
    env.HUB_DISPATCH_TOKEN, { method: 'POST', body: { ref: 'main', inputs: {
      schema_version: '1', source_commit: commit, manifest_sha256: hash(text),
    } } });
  console.log('Hub adoption dispatch accepted; imports/builds/deployment are not verified here.');
}

async function main() {
  const [mode, audience, number] = process.argv.slice(2);
  const root = process.cwd();
  if (mode === 'workflow-failure') return recordWorkflowFailure(root);
  if (mode === 'manifest') return manifest(root);
  if (mode === 'dispatch') return dispatch(root);
  if (mode === 'authorize') return authorizePublication(root);
  if (mode === 'registry') {
    // Registry synchronization is its own stage; collection continues with the last committed registry.
    return refreshSourceRegistry(root).catch(error => {
      const message = error instanceof PipelineError || error instanceof RefreshError ? error.message : 'Registry synchronization failed';
      console.warn(`::warning::${message}; collection continues with the last committed registry.`);
    });
  }
  audienceCheck(audience);
  if (mode === 'exception') {
    const phase = process.argv[5] ?? 'validation';
    const reportFile = process.env.KNOWLEDGE_REVIEW_REPORT;
    let message = `The ${phase} step could not produce a valid, complete publication. Inspect its validation result and correct the authoring input before retrying.`;
    if (reportFile && fs.existsSync(reportFile)) {
      const report = JSON.parse(fs.readFileSync(reportFile, 'utf8'));
      if (typeof report.summary !== 'string' || report.summary.length > 8000 || sanitize(report.summary) !== report.summary) fail('Unsafe exception summary');
      message = report.summary;
    }
    return recordException(root, audience, phase, /^[1-9]\d*$/.test(number ?? '') ? Number(number) : null, message);
  }
  if (mode === 'stage') {
    const result = await stage(root, audience);
    if (result?.recovery_pr && process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `recovery_pr=${result.recovery_pr}\n`);
    return result;
  }
  if (mode === 'check') return checkReview(root, audience, number, process.env.REVIEW_READ_TOKEN);
  if (mode === 'promote') {
    const result = await promote(root, audience, number);
    if (result?.staged && process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, 'stage_only=true\n');
    if (result?.retry_dispatch && process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, 'retry_dispatch=true\n');
    return result;
  }
  fail('Usage: reviewed-sources.mjs stage|check|promote shared|admin [PR] or manifest|dispatch');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    // Error messages are static/local diagnostics: never emit remote bodies or source/model text.
    const message = error instanceof PipelineError || error instanceof RefreshError ? error.message
      : 'Schema, evidence, approval, file access or remote validation failed. No source text or remote response is logged; inspect configuration and local validation diagnostics.';
    console.error(`Reviewed-source pipeline failed: ${message}`);
    if (process.env.KNOWLEDGE_REVIEW_REPORT && !['check', 'exception'].includes(process.argv[2])) {
      try { fs.writeFileSync(process.env.KNOWLEDGE_REVIEW_REPORT, encode({ summary: message })); }
      catch { console.error('Could not persist the bounded exception explanation; the workflow still fails.'); }
    }
    process.exitCode = 1;
  });
}
