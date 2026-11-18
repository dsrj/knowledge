import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { archivalNotice, historicalNotice, withNotice, validateDocument, publicationContentHash } from './validate.mjs';
import { splitKnownErrors } from './split-known-errors.mjs';

const source = process.argv[2];
const commit = process.argv[3];
const restoreHistory = process.argv[4] === '--restore-history';
if (!source || !/^[0-9a-f]{40}$/.test(commit ?? '')) {
  throw new Error('Usage: node scripts/migrate.mjs <legacy-directory> <full-source-SHA> [--restore-history]');
}
const repository = 'almbrand/landingzone-service-catalog-code';
const prefix = 'cloudops-hub-knowledge-source/';
const adminReferences = new Set(['azure-enterprise-framework.md', 'cloudops-platform-repository-hierarchy.md']);
const root = path.dirname(source);
const git = (...args) => execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' });
const files = git('ls-tree', '-r', '--name-only', commit, '--', prefix)
  .trim().split('\n').filter(Boolean).map(file => file.slice(prefix.length));
if (!files.length || files.some(file => !/^[a-zA-Z0-9_-]+\.md$/.test(file))) {
  throw new Error('Expected only flat Markdown legacy source files');
}
const historical = file => /failed-run-ledger|workspace-output-evidence/.test(file);
const reference = /enterprise-framework|repository-hierarchy|capabilities|role-assignments/;
function destination(file) {
  if (file === 'AGENTS.md') return 'assets/legacy-agent-instructions.md';
  if (file === '_SCHEMA.md') return 'assets/legacy-authoring-schema.md';
  if (historical(file)) return `run-records/historical/${file}`;
  if (file === 'service-catalog-known-errors.md' || file === 'github-runners-troubleshooting.md') return `known-errors/${file}`;
  if (adminReferences.has(file)) return `admin/reference/${file}`;
  return `${reference.test(file) ? 'reference' : 'guides'}/${file}`;
}
const mapping = new Map(files.map(file => [file, destination(file)]));
const priorMap = restoreHistory ? JSON.parse(fs.readFileSync('assets/migration-map.json', 'utf8')) : null;
if (priorMap && (priorMap.source_commit !== commit || priorMap.source_repository !== repository
  || priorMap.entries.length !== files.length)) throw new Error('Restore requires the original complete migration inventory');
for (const dest of mapping.values()) {
  if (!restoreHistory && fs.existsSync(dest)) throw new Error(`Refusing to overwrite ${dest}`);
  if (restoreHistory) {
    const prior = priorMap.entries.find(entry => entry.destination_path === dest);
    if (!prior || !fs.existsSync(dest)
      || crypto.createHash('sha256').update(fs.readFileSync(dest)).digest('hex') !== prior.migration_sha256) {
      throw new Error(`Refusing to overwrite changed or missing migration document: ${dest}`);
    }
  }
}
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const blob = file => `https://github.com/${repository}/blob/${commit}/${file}`;
function rewrite(text, file, dest) {
  return text.replace(/(\]\()([^)\s]+)(\))/g, (all, before, href, after) => {
    if (/^(?:[a-z][a-z0-9+.-]*:|#)/i.test(href)) return all;
    const [target, anchor] = href.split('#');
    const resolved = path.posix.normalize(path.posix.join(prefix, target));
    const localName = resolved.startsWith(prefix) ? resolved.slice(prefix.length) : null;
    const mapped = mapping.get(localName);
    const knownError = localName === 'service-catalog-known-errors.md' && /^ke-\d+$/i.test(anchor ?? '');
    const url = knownError
      ? path.posix.relative(path.posix.dirname(dest), `known-errors/service-catalog-${anchor.toLowerCase()}.md`)
      : mapped
      ? path.posix.relative(path.posix.dirname(dest), mapped)
      : blob(resolved);
    return `${before}${url}${anchor ? `#${anchor}` : ''}${after}`;
  });
}
const entries = [];
const derivedDocuments = [];
for (const file of files) {
  const raw = execFileSync('git', ['-C', root, 'show', `${commit}:${prefix}${file}`], { maxBuffer: 8 * 1024 * 1024 });
  const original = raw.toString('utf8').replace(/^\uFEFF/, '');
  const normalized = original.replace(/\r\n/g, '\n');
  const title = normalized.match(/^# (.+)$/m)?.[1];
  if (!title) throw new Error(`Missing title in ${file}`);
  const dest = mapping.get(file);
  const legacy = dest.startsWith('assets/');
  const collection = historical(file);
  const type = legacy ? 'legacy-instructions' : collection ? 'historical-collection'
    : dest.startsWith('known-errors/') ? 'known-error' : /(?:^|\/)reference\//.test(dest) ? 'reference' : 'guide';
  const assistants = dest.startsWith('admin/') ? ['platform-admin']
    : /service-catalog|terraform-plan/.test(file) ? ['service-catalog']
    : /network|gsa|secure-access/.test(file) ? ['landing-zone', 'firewall'] : ['landing-zone'];
  const metadata = {
    schema_version: 1,
    id: file.replace(/\.md$/, '').toLowerCase().replace(/^_/, 'legacy-'),
    title, assistants,
    topics: [collection ? 'historical-evidence' : type === 'known-error' ? 'troubleshooting' : 'cloudops'],
    owner: 'almbrand/cloudfoundation', document_type: type,
    source_repository: repository, source_path: prefix + file, source_commit: commit,
    review_status: 'pending-review', verification_status: 'unverified',
  };
  let body = rewrite(normalized, file, dest);
  if (collection) body = withNotice(body, historicalNotice);
  if (legacy) body = withNotice(body, archivalNotice);
  let output = `---\n${Object.entries(metadata).map(([key, value]) => `${key}: ${JSON.stringify(value)}`).join('\n')}\n---\n${body}`;
  let derived = [];
  if (file === 'service-catalog-known-errors.md') {
    const split = splitKnownErrors(output);
    output = split.indexText;
    derived = split.records;
  }
  validateDocument(output, dest);
  for (const record of derived) {
    if (restoreHistory) {
      const prior = priorMap.derived_documents?.find(item => item.destination_path === record.path);
      if (!prior || !fs.existsSync(record.path)
        || crypto.createHash('sha256').update(fs.readFileSync(record.path)).digest('hex') !== prior.sha256) {
        throw new Error(`Refusing to overwrite changed or missing derived document: ${record.path}`);
      }
    } else if (fs.existsSync(record.path)) {
      throw new Error(`Refusing to overwrite ${record.path}`);
    }
    derivedDocuments.push({
      destination_path: record.path,
      id: record.id,
      source_path: prefix + file,
      sha256: sha256(record.text),
      content_sha256: publicationContentHash(record.text),
    });
  }
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, output);
  for (const record of derived) fs.writeFileSync(record.path, record.text);
  entries.push({
    source_path: prefix + file, destination_path: dest, id: metadata.id,
    handling: collection ? 'historical-content' : legacy ? 'archived-instructions' : 'migrated',
    source_sha256: sha256(raw), migration_sha256: sha256(output),
  });
}
fs.writeFileSync('assets/migration-map.json', JSON.stringify({
  schema_version: 1, source_repository: repository, source_commit: commit,
  original_source_retained: true, entries, derived_documents: derivedDocuments,
}, null, 2) + '\n');
console.log(JSON.stringify({ source_files: files.length, handling: entries.reduce((out, entry) => {
  out[entry.handling] = (out[entry.handling] ?? 0) + 1; return out;
}, {}) }, null, 2));
