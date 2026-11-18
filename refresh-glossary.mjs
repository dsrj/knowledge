import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { isEligible, isPublicationCandidate, parseDocument, questionBodies, questionSections } from './validate.mjs';

export const generatedGlossaryFiles = [
  'glossary/retrieval-synonyms.json',
  'glossary/glossary-source-coverage.json',
  'glossary/review-candidates.json',
  'glossary/evaluation-status.json',
];
const sourceDirectories = ['guides', 'reference', 'known-errors'];
const sourceTypes = { guides: 'guide', reference: 'reference', 'known-errors': 'known-error' };
const assistants = ['landing-zone', 'firewall', 'service-catalog'];
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const encode = value => `${JSON.stringify(value, null, 2)}\n`;
const fold = value => value.toLowerCase();
const sorted = values => [...values].sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
const terms = /^[\p{L}\p{N}_ .:/()?-]+$/u;
const readJson = (root, file) => JSON.parse(fs.readFileSync(path.join(root, file), 'utf8'));

export function approvedGlossaryReview(root, env = process.env, runGit = execFileSync) {
  if (env.KNOWLEDGE_REVIEW_APPROVED !== '1') return null;
  const commit = env.KNOWLEDGE_SOURCE_COMMIT;
  if (!/^[a-f0-9]{40}$/.test(commit ?? '')) throw new Error('Approved glossary requires KNOWLEDGE_SOURCE_COMMIT');
  const git = (...args) => runGit('git', ['-c', 'core.longpaths=true', ...args], { cwd: root });
  git('merge-base', '--is-ancestor', commit, 'HEAD');
  const raw = fs.readFileSync(path.join(root, 'publication/review.json'));
  if (!raw.equals(git('show', `${commit}:publication/review.json`))) throw new Error('Glossary audit differs from pinned publication commit');
  const audit = JSON.parse(raw);
  const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
  if (!exact(audit, ['schema_version', 'audience', 'proposal_id', 'review', 'approval'])
    || audit.schema_version !== 1 || !['shared', 'admin'].includes(audit.audience)
    || !/^[a-f0-9]{64}$/.test(audit.proposal_id ?? '')
    || !exact(audit.review, ['pull_request', 'head_commit'])
    || !Number.isSafeInteger(audit.review.pull_request) || audit.review.pull_request < 1
    || !/^[a-f0-9]{40}$/.test(audit.review.head_commit ?? '')
    || !exact(audit.approval, ['login', 'submitted_at'])
    || !/^[a-z0-9][a-z0-9_-]{0,38}$/i.test(audit.approval.login ?? '')
    || typeof audit.approval.submitted_at !== 'string'
    || !/(?:Z|[+-]\d{2}:\d{2})$/.test(audit.approval.submitted_at)
    || !Number.isFinite(Date.parse(audit.approval.submitted_at))) throw new Error('Invalid human-approved glossary audit');
  return { commit, audit, git };
}

function walk(root, directory) {
  if (fs.lstatSync(path.join(root, directory)).isSymbolicLink()) {
    throw new Error(`Glossary source cannot be a symlink: ${directory}`);
  }
  const files = [];
  for (const entry of fs.readdirSync(path.join(root, directory), { withFileTypes: true })) {
    const file = `${directory}/${entry.name}`;
    if (entry.isSymbolicLink()) throw new Error(`Glossary source cannot be a symlink: ${file}`);
    if (entry.isDirectory()) files.push(...walk(root, file));
    else if (file.endsWith('.md')) files.push(file);
  }
  return sorted(files);
}

function validateGroup(group, label) {
  if (!Array.isArray(group) || group.length < 2 || group.length > 16
    || group.some(term => typeof term !== 'string' || !term.trim()
      || term !== term.trim() || term.length > 100 || !terms.test(term))
    || new Set(group.map(fold)).size !== group.length) {
    throw new Error(`Invalid glossary group: ${label}`);
  }
}

export function validateRuntime(value) {
  if (!value || value.version !== 1 || !Array.isArray(value.groups) || value.groups.length > 200
    || !Array.isArray(value.aliases) || value.aliases.length > 1000
    || !Array.isArray(value.guide_aliases) || value.guide_aliases.length > 1000
    || Object.keys(value).some(key => !['version', 'groups', 'aliases', 'guide_aliases'].includes(key))) {
    throw new Error('Invalid runtime glossary; private review metadata is not allowed');
  }
  if (value.groups.length) throw new Error('Glossary groups must be empty; use explicitly scoped aliases');
  for (const alias of value.aliases) {
    if (!alias || Object.keys(alias).some(key => !['canonical', 'terms', 'scope'].includes(key))
      || !Array.isArray(alias.terms) || !['firewall', 'other-agents'].includes(alias.scope)) {
      throw new Error('Invalid scoped glossary alias; do not imply unsupported per-agent isolation');
    }
    validateGroup([alias.canonical, ...alias.terms], alias.canonical);
  }
  for (const alias of value.guide_aliases) {
    if (!alias || Object.keys(alias).sort().join(',') !== 'canonical,terms' || !Array.isArray(alias.terms)) {
      throw new Error('Invalid source-owned resource alias');
    }
    validateGroup([alias.canonical, ...alias.terms], alias.canonical);
  }
  const sourceOwners = new Map();
  for (const alias of value.guide_aliases) {
    for (const term of [alias.canonical, ...alias.terms]) {
      const owner = sourceOwners.get(fold(term));
      if (owner && owner !== fold(alias.canonical)) throw new Error(`Conflicting source-owned alias: ${term}`);
      sourceOwners.set(fold(term), fold(alias.canonical));
    }
  }
  for (const scope of ['firewall', 'other-agents']) {
    const owners = new Map();
    for (const group of value.aliases
      .filter(alias => alias.scope === scope)
      .map(alias => [alias.canonical, ...alias.terms])) {
      for (const term of group) {
        const owner = owners.get(fold(term));
        if (owner && owner !== fold(group[0])) throw new Error(`Conflicting ${scope} alias: ${term}`);
        owners.set(fold(term), fold(group[0]));
      }
    }
  }
  if (Buffer.byteLength(encode(value)) > 524288) throw new Error('Glossary exceeds the Hub 512 KiB limit');
}

// Sort equivalent collections only for comparison; preserve authored runtime order.
export function runtimeFingerprint(value) {
  const canonicalize = entries => entries.map(([canonical, ...terms]) => ({
    canonical: fold(canonical), terms: sorted(terms.map(fold)),
  }))
    .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b), 'en'));
  return hash(JSON.stringify({
    groups: canonicalize(value.groups),
    aliases: value.aliases.map(alias => ({
      scope: alias.scope, canonical: fold(alias.canonical), terms: sorted(alias.terms.map(fold)),
    })).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b), 'en')),
    guide_aliases: value.guide_aliases.map(alias => ({
      canonical: fold(alias.canonical), terms: sorted(alias.terms.map(fold)),
    })).sort((a, b) => a.canonical.localeCompare(b.canonical, 'en')),
  }));
}

export function sourceFingerprint(documents) {
  return hash(JSON.stringify([...documents].sort((a, b) => a.file.localeCompare(b.file, 'en'))
    .map(doc => [doc.file, doc.source_sha256])));
}

export function glossaryOutputs(root, { env = process.env, runGit = execFileSync } = {}) {
  const publication = approvedGlossaryReview(root, env, runGit);
  const previous = readJson(root, 'glossary/retrieval-synonyms.json');
  validateRuntime(previous);
  const documents = [];
  const questions = [];
  const routes = [];
  const corpus = new Map();
  const aliases = new Map();
  const excluded = [];
  const addTerm = (term, file, kind, scopes) => {
    term = term.replace(/\s+/g, ' ').trim();
    if (!term) return;
    const key = fold(term);
    const record = corpus.get(key) ?? { term, occurrences: new Set(), kinds: new Set(), assistants: new Set() };
    record.occurrences.add(file);
    record.kinds.add(kind);
    scopes.forEach(scope => record.assistants.add(scope));
    corpus.set(key, record);
  };
  for (const directory of sourceDirectories) {
    for (const file of walk(root, directory)) {
      const raw = fs.readFileSync(path.join(root, file), 'utf8').replace(/\r\n/g, '\n');
      const { metadata: m, body } = parseDocument(raw);
      if (!Array.isArray(m.assistants) || m.assistants.length === 0
        || m.assistants.some(scope => !assistants.includes(scope))) {
        throw new Error(`Non-public assistant scope in glossary source: ${file}`);
      }
      if (m.document_type !== sourceTypes[directory]) {
        excluded.push({ file, reason: 'Evidence or legacy collection; not operational vocabulary' });
        continue;
      }
      if (!isPublicationCandidate(m, file)) {
        excluded.push({ file, reason: 'Permanently excluded mixed collection or rejected document; never published' });
        continue;
      }
      if (publication) {
        const source = fs.readFileSync(path.join(root, file));
        if (!source.equals(publication.git('show', `${publication.commit}:${file}`))) {
          throw new Error(`Glossary source differs from pinned publication commit: ${file}`);
        }
        if (!isEligible(m, file)) throw new Error(`Glossary source is not approved/verified: ${file}`);
      }
      const sections = questionSections(body);
      const bodies = questionBodies(body);
      documents.push({
        file, id: m.id, title: m.title, type: m.document_type, assistants: m.assistants,
        review_status: m.review_status, verification_status: m.verification_status,
        eligible: isEligible(m, file), source_sha256: hash(raw),
        questions: sections.length, routes: m.answers?.length ?? 0,
      });
      addTerm(m.title, file, 'document-title', m.assistants);
      const prose = body.replace(/^(`{3,}|~{3,})[^\n]*\n[\s\S]*?^\1\s*$/gm, '')
        .replace(/\]\(https?:\/\/[^)]+\)/g, ']').replace(/https?:\/\/\S+/g, '');
      for (const match of prose.matchAll(/^#{1,6} (.+)$/gm)) addTerm(match[1], file, 'heading', m.assistants);
      for (const match of prose.matchAll(/`([^`\n]+)`/g)) addTerm(match[1], file, 'exact-technical-term', m.assistants);
      for (const token of prose.match(/\b[A-Z][A-Z0-9]{1,14}\b/g) ?? []) {
        addTerm(token, file, 'uppercase-identifier-not-an-inferred-expansion', m.assistants);
      }
      for (const word of prose.replace(/`[^`\n]+`/g, ' ').match(/[\p{L}][\p{L}\p{N}_-]*/gu) ?? []) {
        addTerm(word, file, 'source-word-not-a-synonym', m.assistants);
      }
      for (const section of sections) {
        if (!bodies.has(section)) throw new Error(`Missing question body: ${file}: ${section}`);
        questions.push({ file, section, source_body_sha256: hash(bodies.get(section)),
          assistants: m.assistants, eligible: isEligible(m, file),
          route_id: m.answers?.find(route => route.section === section)?.id ?? null });
      }
      for (const route of m.answers ?? []) {
        routes.push({ ...route, file, assistants: m.assistants, eligible: isEligible(m, file) });
        for (const phrase of route.aliases) addTerm(phrase, file, 'resource-phrase-not-an-automatic-equivalence', m.assistants);
        for (const phrase of route.task_aliases) addTerm(phrase, file, 'task-phrase-not-a-product-synonym', m.assistants);
      }
      if (m.retrieval_aliases) {
        if (directory !== 'reference' || m.assistants.length !== 1 || m.assistants[0] !== 'landing-zone') {
          throw new Error(`Source alias would widen scope: ${file}`);
        }
        for (const alias of m.retrieval_aliases) {
          validateGroup([alias.canonical, ...alias.terms], file);
          const key = fold(alias.canonical);
          if (aliases.has(key)) throw new Error(`Duplicate source alias canonical: ${alias.canonical}`);
          aliases.set(key, { canonical: alias.canonical, terms: [...alias.terms] });
          for (const phrase of [alias.canonical, ...alias.terms]) addTerm(phrase, file, 'declared-resource-equivalent', m.assistants);
        }
      }
    }
  }
  const guideAliases = [...aliases.values()].sort((a, b) => a.canonical.localeCompare(b.canonical, 'en'));
  const sourceOwners = new Map();
  for (const alias of guideAliases) {
    for (const term of [alias.canonical, ...alias.terms]) {
      const owner = sourceOwners.get(fold(term));
      if (owner && owner !== alias.canonical) throw new Error(`Conflicting source-owned alias: ${term}`);
      sourceOwners.set(fold(term), alias.canonical);
    }
  }
  const runtime = { version: 1, groups: previous.groups, aliases: previous.aliases, guide_aliases: guideAliases };
  validateRuntime(runtime);
  const known = new Set([...runtime.groups.flat(), ...runtime.aliases.flatMap(alias => [alias.canonical, ...alias.terms]),
    ...guideAliases.flatMap(alias => [alias.canonical, ...alias.terms])].map(fold));
  const entries = [...corpus.values()].map(entry => ({
    term: entry.term, occurrences: sorted(entry.occurrences), kinds: sorted(entry.kinds), assistants: sorted(entry.assistants),
    disposition: known.has(fold(entry.term)) ? 'term-present-in-runtime-vocabulary-not-proof-of-scope-or-answer'
      : 'source-candidate-only-no-equivalence-approved',
  })).sort((a, b) => a.term.localeCompare(b.term, 'en'));
  const fingerprint = sourceFingerprint(documents);
  const baseline = readJson(root, 'glossary/evaluation-baseline.json');
  const sourceMatch = fingerprint === baseline.source_fingerprint;
  const runtimeMatch = runtimeFingerprint(runtime) === baseline.runtime_fingerprint;
  const coverage = {
    schema_version: 1, source_fingerprint: fingerprint,
    summary: { public_documents: documents.length, questions: questions.length, routes: routes.length,
      source_terms: entries.length, source_owned_alias_groups: guideAliases.length },
    exclusions: [
      'admin is not read or exported; other-agents is not a platform-admin isolation boundary',
      'decisions, run-records, assets and engineering-contract are not read or promoted into runtime synonyms',
      'source candidates do not approve guidance, establish equivalence or create routes',
    ],
    excluded, documents, questions, routes, corpus: entries,
  };
  const candidates = {
    schema_version: 1, source_fingerprint: fingerprint,
    status: 'review-only-never-upload-as-retrieval-synonyms',
    instructions: 'Review equivalents manually in explicitly scoped aliases or source retrieval_aliases. Never convert every source word or task into a synonym.',
    candidates: entries.filter(entry => !known.has(fold(entry.term))),
  };
  const evaluation = {
    schema_version: 1, source_fingerprint: fingerprint, runtime_fingerprint: runtimeFingerprint(runtime),
    historical_evaluation: baseline,
    source_matches_evaluated_snapshot: sourceMatch, runtime_matches_evaluated_snapshot: runtimeMatch,
    status: publication ? 'approved-verified-source-answer-validation'
      : sourceMatch && runtimeMatch ? 'snapshot-matches-not-end-to-end-certified' : 'stale-consumer-evaluation-rerun-required',
    limits: [
      'Historical glossary-*-results, glossary-complete-validation and internet-review files are immutable review snapshots, not fresh test results.',
      'Generation never reasserts historical matching counts or fixes built-in Hub vocabulary collisions.',
      'Source-owned alias publication requires the exact-head human source review; generation does not approve the source document.',
      'The reviewed immutable handoff notifies Hub-owned adoption; live response evaluation and deployment approval remain outside this compiler.',
    ],
  };
  if (publication) {
    const attribution = { review_status: 'approved', verification_status: 'verified',
      verification_scope: 'source-answer-validation', source_snapshot_commit: publication.commit,
      reviewed_by: publication.audit.approval.login, reviewed_at: publication.audit.approval.submitted_at,
      publication_review: publication.audit, runtime_sha256: hash(encode(runtime)) };
    for (const artifact of [coverage, candidates, evaluation]) Object.assign(artifact, attribution);
    coverage.status = 'approved-verified-source-answer-validation';
    candidates.status = 'approved-verified-source-answer-validation';
    evaluation.consumer_evaluation = 'historical-results-preserved-not-rerun';
    evaluation.limits = ['Human approval validates the source-derived glossary only. Historical consumer evaluation facts are preserved unchanged.'];
  }
  return Object.fromEntries(generatedGlossaryFiles.map((file, i) =>
    [file, encode([runtime, coverage, candidates, evaluation][i])]));
}

export function refreshGlossary(root, { check = false } = {}) {
  const outputs = glossaryOutputs(root);
  const changed = Object.entries(outputs).filter(([file, content]) => !fs.existsSync(path.join(root, file))
    || fs.readFileSync(path.join(root, file), 'utf8').replace(/\r\n/g, '\n') !== content).map(([file]) => file);
  if (check && changed.length) throw new Error(`Glossary outputs are stale: ${changed.join(', ')}. Run npm run glossary:update.`);
  if (!check) for (const file of changed) fs.writeFileSync(path.join(root, file), outputs[file], 'utf8');
  return changed;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.some(arg => arg !== '--check')) throw new Error('Usage: node scripts/refresh-glossary.mjs [--check]');
  try {
    const changed = refreshGlossary(process.cwd(), { check: args.includes('--check') });
    console.log(changed.length ? `Updated ${changed.join(', ')}` : 'Glossary outputs are current.');
  } catch (error) {
    const report = { summary: `Glossary source-answer compilation needs review: ${error.message}`.slice(0, 10000),
      affected: [...new Set(error.message.match(/(?:guides|reference|known-errors)\/[a-zA-Z0-9_./-]+\.md/g) ?? [])].slice(0, 100),
      options: ['Correct conflicting aliases or source schema in review Markdown and regenerate.',
        'Review existing runtime synonyms for a scoped curation correction; preserve historical evaluation facts.',
        'Retry unchanged only if the failure was transient.'] };
    if (process.env.KNOWLEDGE_REVIEW_REPORT) fs.writeFileSync(process.env.KNOWLEDGE_REVIEW_REPORT, encode(report));
    console.error(JSON.stringify({ schema_version: 1, type: 'glossary-review-required',
      message: error.message, items: [], requested_input: 'Correct the cited aliases or source schema in review Markdown and regenerate; historical evaluation records must not be rewritten.' }));
    process.exitCode = 1;
  }
}
