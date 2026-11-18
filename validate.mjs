import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { answerInventory, gsaWorkflows, referenceOnlyQuestions } from './answer-inventory.mjs';

const directories = ['guides', 'reference', 'known-errors', 'run-records', 'assets', 'admin', 'decisions', 'engineering-contract'];
const decisionNotes = new Set(['decisions/README.md', 'decisions/review-scenarios.md']);
const userAssistants = ['landing-zone', 'firewall', 'service-catalog'];
export const adminAssistant = 'platform-admin';
const adminTypes = { guides: 'guide', reference: 'reference', 'known-errors': 'known-error', decisions: 'decision' };
const isAdminPath = file => file.split('/')[0] === 'admin';
const fields = new Set([
  'schema_version', 'id', 'title', 'assistants', 'topics', 'owner', 'document_type',
  'source_repository', 'source_path', 'source_commit', 'review_status',
  'verification_status', 'reviewed_by', 'reviewed_at', 'run_url', 'attempt',
  'conclusion', 'environment', 'retrieval_aliases', 'answer_schema_version', 'answers',
  'answer_presentation_version', 'answer_presentations', 'version',
]);
const required = [
  'schema_version', 'id', 'title', 'assistants', 'topics', 'owner', 'document_type',
  'source_repository', 'source_path', 'source_commit',
];
const runFields = ['run_url', 'attempt', 'conclusion', 'environment'];
const types = {
  guides: 'guide', reference: 'reference', 'known-errors': 'known-error',
  'run-records': 'run-record', assets: 'legacy-instructions', decisions: 'decision',
};
const runNotice = 'Sanitized run metadata only. This record is evidence, not approved guidance.';
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const nonempty = value => typeof value === 'string' && value.trim().length > 0;
const slug = value => typeof value === 'string' && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value);
const answerIdentifier = value => typeof value === 'string'
  && /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/.test(value) && value.length <= 120;
const fullSHA = value => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value);
const safePath = value => nonempty(value) && !/[:\\?#\x00-\x1f]/.test(value)
  && !value.startsWith('/') && value.split('/').every(part => part && part !== '.' && part !== '..');
const uniqueArray = (value, check) => Array.isArray(value) && value.length > 0
  && new Set(value).size === value.length && value.every(check);

export const historicalNotice = '> Historical evidence only; pending review and unverified. This collection is not\n> an individual run record or approved remediation. The recorded evidence is\n> preserved below; do not infer missing values or a verified fix from later success.';
export const archivalNotice = '> Archived legacy instructions, preserved for provenance only. These instructions\n> are not active repository policy. Follow the root AGENTS.md and _SCHEMA.md instead.';

export function withNotice(body, notice) {
  const newline = body.indexOf('\n');
  if (newline < 0) throw new Error('Document requires a body after its H1');
  return `${body.slice(0, newline)}\n\n${notice}\n${body.slice(newline)}`;
}

const workspaceNames = new Set([
  'APPROLES', 'BACKEND', 'BRANCHPROTECTION', 'CERTS', 'CLOUDOPS', 'DEVOPS',
  'GHCLIENTID', 'GHCLIENTSECRET', 'GHCUSTOMSECRETS', 'GHSUBSCRIPTIONID', 'GHTENANTID',
  'GITHUBACCESS', 'GITHUBAPP', 'GITHUBENVS', 'GITHUBOPTIONAL', 'GITHUBREPOS',
  'GITHUBSECRETS', 'GITHUBSPNS', 'GITHUBTEAM', 'GROUPS', 'GSA', 'IDNS', 'KEYVAULT',
  'MEMBERS', 'NSP', 'ONPREMACCESS', 'PIM', 'PUBLICNETWORKACCESS', 'RBAC', 'SFTP', 'WEBAPP',
]);
const workflowModes = new Set([
  'DEFAULT-[only changed workspaces]', 'GITHUBREPOS-[team.json]', 'CUSTOM',
  'PIM-[pim.json]', 'RUN_ALL-[All workspaces]', 'IDNS-[idns.json]', 'APPS-[spns.json]',
  'GROUPS-[groups.json]', 'GSA-[gsa.json]', 'PUBLICNETWORKACCESS-[publicnetworkaccess.json]',
  'NSP-[nsp.json]', 'ONPREM_ACCESS-[onpremaccess.json]', 'SFTP-[sftp.json]',
]);

export function validateHistoricalPayloads(body) {
  withoutFences(body);
  const fences = [...body.matchAll(/^ {0,3}(`{3,}|~{3,})([^\n]*)\n([\s\S]*?)^ {0,3}\1[ \t]*$/gm)];
  for (const [, , language, payload] of fences) {
    if (language.trim() !== 'json') throw new Error('Historical evidence permits only allow-listed workspace JSON, not raw logs or code');
    let value;
    try { value = JSON.parse(payload); }
    catch { throw new Error('Historical workspace evidence must be valid JSON'); }
    if (!value || Array.isArray(value) || typeof value !== 'object' || !Object.keys(value).length) throw new Error('Invalid historical workspace object');
    for (const [field, content] of Object.entries(value)) {
      if (/^workspaces_l[1-4]$/.test(field)) {
        if (!Array.isArray(content) || !content.every(name => workspaceNames.has(name))
          || new Set(content).size !== content.length) throw new Error('Historical workspace arrays permit known workspace labels only');
      } else if (/^refresh[1-4]$/.test(field)) {
        if (!content || Array.isArray(content) || typeof content !== 'object'
          || Object.entries(content).some(([name, flag]) => !workspaceNames.has(name) || !['true', 'false'].includes(flag))) {
          throw new Error('Historical refresh maps permit workspace labels and boolean strings only');
        }
      } else if (field === 'workflow_mode') {
        if (!workflowModes.has(content)) throw new Error('Unknown historical workflow mode');
      } else throw new Error(`Unrestricted historical output field: ${field}`);
    }
  }
}

export function parseDocument(text) {
  const normalized = text.replace(/\r\n/g, '\n');
  const match = normalized.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
  if (!match) throw new Error('Missing restricted YAML frontmatter');
  const metadata = {};
  for (const line of match[1].split('\n')) {
    const field = line.match(/^([a-z_]+): (.+)$/);
    if (!field) throw new Error(`Invalid metadata line: ${line}`);
    const [, key, value] = field;
    if (!fields.has(key)) throw new Error(`Unknown metadata field: ${key}`);
    if (Object.hasOwn(metadata, key)) throw new Error(`Duplicate metadata field: ${key}`);
    try { metadata[key] = JSON.parse(value); }
    catch { throw new Error(`Metadata ${key} must use a JSON-encoded value`); }
  }
  return { metadata, body: match[2] };
}

export function publicationContentHash(text) {
  const match = text.match(/^(---\r?\n)([\s\S]*?)(\r?\n---\r?\n)([\s\S]*)$/);
  if (!match) throw new Error('Missing publication frontmatter');
  const newline = match[1].includes('\r\n') ? '\r\n' : '\n';
  const header = match[2].split(/\r?\n/).filter(line => !/^(review_status|verification_status|reviewed_by|reviewed_at): /.test(line));
  return sha256(match[1] + header.join(newline) + match[3] + match[4]);
}

export function expectedAdminType(file) {
  const parts = file.split('/');
  return parts[0] === 'admin' && parts.length === 3 ? adminTypes[parts[1]] : undefined;
}

export function isPublicationCandidate(metadata, file) {
  if (metadata.review_status === 'rejected') return false;
  const directory = file.split('/')[0];
  const user = ['guides', 'reference', 'known-errors'].includes(directory)
    && metadata.document_type === types[directory]
    && !metadata.assistants?.includes(adminAssistant)
    && metadata.id !== 'service-catalog-known-errors';
  const admin = isAdminPath(file) && ['guide', 'reference', 'known-error'].includes(metadata.document_type)
    && metadata.document_type === expectedAdminType(file)
    && Array.isArray(metadata.assistants) && metadata.assistants.length === 1
    && metadata.assistants[0] === adminAssistant;
  return user || admin;
}

const isApproved = metadata => metadata.review_status === 'approved'
  && metadata.verification_status === 'verified'
  && nonempty(metadata.reviewed_by) && nonempty(metadata.reviewed_at);

// User-facing eligibility. Admin-only content is never eligible here.
export function isEligible(metadata, file) {
  return !isAdminPath(file) && isPublicationCandidate(metadata, file) && isApproved(metadata);
}

// Admin-only eligibility for a separate, access-restricted index.
export function isAdminEligible(metadata, file) {
  return isAdminPath(file) && isPublicationCandidate(metadata, file) && isApproved(metadata);
}

function withoutFences(body) {
  let marker = null;
  const lines = [];
  for (const line of body.split('\n')) {
    const fence = line.match(/^ {0,3}(`{3,}|~{3,})(.*)$/);
    if (fence) {
      if (!marker) marker = fence[1];
      else if (fence[1][0] === marker[0] && fence[1].length >= marker.length && !fence[2].trim()) marker = null;
      lines.push('');
    } else lines.push(marker ? '' : line);
  }
  if (marker) throw new Error('Unclosed Markdown code fence');
  return lines.join('\n');
}

export function anchors(body) {
  const prose = withoutFences(body);
  const result = new Set();
  for (const match of prose.matchAll(/<a\s+id="([^"]+)"\s*><\/a>/g)) {
    if (result.has(match[1])) throw new Error(`Duplicate explicit anchor: ${match[1]}`);
    result.add(match[1]);
  }
  const occurrences = new Map();
  for (const match of prose.matchAll(/^#{1,6}\s+(.+?)\s*#*\s*$/gm)) {
    const base = match[1].toLowerCase().replace(/<[^>]*>/g, '').replace(/[^\p{L}\p{N}_\s-]/gu, '').replace(/\s/g, '-');
    const count = occurrences.get(base) ?? 0;
    occurrences.set(base, count + 1);
    result.add(count ? `${base}-${count}` : base);
  }
  return result;
}

function validateRetrievalAliases(metadata, file) {
  if (!Object.hasOwn(metadata, 'retrieval_aliases')) return;
  const aliases = metadata.retrieval_aliases;
  const canonicalPrefix = 'SecOps policies: ';
  if (metadata.document_type !== 'reference' || !file.startsWith('reference/')
    || metadata.assistants.length !== 1 || metadata.assistants[0] !== 'landing-zone') {
    throw new Error('Retrieval aliases are limited to Landing Zone resource references');
  }
  if (!Array.isArray(aliases) || aliases.length === 0) throw new Error('retrieval_aliases must be a nonempty array');
  const canonicalNames = new Set();
  const terms = new Set();
  for (const alias of aliases) {
    if (!alias || Array.isArray(alias) || typeof alias !== 'object'
      || Object.keys(alias).sort().join(',') !== 'canonical,terms') {
      throw new Error('Each retrieval alias requires exactly canonical and terms');
    }
    const { canonical, terms: aliasTerms } = alias;
    if (typeof canonical !== 'string' || canonical.trim() !== canonical || canonical.length > 120
      || !canonical || !metadata.title.startsWith(canonicalPrefix)
      || metadata.title.slice(canonicalPrefix.length) !== canonical) {
      throw new Error('Retrieval alias canonical must match the SecOps resource title');
    }
    if (!Array.isArray(aliasTerms) || aliasTerms.length === 0
      || aliasTerms.some(term => typeof term !== 'string' || !term.trim() || term.trim() !== term
        || term.length > 120 || /[\r\n\x00-\x1f]/.test(term))) {
      throw new Error('Retrieval alias terms must be nonempty plain-text names');
    }
    const canonicalKey = canonical.toLowerCase();
    if (canonicalNames.has(canonicalKey)) throw new Error(`Duplicate retrieval alias canonical: ${canonical}`);
    canonicalNames.add(canonicalKey);
    for (const term of aliasTerms) {
      const termKey = term.toLowerCase();
      if (termKey === canonicalKey || terms.has(termKey)) throw new Error(`Duplicate or redundant retrieval alias term: ${term}`);
      terms.add(termKey);
    }
  }
}

export function questionSections(body) {
  const stack = [];
  const sections = [];
  for (const match of withoutFences(body).matchAll(/^(#{1,6})\s+(.+?)\s*#*\s*$/gm)) {
    const level = match[1].length;
    const heading = match[2];
    while (stack.length && stack.at(-1).level >= level) stack.pop();
    stack.push({ level, heading });
    if (heading.endsWith('?') || /^q:/i.test(heading)) {
      sections.push(stack.map(item => item.heading).join(' > '));
    }
  }
  return sections;
}

export function questionBodies(body) {
  const stack = [];
  const sections = new Map();
  const lines = body.split('\n');
  const prose = withoutFences(body).split('\n');
  for (let index = 0; index < lines.length; index++) {
    const heading = prose[index].match(/^(#{1,6})\s+(.+?)\s*#*\s*$/);
    if (heading) {
      const level = heading[1].length;
      while (stack.length && stack.at(-1).level >= level) stack.pop();
      stack.push({ level, heading: heading[2] });
    }
    const owner = stack.findLastIndex(item => item.heading.endsWith('?') || /^q:/i.test(item.heading));
    if (owner < 0) continue;
    const section = stack.slice(0, owner + 1).map(item => item.heading).join(' > ');
    if (!sections.has(section)) sections.set(section, []);
    if (!heading || owner !== stack.length - 1) sections.get(section).push(lines[index]);
  }
  return new Map([...sections].map(([section, content]) => [section, content.join('\n').trim()]));
}

export function validateAnswerInventory(documents, inventory = answerInventory) {
  const expected = new Set();
  const coverage = [];
  for (const requirement of inventory) {
    const { file, resource, task, id } = requirement;
    const key = `${resource}/${task}`;
    if (expected.has(key)) throw new Error(`Duplicate inventory combination: ${key}`);
    expected.add(key);
    const document = documents.find(doc => doc.path === file);
    if (!document?.metadata.assistants.includes('landing-zone')) {
      throw new Error(`Missing inventory document or Landing Zone scope: ${file}`);
    }
    const route = document.metadata.answers?.find(answer => answer.resource === resource && answer.task === task);
    if (!route || route.id !== id) throw new Error(`Missing inventory route: ${key} (${id}) in ${file}`);
    const presentation = document.metadata.answer_presentations?.find(entry => entry.section === route.section);
    if (presentation?.disposition !== 'direct') throw new Error(`Inventory route requires direct presentation: ${id}`);
    const body = questionBodies(document.body).get(route.section);
    const prose = body?.replace(/^#{1,6} .*$/gm, '').trim();
    if (!prose || prose.length < 60 || /^(?:Use|See|Follow|Refer to) (?:the )?.{0,100}(?:answer|workflow|section) (?:above|below)[.!]/i.test(prose)) {
      throw new Error(`Incomplete inventory answer: ${id}`);
    }
    if (/^(?:Follow the steps below for this task\.|Review the details below for this task\.|Use the checks below to investigate this issue\.)$/m.test(body)) {
      throw new Error(`Canonical answer requires a resource/task-specific introduction, not generic filler: ${id}`);
    }
    if (['security-controls', 'cloudops-policy-controls'].includes(task)) {
      if (presentation.layout !== 'controls'
        || !body.includes('| Control | Required setting or action | Reason | Policy / responsibility |')) {
        throw new Error(`Incomplete controls answer or mismatched layout: ${id}`);
      }
    }
    if (task === 'gsa-access') validateGsaAnswer(route, body, presentation);
    coverage.push({ ...requirement, section: route.section, support: route.support,
      eligible: isEligible(document.metadata, file) });
  }
  for (const document of documents.filter(doc => doc.metadata.assistants.includes('landing-zone'))) {
    for (const route of document.metadata.answers ?? []) {
      if (!expected.has(`${route.resource}/${route.task}`)) {
        throw new Error(`Landing Zone route missing from authoring inventory: ${route.id}`);
      }
    }
  }
  for (const [file, question] of referenceOnlyQuestions) {
    const document = documents.find(doc => doc.path === file);
    if (!document) continue;
    const section = `${document.metadata.title} > Common questions > ${question}`;
    if (document.metadata.answer_presentations?.find(entry => entry.section === section)?.disposition !== 'reference-only'
      || document.metadata.answers?.some(entry => entry.section === section)) {
      throw new Error(`Reference-only authoring pointer/example must not be a direct answer: ${file}: ${question}`);
    }
  }
  return coverage;
}

function validateGsaAnswer(route, body, presentation) {
  const workflow = gsaWorkflows[route.resource];
  const fail = detail => { throw new Error(`Incomplete GSA answer ${route.id}: ${detail}`); };
  if (!workflow) fail('no source-backed workflow inventory');
  if (workflow === 'unsupported') {
    if (route.support !== 'unsupported' || !body.includes('Contact CloudOps to arrange a supported access approach')
      || presentation.layout !== 'explanation') fail('support decision/action/layout');
    return;
  }
  if (route.support !== 'conditional' || !route.conditions.length || presentation.layout !== 'procedure') {
    fail('conditional applicability and procedure layout');
  }
  const required = [
    'Wait for DNS to update', 'Use a managed laptop signed in to GSA.',
    'Confirm the resource hostname resolves to its private IP or a GSA address starting with `6.6.`, then test the connection.',
  ];
  if (workflow === 'internal-environment') {
    required.push('internal Container App Environment', 'dedicated subnet', 'CloudOps ticket',
      "private IP address and Container Apps domain");
  } else {
    required.push('`snet-gsa-private-endpoints` in your own subscription',
      '`snet-gsa-private-endpoints-delegated` for approved cross-team access',
      '**If moving an existing endpoint:** expect a connection interruption during the IP switchover until DNS points to the new private endpoint IP.');
    if (workflow === 'fqdn') required.push('FQDN', 'port', 'resource ID, subscription',
      'For ports requiring an exception, request CloudOps approval.', 'CloudOps to add the rule');
    else {
      required.push('IP/CIDR-plus-port');
      if (route.resource === 'service-bus') required.push('does not need an FQDN rule');
      if (/Request the GSA rule/.test(body)) fail('automatic IP workflow must not request an FQDN rule');
    }
    const resourceNames = {
      'service-bus': 'Service Bus', 'azure-key-vault': 'Key Vault', 'azure-cache-for-redis': 'Redis',
      'azure-sql-database': 'SQL', 'azure-storage-accounts': 'Storage',
    };
    const endpointStep = body.match(/^2\. .*$/m)?.[0] ?? '';
    const resourceName = resourceNames[route.resource] ?? route.aliases[0];
    if (!endpointStep.includes('private endpoint') || !endpointStep.includes(resourceName)) {
      fail('resource-specific private endpoint step');
    }
  }
  for (const fragment of required) if (!body.includes(fragment)) fail(`missing ${fragment}`);
  const steps = [...body.matchAll(/^(\d+)\. \*\*[^*]+\.\*\* /gm)].map(match => Number(match[1]));
  const count = workflow === 'fqdn' ? 4 : 3;
  if (steps.length !== count || steps.some((step, index) => step !== index + 1)) fail('ordered complete actions');
}

function validateAnswers(metadata, body) {
  const hasVersion = Object.hasOwn(metadata, 'answer_schema_version');
  const hasAnswers = Object.hasOwn(metadata, 'answers');
  if (!hasVersion && !hasAnswers) return;
  if (!hasVersion || !hasAnswers || metadata.answer_schema_version !== 1) {
    throw new Error('Answer routes require paired answer_schema_version: 1 and answers');
  }
  if (!['guide', 'reference'].includes(metadata.document_type)) {
    throw new Error('Answer routes are only allowed on guide and reference documents');
  }
  if (!Array.isArray(metadata.answers) || metadata.answers.length === 0 || metadata.answers.length > 200) {
    throw new Error('answers must be a nonempty array with at most 200 entries');
  }
  const targets = questionSections(body);
  const ids = new Set();
  const routes = new Set();
  const sections = new Set();
  const strings = (value, allowEmpty) => Array.isArray(value) && value.length <= 40 && (allowEmpty || value.length > 0)
    && value.every(item => nonempty(item) && item === item.trim() && item.length <= 250
      && !/[\x00-\x1f\x7f]/.test(item))
    && new Set(value.map(item => item.toLowerCase())).size === value.length;
  for (const answer of metadata.answers) {
    if (!answer || Array.isArray(answer) || typeof answer !== 'object'
      || Object.keys(answer).sort().join(',') !== 'aliases,conditions,id,resource,section,support,task,task_aliases') {
      throw new Error('Each answer requires exactly id, resource, task, support, aliases, task_aliases, section and conditions');
    }
    if (![answer.id, answer.resource, answer.task].every(answerIdentifier)) {
      throw new Error('Answer id, resource and task must be stable lowercase-letter-leading kebab-case identifiers');
    }
    if (!['supported', 'conditional', 'unsupported', 'generic'].includes(answer.support)) {
      throw new Error(`Invalid answer support: ${answer.id}`);
    }
    if (!strings(answer.aliases, false) || !strings(answer.task_aliases, false)
      || !strings(answer.conditions, answer.support !== 'conditional')) {
      throw new Error(`Answer aliases/task_aliases must be nonempty plain-text lists; conditional support requires conditions: ${answer.id}`);
    }
    if (typeof answer.section !== 'string' || targets.filter(target => target === answer.section).length !== 1) {
      throw new Error(`Answer section must match exactly one full question heading path: ${answer.id}`);
    }
    const route = `${answer.resource}/${answer.task}`;
    if (ids.has(answer.id) || routes.has(route) || sections.has(answer.section)) {
      throw new Error(`Duplicate answer id, route or section: ${answer.id}`);
    }
    ids.add(answer.id);
    routes.add(route);
    sections.add(answer.section);
  }
}

export function validateAnswerPresentations(metadata, body) {
  const version = Object.hasOwn(metadata, 'answer_presentation_version');
  const entries = Object.hasOwn(metadata, 'answer_presentations');
  if (!version && !entries) return;
  if (!version || !entries || metadata.answer_presentation_version !== 1) {
    throw new Error('Answer presentations require paired answer_presentation_version: 1 and answer_presentations');
  }
  if (!['guide', 'reference'].includes(metadata.document_type)) {
    throw new Error('Answer presentations are only allowed on guide and reference documents');
  }
  const targets = questionSections(body);
  if (!Array.isArray(metadata.answer_presentations) || metadata.answer_presentations.length > 500) {
    throw new Error('answer_presentations must be an array with at most 500 entries');
  }
  const sections = new Set();
  for (const entry of metadata.answer_presentations) {
    if (!entry || Array.isArray(entry) || typeof entry !== 'object'
      || Object.keys(entry).sort().join(',') !== 'canonical_answer_id,disposition,layout,section') {
      throw new Error('Each answer presentation requires exactly section, layout, disposition and canonical_answer_id');
    }
    if (!['controls', 'procedure', 'explanation', 'troubleshooting', 'reference'].includes(entry.layout)
      || !['direct', 'duplicate', 'composite', 'reference-only', 'incomplete', 'over-budget'].includes(entry.disposition)) {
      throw new Error('Invalid answer presentation layout or disposition');
    }
    if (typeof entry.section !== 'string' || targets.filter(target => target === entry.section).length !== 1
      || sections.has(entry.section)) {
      throw new Error('Answer presentation section must match exactly one full question heading path without duplicates');
    }
    if (entry.disposition === 'duplicate' ? !answerIdentifier(entry.canonical_answer_id)
      : entry.canonical_answer_id !== '') {
      throw new Error('Only duplicate presentations require a canonical_answer_id; other dispositions require an empty string');
    }
    sections.add(entry.section);
  }
  for (const [section, content] of questionBodies(body)) {
    if (/^(?:Follow the steps below for this task\.|Review the details below for this task\.|Use the checks below to investigate this issue\.)$/m.test(content)) {
      throw new Error(`FAQ requires a source-backed resource/task introduction, not generic filler: ${section}`);
    }
  }
  if (sections.size !== targets.length) {
    throw new Error('Every FAQ requires exactly one answer presentation entry when opted in');
  }
}

export function validateAnswerScope(documents) {
  const ids = new Map();
  const routes = new Map();
  const names = new Map();
  for (const { metadata, path: file } of documents) {
    for (const answer of metadata.answers ?? []) {
      for (const assistant of metadata.assistants) {
        for (const [map, key, label] of [
          [ids, `${assistant}/${answer.id}`, 'id'],
          [routes, `${assistant}/${answer.resource}/${answer.task}`, 'route'],
        ]) {
          if (map.has(key)) throw new Error(`Duplicate answer ${label} ${key} in ${file} and ${map.get(key)}`);
          map.set(key, file);
        }
        for (const [kind, canonical, aliases] of [
          ['resource', answer.resource, answer.aliases], ['task', answer.task, answer.task_aliases],
        ]) {
          for (const alias of [canonical, ...aliases]) {
            const key = `${assistant}/${kind}/${kind === 'task' ? `${answer.resource}/` : ''}${alias.toLowerCase().replace(/[-\s]+/g, ' ')}`;
            const previous = names.get(key);
            if (previous && previous.canonical !== canonical) {
              throw new Error(`Answer ${kind} alias conflict "${alias}" between ${file} and ${previous.file}`);
            }
            names.set(key, { canonical, file });
          }
        }
      }
    }
  }
  for (const { metadata, path: file } of documents) {
    for (const entry of metadata.answer_presentations ?? []) {
      if (entry.disposition !== 'duplicate') continue;
      for (const assistant of metadata.assistants) {
        if (!ids.has(`${assistant}/${entry.canonical_answer_id}`)) {
          throw new Error(`Duplicate presentation canonical answer must resolve in the same assistant scope: ${file}: ${entry.canonical_answer_id}`);
        }
      }
      if (metadata.answers?.some(answer => answer.section === entry.section)) {
        throw new Error(`Duplicate presentation must not declare another runtime route: ${file}`);
      }
    }
  }
}

export function validateDocument(text, file) {
  const { metadata: m, body } = parseDocument(text);
  for (const field of required) if (!Object.hasOwn(m, field)) throw new Error(`Missing ${field}`);
  if (m.schema_version !== 1) throw new Error('Unsupported schema_version');
  if (Object.hasOwn(m, 'version') && (!Number.isSafeInteger(m.version) || m.version < 1
    || !['guide', 'reference', 'known-error'].includes(m.document_type))) {
    throw new Error('Content version must be a positive integer on guidance only');
  }
  if (!slug(m.id)) throw new Error('Invalid stable id');
  if (!nonempty(m.title) || body.split('\n')[0] !== `# ${m.title}`) throw new Error('H1 must match title');
  if (isAdminPath(file)) {
    if (!Array.isArray(m.assistants) || m.assistants.length !== 1 || m.assistants[0] !== adminAssistant) {
      throw new Error(`Admin-only documents must use exactly assistants: ["${adminAssistant}"]`);
    }
  } else if (!uniqueArray(m.assistants, item => userAssistants.includes(item))) {
    throw new Error(m.assistants?.includes?.(adminAssistant) ? `${adminAssistant} content must live under admin/` : 'Invalid assistants');
  }
  if (!uniqueArray(m.topics, slug)) throw new Error('Invalid topics');
  if (m.owner !== 'almbrand/cloudfoundation') throw new Error('Unknown owner team');
  if (typeof m.source_repository !== 'string' || !/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(m.source_repository)) throw new Error('Invalid source_repository');
  if (!safePath(m.source_path) || !fullSHA(m.source_commit)) throw new Error('Invalid source path or full commit SHA');
  if (m.review_status !== undefined && !['pending-review', 'approved', 'rejected'].includes(m.review_status)) throw new Error('Invalid review_status');
  if (m.verification_status !== undefined && !['unverified', 'verified'].includes(m.verification_status)) throw new Error('Invalid verification_status');
  if (m.reviewed_by !== undefined && !/^[a-zA-Z0-9](?:[a-zA-Z0-9_-]{0,38})(?:\[bot\])?$/.test(m.reviewed_by)) {
    throw new Error('Invalid publication reviewer login');
  }
  if (m.reviewed_at !== undefined && (typeof m.reviewed_at !== 'string'
    || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(m.reviewed_at)
    || !Number.isFinite(Date.parse(m.reviewed_at))
    || new Date(m.reviewed_at).toISOString() !== m.reviewed_at.replace('Z', '.000Z'))) {
    throw new Error('Invalid UTC reviewed_at');
  }
  const directory = file.split('/')[0];
  const expectedType = isAdminPath(file) ? expectedAdminType(file)
    : file.startsWith('run-records/historical/') ? 'historical-collection' : types[directory];
  if (!expectedType) throw new Error('Admin-only documents must be in admin/guides/, admin/reference/, admin/known-errors/ or admin/decisions/');
  if (m.document_type !== expectedType) throw new Error('Document type does not match directory');
  validateRetrievalAliases(m, file);
  validateAnswers(m, body);
  validateAnswerPresentations(m, body);
  if (['guide', 'reference'].includes(m.document_type)
    && /^(?:Follow the steps below for this task\.|Review the details below for this task\.|Use the checks below to investigate this issue\.)$/m.test(withoutFences(body))) {
    throw new Error('Guide/reference answers must not use generic presentation filler');
  }
  if (m.document_type === 'decision') {
    if (m.review_status !== 'pending-review' || m.verification_status !== 'unverified'
      || Object.hasOwn(m, 'reviewed_by') || Object.hasOwn(m, 'reviewed_at')) {
      throw new Error('Decision drafts must remain pending-review/unverified without approval attribution');
    }
    if (m.source_repository !== 'almbrand/cloudops-openai-hub-knowledge-source') {
      throw new Error('Decision provenance must point to this repository');
    }
    for (const section of ['## Scope', '## Decisions', '## Sources', '## Review gaps']) {
      if (!body.includes(section)) throw new Error(`Missing decision section ${section}`);
    }
    if (![...body.matchAll(/^\| `([a-z][a-z0-9-]+)` \|/gm)].length) {
      throw new Error('Decision drafts require stable decision IDs in a decision table');
    }
  }
  if (m.document_type === 'historical-collection') {
    if (!body.startsWith(`# ${m.title}\n\n${historicalNotice}\n`)) throw new Error('Historical collections require an explicit non-authoritative evidence notice');
    validateHistoricalPayloads(body);
  }
  if (m.document_type === 'legacy-instructions' && !body.startsWith(`# ${m.title}\n\n${archivalNotice}\n`)) {
    throw new Error('Legacy instructions require an explicit archival notice');
  }
  if (m.review_status === 'approved') {
    if (['run-record', 'historical-collection', 'legacy-instructions'].includes(m.document_type)
      || m.id === 'service-catalog-known-errors') throw new Error('Evidence, legacy instructions and mixed KE collection cannot be approved');
  }
  if (m.document_type === 'run-record') {
    for (const field of runFields) if (!Object.hasOwn(m, field)) throw new Error(`Missing run field ${field}`);
    const run = typeof m.run_url === 'string' && m.run_url.match(/^https:\/\/github\.com\/([^/]+\/[^/]+)\/actions\/runs\/([1-9]\d*)$/);
    if (!run || run[1] !== m.source_repository) throw new Error('Invalid run_url or repository mismatch');
    if (!Number.isSafeInteger(m.attempt) || m.attempt < 1) throw new Error('Invalid attempt');
    if (!['success', 'failure', 'cancelled', 'timed_out', 'action_required', 'neutral', 'skipped', 'stale', 'startup_failure'].includes(m.conclusion)) throw new Error('Invalid conclusion');
    if (typeof m.environment !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$/.test(m.environment)) throw new Error('Invalid environment; use a known short environment slug');
    const id = `run-${run[1].split('/')[1]}-${run[2]}-attempt-${m.attempt}`;
    if (m.id !== id || file !== `run-records/${id}.md`) throw new Error('Run ID and filename must use deterministic repository/run/attempt identity');
    if (m.title !== `Run ${run[2]} attempt ${m.attempt}`) throw new Error('Run title must use deterministic run/attempt identity');
    if (m.review_status !== 'pending-review' || m.verification_status !== 'unverified') throw new Error('Run evidence must remain pending-review/unverified');
    if (body.trim() !== `# ${m.title}\n\n${runNotice}`) throw new Error('Run body must contain only the static sanitized metadata notice');
  } else if (runFields.some(field => Object.hasOwn(m, field))) throw new Error('Run fields are only allowed for individual run records');
  const prose = withoutFences(body);
  if ([...prose.matchAll(/^# /gm)].length !== 1) throw new Error('Exactly one H1 is required');
  if (/^\*\*Keywords:\*\*/m.test(prose)) throw new Error('Keywords lists are not allowed; maintain search terms in the CloudOps OpenAI Hub glossary');
  if (['guide', 'reference', 'known-error', 'historical-collection'].includes(m.document_type)) {
    for (const section of ['## Purpose and scope', '## Common questions']) {
      if (!prose.includes(section)) throw new Error(`Missing ${section}`);
    }
    let questions = false;
    let count = 0;
    for (const line of prose.split('\n')) {
      if (/^## /.test(line)) questions = line === '## Common questions';
      if (questions && /^### /.test(line)) {
        count++;
        if (!line.endsWith('?') && !line.startsWith('### Q:')) throw new Error(`Question must end with ?: ${line}`);
      }
    }
    if (!count) throw new Error('Common questions must contain at least one question');
  }
  anchors(body);
  assertSafe(text);
  return { metadata: m, body, eligible: isEligible(m, file), admin_eligible: isAdminEligible(m, file) };
}

export function assertSafe(text) {
  const forbidden = [
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b/,
    /AccountKey=[A-Za-z0-9+/]{40,}={0,2}/i,
    /[?&]sig=[A-Za-z0-9%+/]{24,}/i,
    /https?:\/\/[^/\s:@]+:[^/\s@]+@/i,
    /<script\b|\]\(\s*(?:javascript|data):/i,
  ];
  if (forbidden.some(pattern => pattern.test(text))) throw new Error('Unsafe credential or executable content signature');
}

function walk(root, relative = '') {
  return fs.readdirSync(path.join(root, relative), { withFileTypes: true })
    .filter(entry => !['.git', 'node_modules'].includes(entry.name)
      && !(relative === '' && ['sources', 'reviews'].includes(entry.name)))
    .flatMap(entry => {
      const file = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) throw new Error(`Symlinks not allowed: ${file}`);
      return entry.isDirectory() ? walk(root, file) : [file];
    }).sort();
}

export function validateRepository(root) {
  const files = walk(root);
  const docs = [];
  const ids = new Set();
  const decisionIds = new Set();
  const retrievalNames = new Map();
  const answerDocuments = [];
  const bodies = new Map();
  for (const file of files) {
    if (['sources', 'reviews'].includes(file.split('/')[0])) continue;
    if (/\.(?:tfstate(?:\..*)?|tfplan|log|zip|gz|pem|pfx|key)$/i.test(file)) throw new Error(`Forbidden evidence/credential file: ${file}`);
    if (directories.includes(file.split('/')[0]) && !file.endsWith('.md')
      && file !== 'assets/migration-map.json' && file !== 'admin/.gitkeep') {
      throw new Error(`Unapproved content asset type: ${file}; add a reviewed explicit asset allow-list before using other file types`);
    }
    if (!file.endsWith('.md')) continue;
    const text = fs.readFileSync(path.join(root, file), 'utf8');
    try {
      assertSafe(text);
      if (!directories.includes(file.split('/')[0]) || decisionNotes.has(file)
        || file.startsWith('engineering-contract/')) {
        bodies.set(file, text);
        continue;
      }
      const doc = validateDocument(text, file);
      answerDocuments.push({ metadata: doc.metadata, body: doc.body, path: file });
      for (const { canonical, terms } of doc.metadata.retrieval_aliases ?? []) {
        for (const term of [canonical, ...terms]) {
          const key = term.toLowerCase();
          const previous = retrievalNames.get(key);
          if (previous) throw new Error(`Retrieval alias conflict for "${term}" with ${previous}`);
          retrievalNames.set(key, file);
        }
      }
      if (doc.metadata.document_type === 'decision') {
        if (!files.includes(doc.metadata.source_path)
          || !/^(?:admin\/)?(?:guides|reference|known-errors)\//.test(doc.metadata.source_path)) {
          throw new Error('Decision source_path must name an existing source document');
        }
        if (!isAdminPath(file) && isAdminPath(doc.metadata.source_path)) {
          throw new Error('General decisions must not derive from admin-only sources');
        }
        for (const [, id] of doc.body.matchAll(/^\| `([a-z][a-z0-9-]+)` \|/gm)) {
          if (decisionIds.has(id)) throw new Error(`Duplicate decision id ${id}`);
          decisionIds.add(id);
        }
      }
      if (ids.has(doc.metadata.id)) throw new Error(`Duplicate document id ${doc.metadata.id}`);
      ids.add(doc.metadata.id);
      bodies.set(file, doc.body);
      docs.push({
        id: doc.metadata.id, path: file, document_type: doc.metadata.document_type,
        review_status: doc.metadata.review_status, verification_status: doc.metadata.verification_status,
        audience: isAdminPath(file) ? 'admin' : 'user',
        eligible: doc.eligible, admin_eligible: doc.admin_eligible, sha256: sha256(text),
      });
    } catch (error) { throw new Error(`${file}: ${error.message}`); }
  }
  validateAnswerScope(answerDocuments);
  if (fs.existsSync(path.join(root, 'scripts', 'answer-inventory.mjs'))) validateAnswerInventory(answerDocuments);
  for (const [file, body] of bodies) {
    const prose = withoutFences(body);
    for (const match of prose.matchAll(/!?\[[^\]\n]*\]\(([^)\s]+)\)/g)) {
      const href = match[1];
      if (/^[a-z][a-z0-9+.-]*:/i.test(href)) continue;
      const [target, fragment] = href.split('#');
      const resolved = target ? path.posix.normalize(path.posix.join(path.posix.dirname(file), decodeURIComponent(target))) : file;
      if (resolved.startsWith('../') || !files.includes(resolved)) throw new Error(`${file}: Missing or escaping relative link ${href}`);
      if (isAdminPath(resolved) && !isAdminPath(file) && directories.includes(file.split('/')[0])) throw new Error(`${file}: User-facing content must not link to admin-only content ${href}`);
      if (fragment && bodies.has(resolved) && !anchors(bodies.get(resolved)).has(decodeURIComponent(fragment))) throw new Error(`${file}: Missing anchor ${href}`);
    }
  }
  const map = JSON.parse(fs.readFileSync(path.join(root, 'assets', 'migration-map.json'), 'utf8'));
  if (map.schema_version !== 1 || !fullSHA(map.source_commit) || !map.original_source_retained || !Array.isArray(map.entries)) throw new Error('Invalid migration inventory');
  const sourcePaths = new Set(), destinations = new Set();
  function currentPublication(entry, text) {
    if (entry.publication === undefined) return null;
    const value = entry.publication;
    const m = parseDocument(text).metadata;
    if (!value || Object.keys(value).sort().join(',') !== 'content_sha256,source_commit,source_path,source_repository'
      || !Number.isSafeInteger(m.version) || m.version < 1
      || !/^[a-f0-9]{64}$/.test(value.content_sha256)
      || publicationContentHash(text) !== value.content_sha256
      || ['source_repository', 'source_path', 'source_commit'].some(key => m[key] !== value[key])) {
      throw new Error(`Invalid current publication baseline: ${entry.destination_path}`);
    }
    return value;
  }
  for (const entry of map.entries) {
    if (!safePath(entry.source_path) || !safePath(entry.destination_path)
      || sourcePaths.has(entry.source_path) || destinations.has(entry.destination_path)) throw new Error('Duplicate or invalid migration paths');
    sourcePaths.add(entry.source_path); destinations.add(entry.destination_path);
    if (!['migrated', 'historical-content', 'archived-instructions', 'consolidated'].includes(entry.handling)
      || !/^[a-f0-9]{64}$/.test(entry.source_sha256) || !/^[a-f0-9]{64}$/.test(entry.migration_sha256)) throw new Error('Invalid migration handling or checksum');
    if (entry.handling === 'consolidated') {
      const target = entry.consolidation;
      if (!slug(entry.id) || !target || !safePath(target.destination_path) || !slug(target.id)
        || !slug(target.anchor) || !fullSHA(target.previous_commit)
        || !/^(?:admin\/)?(?:guides|reference|known-errors)\//.test(entry.destination_path)
        || isAdminPath(entry.destination_path) !== isAdminPath(target.destination_path)) {
        throw new Error(`Invalid consolidation record: ${entry.destination_path}`);
      }
      if (files.includes(entry.destination_path) || docs.some(doc => doc.id === entry.id)) {
        throw new Error(`Consolidated document must be retired: ${entry.destination_path}`);
      }
      const replacement = docs.find(doc => doc.path === target.destination_path && doc.id === target.id);
      if (!replacement || !['guide', 'reference', 'known-error'].includes(replacement.document_type)
        || !anchors(bodies.get(target.destination_path)).has(target.anchor)) {
        throw new Error(`Missing consolidation target or anchor: ${entry.destination_path}`);
      }
      continue;
    }
    if (entry.consolidation !== undefined) throw new Error(`Unexpected consolidation record: ${entry.destination_path}`);
    const doc = docs.find(item => item.path === entry.destination_path);
    if (!doc || doc.id !== entry.id) throw new Error(`Missing migrated document ${entry.destination_path}; retain a historical reference if retiring it`);
    const text = fs.readFileSync(path.join(root, entry.destination_path), 'utf8');
    const m = parseDocument(text).metadata;
    if (!currentPublication(entry, text)
      && (m.source_repository !== map.source_repository || m.source_commit !== map.source_commit || m.source_path !== entry.source_path)) {
      throw new Error(`Migration provenance mismatch: ${entry.destination_path}`);
    }
  }
  if (map.derived_documents !== undefined) {
    if (!Array.isArray(map.derived_documents)) throw new Error('Invalid derived migration documents');
    const derivedPaths = new Set();
    for (const entry of map.derived_documents) {
      if (!safePath(entry.destination_path) || derivedPaths.has(entry.destination_path)
        || destinations.has(entry.destination_path) || !/^[a-f0-9]{64}$/.test(entry.sha256)) {
        throw new Error('Duplicate or invalid derived migration document');
      }
      derivedPaths.add(entry.destination_path);
      const doc = docs.find(item => item.path === entry.destination_path);
      const source = map.entries.find(item => item.source_path === entry.source_path);
      const text = doc ? fs.readFileSync(path.join(root, entry.destination_path), 'utf8') : null;
      const current = text === null ? null : currentPublication(entry, text);
      const checksumMatches = current || (text !== null && (entry.content_sha256 === undefined
        ? sha256(text) === entry.sha256
        : /^[a-f0-9]{64}$/.test(entry.content_sha256) && publicationContentHash(text) === entry.content_sha256));
      if (!doc || doc.id !== entry.id || !source || !checksumMatches) {
        throw new Error(`Missing or changed derived migration document ${entry.destination_path}`);
      }
      const m = parseDocument(fs.readFileSync(path.join(root, entry.destination_path), 'utf8')).metadata;
      if (!current && (m.source_repository !== map.source_repository || m.source_commit !== map.source_commit || m.source_path !== entry.source_path)) {
        throw new Error(`Derived migration provenance mismatch: ${entry.destination_path}`);
      }
    }
  }
  return { schema_version: 1, documents: docs, totals: {
    documents: docs.length, eligible: docs.filter(doc => doc.eligible).length,
    admin_documents: docs.filter(doc => doc.audience === 'admin').length,
    admin_eligible: docs.filter(doc => doc.admin_eligible).length,
    legacy_inventory: map.entries.length,
  } };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const report = validateRepository(process.cwd());
    let commit = null;
    try { commit = execFileSync('git', ['rev-parse', '--verify', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); }
    catch {
      if (process.argv.includes('--report')) throw new Error('A committed checkout is required for a consumer report');
    }
    if (process.argv.includes('--report')) {
      const dirty = execFileSync('git', ['status', '--porcelain', '--untracked-files=all'], { encoding: 'utf8' }).trim();
      if (dirty) throw new Error('Consumer reports require a clean checkout pinned to the reported commit');
      console.log(JSON.stringify({ ...report, commit }, null, 2));
    } else console.log(`Validated ${report.totals.documents} documents; ${report.totals.eligible} authoritative (user); ${report.totals.admin_documents} admin-only (${report.totals.admin_eligible} authoritative); ${report.totals.legacy_inventory} legacy files mapped.`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
