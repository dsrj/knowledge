import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isEligible, isPublicationCandidate, parseDocument, questionSections, questionBodies, validateAnswerInventory } from './validate.mjs';

export function answerCoverage(root) {
  const documents = [];
  const faqs = [];
  const sources = [];
  for (const directory of ['guides', 'reference']) {
    for (const name of fs.readdirSync(path.join(root, directory)).filter(name => name.endsWith('.md')).sort()) {
      const file = `${directory}/${name}`;
      const { metadata, body } = parseDocument(fs.readFileSync(path.join(root, directory, name), 'utf8'));
      sources.push({ path: file, metadata, body });
      const eligible = isEligible(metadata, file);
      if (!isPublicationCandidate(metadata, file) && !metadata.answer_presentations) continue;
      const sections = questionSections(body);
      const bodies = questionBodies(body);
      const entries = metadata.answer_presentations ?? [];
      documents.push({ file, eligible, assistants: metadata.assistants,
        questions: sections.length, presentations: entries.length, routes: metadata.answers?.length ?? 0 });
      for (const section of sections) {
        const presentation = entries.find(entry => entry.section === section);
        const route = metadata.answers?.find(entry => entry.section === section);
        faqs.push({ file, eligible, assistants: metadata.assistants, section,
          layout: presentation?.layout ?? 'unclassified',
          disposition: presentation?.disposition ?? 'unclassified',
          generic_filler: /^(?:Follow the steps below for this task\.|Review the details below for this task\.|Use the checks below to investigate this issue\.)$/m.test(bodies.get(section) ?? ''),
          canonical_answer_id: presentation?.canonical_answer_id ?? '',
          route: route?.id ?? '', support: route?.support ?? '' });
      }
    }
  }
  const summarize = (docs, entries) => {
    const count = key => Object.fromEntries([...new Set(entries.map(entry => entry[key]))].sort()
      .map(value => [value, entries.filter(entry => entry[key] === value).length]));
    return { documents: docs.length, faqs: entries.length,
      runtime_routes: entries.filter(entry => entry.route).length,
      legacy_retrieval: entries.filter(entry => !entry.route).length,
      legacy_direct_generic_filler: entries.filter(entry => !entry.route
        && entry.disposition === 'direct' && entry.generic_filler).length,
      layouts: count('layout'), dispositions: count('disposition') };
  };
  const combinations = validateAnswerInventory(sources);
  return {
    schema_version: 1,
    resource_task_coverage: {
      expected: combinations.length,
      validated: combinations.length,
      current_eligible: combinations.filter(entry => entry.eligible).length,
      pending_or_ineligible: combinations.filter(entry => !entry.eligible).length,
      support: Object.fromEntries(['supported', 'conditional', 'unsupported', 'generic']
        .map(support => [support, combinations.filter(entry => entry.support === support).length])),
      combinations,
    },
    current_eligible: summarize(documents.filter(doc => doc.eligible), faqs.filter(faq => faq.eligible)),
    all_opted_in: summarize(documents, faqs),
    scopes: Object.fromEntries(['landing-zone', 'firewall', 'service-catalog'].map(assistant => [assistant,
      summarize(documents.filter(doc => doc.eligible && doc.assistants.includes(assistant)),
        faqs.filter(faq => faq.eligible && faq.assistants.includes(assistant)))])),
    limitations: [
      'Presentation coverage is not semantic route coverage or proof of a deployed control.',
      'The independent authoring inventory checks declared resource/task combinations, not every FAQ or every product under a domain suffix.',
      'Body and workflow checks catch known omissions; technical correctness and newly supported combinations still require human source review.',
      'Direct answers can retain legacy retrieval; no fabricated resource/task identifiers.',
      'Known errors retain their existing troubleshooting path and assistant scopes.',
      'CloudOps policy guide exceeds the legacy indexed-content cap with production chunk sizes; schema-enabled lossless indexing counts original bodies under the unchanged 200000-character bound. Existing complete layouts are preserved.',
      'No standalone general firewall operations runbook is present; request, runner-network and controls guidance are separate.',
      'Shared WAF policy detail spans two products; it has no fabricated single-product detail route.',
    ],
    documents, faqs,
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify(answerCoverage(path.resolve('.')), null, 2));
}
