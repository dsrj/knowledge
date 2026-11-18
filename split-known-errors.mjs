import crypto from 'node:crypto';
import { parseDocument, validateDocument } from './validate.mjs';

const errorHeading = /^### Error record (KE-\d+): (.+)$/gm;
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');

export function splitKnownErrors(text) {
  const { metadata, body } = parseDocument(text);
  const headings = [...body.matchAll(errorHeading)];
  if (!headings.length) throw new Error('No KE error records found');
  const records = [];
  for (let index = 0; index < headings.length; index++) {
    const heading = headings[index];
    const ke = heading[1].toLowerCase();
    const title = `Error record ${heading[1]}: ${heading[2]}`;
    const start = heading.index + heading[0].length;
    const end = headings[index + 1]?.index ?? body.indexOf('\n## Associated diagnostics', start);
    if (end < 0) throw new Error('Missing associated-diagnostics section after error records');
    let recordBody = body.slice(start, end).trim();
    const nextKe = headings[index + 1]?.[1].toLowerCase();
    if (nextKe) recordBody = recordBody.replace(new RegExp(`<a id="${nextKe}"><\\/a>\\s*$`), '').trimEnd();
    recordBody = recordBody.replace(/\]\(#(ke-\d+)\)/g, `](service-catalog-$1.md#$1)`);
    const record = {
      metadata: {
        ...metadata,
        id: `service-catalog-${ke}`,
        title,
      },
      body: `# ${title}\n\n`
        + '## Purpose and scope\n\n'
        + `This record preserves the observed signature, evidence, scoped guidance, and validation status for ${heading[1]}. A repeated diagnostic is not by itself a confirmed cause or verified fix.\n\n`
        + '## Common questions\n\n'
        + `### What is recorded for ${heading[1]}?\n\n`
        + `<a id="${ke}"></a>\n\n${recordBody}\n`,
    };
    const file = `known-errors/service-catalog-${ke}.md`;
    const output = serialize(record.metadata, record.body);
    validateDocument(output, file);
    records.push({ path: file, id: record.metadata.id, text: output });
  }

  const firstRecord = headings[0].index;
  const diagnostics = body.indexOf('\n## Associated diagnostics', firstRecord);
  if (diagnostics < 0) throw new Error('Missing associated-diagnostics section');
  let indexBody = body.slice(0, firstRecord) + body.slice(diagnostics);
  indexBody = indexBody.replace(/<a id="ke-\d+"><\/a>\s*/g, '');
  indexBody = indexBody.replace(
    /(\[KE-(\d+)\]\(#ke-\2\))/g,
    (_link, _match, number) => `[KE-${number}](service-catalog-ke-${number}.md#ke-${number})`,
  );
  indexBody = indexBody.replace(
    'Match the observed diagnostic to the corresponding error record below. Each record distinguishes observed evidence from confirmed causes and owner-reviewed actions; check the status before acting. Use the stable `KE-*` identifier when coordinating with CloudOps.',
    'Match the observed diagnostic to an individual record from the error index. Each record distinguishes observed evidence from confirmed causes and owner-reviewed actions; check its status before acting. Use the stable `KE-*` identifier when coordinating with CloudOps.',
  );
  const indexText = serialize(metadata, indexBody);
  validateDocument(indexText, 'known-errors/service-catalog-known-errors.md');
  return { indexText, records };
}

function serialize(metadata, body) {
  return `---\n${Object.entries(metadata).map(([key, value]) => `${key}: ${JSON.stringify(value)}`).join('\n')}\n---\n${body}`;
}

if (process.argv[1] && process.argv[1].endsWith('split-known-errors.mjs')) {
  const fs = await import('node:fs');
  const file = 'known-errors/service-catalog-known-errors.md';
  const result = splitKnownErrors(fs.readFileSync(file, 'utf8'));
  const manifestPath = 'assets/migration-map.json';
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const entry = manifest.entries.find(item => item.destination_path === file);
  if (!entry || sha256(fs.readFileSync(file)) !== entry.migration_sha256) {
    throw new Error('Refusing to split an index that differs from its migration baseline');
  }
  const derivedDocuments = result.records.map(record => ({
    destination_path: record.path,
    id: record.id,
    source_path: entry.source_path,
    sha256: sha256(record.text),
  }));
  for (const record of result.records) {
    if (fs.existsSync(record.path)) throw new Error(`Refusing to overwrite ${record.path}`);
  }
  entry.migration_sha256 = sha256(result.indexText);
  manifest.derived_documents = [
    ...(manifest.derived_documents ?? []).filter(item => item.source_path !== entry.source_path),
    ...derivedDocuments,
  ];
  fs.writeFileSync(file, result.indexText);
  for (const record of result.records) fs.writeFileSync(record.path, record.text);
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`Created ${result.records.length} individual service-catalog error records.`);
}
