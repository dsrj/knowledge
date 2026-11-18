import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { isEligible, isAdminEligible, isPublicationCandidate, parseDocument, publicationContentHash, validateDocument, validateRepository } from './validate.mjs';

export const publicationReviewer = 'github-actions[bot]';
const reviewFields = new Set(['review_status', 'verification_status', 'reviewed_by', 'reviewed_at']);

export function publicationText(text, reviewedAt) {
  const match = text.match(/^(---\r?\n)([\s\S]*?)(\r?\n---\r?\n)([\s\S]*)$/);
  if (!match) throw new Error('Missing publication frontmatter');
  const newline = match[1].includes('\r\n') ? '\r\n' : '\n';
  const lines = match[2].split(/\r?\n/).filter(line => !reviewFields.has(line.split(':')[0]));
  const metadata = {
    review_status: 'approved', verification_status: 'verified',
    reviewed_by: publicationReviewer, reviewed_at: reviewedAt,
  };
  lines.push(...Object.entries(metadata).map(([field, value]) => `${field}: ${JSON.stringify(value)}`));
  return match[1] + lines.join(newline) + match[3] + match[4];
}

export function publishKnowledge({ root, changedFiles = [], reviewedAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z') }) {
  // Validate the entire source before preparing or writing any publication metadata.
  const report = validateRepository(root);
  const changed = new Set(changedFiles);
  const updates = [];
  for (const document of report.documents) {
    const file = document.path;
    const original = fs.readFileSync(path.join(root, file), 'utf8');
    const { metadata } = parseDocument(original);
    if (!isPublicationCandidate(metadata, file)) continue;
    if (!changed.has(file) && (isEligible(metadata, file) || isAdminEligible(metadata, file))) continue;
    const content = publicationText(original, reviewedAt);
    validateDocument(content, file);
    if (publicationContentHash(content) !== publicationContentHash(original)) {
      throw new Error(`Publication attempted to change content or provenance: ${file}`);
    }
    if (content !== original) updates.push({ file, original, content });
  }
  for (const { file, original } of updates) {
    if (fs.readFileSync(path.join(root, file), 'utf8') !== original) {
      throw new Error(`Source changed during validation: ${file}`);
    }
  }
  for (const { file, content } of updates) fs.writeFileSync(path.join(root, file), content);
  return updates.map(({ file }) => file);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  console.error('Retired automatic publisher: use the exact-head human-reviewed shared/admin source pipelines.');
  process.exitCode = 1;
}
