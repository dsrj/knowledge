#!/usr/bin/env python3
"""Validate generated JSON-LD, SHACL constraints, provenance and audience."""
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

from pyshacl import validate
from rdflib import Graph

ROOT = Path(__file__).resolve().parent.parent
KG = ROOT / "knowledge-graph"
diagram_spec = importlib.util.spec_from_file_location(
    "knowledge_graph_diagrams", ROOT / "scripts" / "knowledge_graph_diagrams.py")
diagram_module = importlib.util.module_from_spec(diagram_spec)
diagram_spec.loader.exec_module(diagram_module)
validate_diagrams = diagram_module.validate_records
PROFILE_DEPENDENCY_PREDICATES = {
    "depends-on", "reads-remote-state-produced-by", "requires-prior-data-from",
    "consumes-cost-mapping-state-from", "looks-up-existing-hub-from",
    "requires-separate-workload-identity-association",
    "requires-independent-network-authorization",
    "requires-catalog-creation-or-import-for-managed-secret-lifecycle",
    "requires-independent-activation-approval",
    "requires-terraform-output",
    "requires-environment-log-workspace",
}


def main():
    subprocess.run([sys.executable, str(ROOT / "scripts" / "build-knowledge-graph.py"), "--check"], check=True)
    graph = Graph()
    records = {}
    manifest = json.loads((KG / "manifest.json").read_text(encoding="utf-8"))
    source_verification_status = manifest["source_markdown_verification_status"]
    if source_verification_status not in {"verified", "not-assessed"}:
        raise ValueError("Invalid source Markdown verification status in manifest")
    publication_review = manifest.get("publication_review")
    if publication_review:
        if (manifest.get("status") != "complete" or
                manifest.get("source_extraction_status") != "complete" or
                manifest.get("review_status") != "approved" or
                manifest.get("verification_status") != "verified" or
                source_verification_status != "verified" or
                manifest.get("reviewed_by") != publication_review["approval"]["login"] or
                manifest.get("reviewed_at") != publication_review["approval"]["submitted_at"]):
            raise ValueError("Approved graph publication is incomplete or unverified")
    files = [file for file in manifest["outputs"] if file.endswith(".jsonld")]
    for file in files:
        data = json.loads((KG / file).read_text(encoding="utf-8"))
        graph.parse(data=json.dumps(data), format="json-ld")
        for record in data["@graph"]:
            if record["@id"] in records:
                raise ValueError(f"Duplicate ID: {record['@id']}")
            records[record["@id"]] = record
            if publication_review and (
                    record.get("reviewStatus") != "approved" or
                    record.get("verificationStatus") != "verified" or
                    record.get("reviewedBy") != publication_review["approval"]["login"] or
                    record.get("reviewedAt") != publication_review["approval"]["submitted_at"] or
                    record.get("publicationReview") != publication_review["review"] or
                    record.get("publicationProposalId") != publication_review["proposal_id"]):
                raise ValueError(f"Missing exact human publication attribution: {record['@id']}")
    diagram_config = json.loads((KG / "config" / "diagrams.json").read_text(encoding="utf-8"))
    validate_diagrams(records, diagram_config, manifest["source_snapshot_commit"])
    semantic_assessments = json.loads(
        (KG / "coverage" / "semantic-assessments.json").read_text(encoding="utf-8"))
    validate_interpretation_verification(records, semantic_assessments, source_verification_status,
                                        publication_review)
    ontology = Graph().parse(data=(KG / "model" / "ontology.ttl").read_text(encoding="utf-8"), format="turtle")
    shapes = Graph().parse(data=(KG / "model" / "shapes.ttl").read_text(encoding="utf-8"), format="turtle")
    conforms, _, report = validate(graph, shacl_graph=shapes, ont_graph=ontology)
    if not conforms:
        raise ValueError(report)
    for record in records.values():
        for key in ("source", "subject", "object", "targetSection", "members", "covers",
                    "environmentScope", "backedBy", "diagramId", "queryEntity",
                    "queryAliasSource", "queryRouteCanonicalResource", "querySourceEvidence",
                    "fromNode", "toNode"):
            if key in record:
                refs = record[key] if isinstance(record[key], list) else [record[key]]
                for ref in refs:
                    target = records.get(ref)
                    if target is None:
                        raise ValueError(f"Unresolved {key} in {record['@id']}")
                    restricted_link_to_guide = (key == "object" and record["audience"] == "admin"
                                                and target["audience"] == "guide"
                                                and record.get("predicate") == "explicitly-links-to-document")
                    if record["audience"] != target["audience"] and not restricted_link_to_guide:
                        raise ValueError(f"Cross-audience {key} in {record['@id']}")
                    if not restricted_link_to_guide and "assistants" in record and "assistants" in target and not set(record["assistants"]).issubset(target["assistants"]):
                        raise ValueError(f"Cross-assistant {key} in {record['@id']}")
        if record["@type"] == "KnowledgeProfile":
            covered = [records[identity] for identity in record["covers"]]
            expected_kind = ("resource-knowledge-bundle" if record["profileKind"] == "resource-type"
                             else "shared-topic-bundle")
            if (not covered or any(item.get("kind") != expected_kind or
                                   item["audience"] != record["audience"] or
                                   set(item["assistants"]) != set(record["assistants"]) or
                                   item["label"] != record["label"] for item in covered)):
                raise ValueError(f"Invalid profile coverage or scope: {record['@id']}")
        if record["@type"] == "ProfileRelationship":
            subject, target = records[record["subject"]], records[record["object"]]
            supporting = [records[identity] for identity in record["backedBy"]]
            source_members = {identity for bundle_id in subject["covers"]
                              for identity in records[bundle_id].get("members", [])}
            target_subjects = {records[identity]["subject"]
                               for bundle_id in target["covers"]
                               for identity in records[bundle_id].get("members", [])
                               if records[identity]["@type"] == "Claim"}
            if (subject["@type"] != "KnowledgeProfile" or target["@type"] != "KnowledgeProfile" or
                    subject["audience"] != target["audience"] or
                    set(subject["assistants"]) != set(target["assistants"]) or
                    any(item["@type"] != "Relationship" or
                        item["predicate"] not in PROFILE_DEPENDENCY_PREDICATES or
                        item["audience"] != record["audience"] or
                        set(item["assistants"]) != set(record["assistants"]) or
                        item["@id"] not in source_members or item["object"] not in target_subjects
                        for item in supporting)):
                raise ValueError(f"Invalid profile dependency link: {record['@id']}")
        if record["@type"] == "Evidence":
            if record["sourceVerificationStatus"] != source_verification_status:
                raise ValueError(f"Evidence source verification mismatch: {record['@id']}")
            expected_basis = ("human-approved-markdown-publication" if publication_review else
                              "user-confirmed-source-markdown-review"
                              if source_verification_status == "verified"
                              else "snapshot-not-matched-to-user-verification")
            if record["sourceVerificationBasis"] != expected_basis:
                raise ValueError(f"Evidence source verification basis mismatch: {record['@id']}")
            source = (ROOT / record["path"]).read_bytes()
            if hashlib.sha256(source).hexdigest() != record["sha256"]:
                raise ValueError(f"Source hash mismatch: {record['@id']}")
            lines = source.decode("utf-8").splitlines()
            start, end = record["startLine"], record["endLine"]
            if not (1 <= start <= end <= len(lines)) or "\n".join(lines[start-1:end]) != record["text"]:
                raise ValueError(f"Evidence range mismatch: {record['@id']}")
    print(f"JSON-LD and SHACL valid; {len(records)} uniquely identified records")


def validate_interpretation_verification(records, report, source_verification_status,
                                        publication_review=None):
    if publication_review:
        if source_verification_status != "verified":
            raise ValueError("Human-approved semantics require verified source Markdown")
        for record in records.values():
            if (record.get("reviewStatus") != "approved" or
                    record.get("verificationStatus") != "verified" or
                    record.get("reviewedBy") != publication_review["approval"]["login"] or
                    record.get("reviewedAt") != publication_review["approval"]["submitted_at"]):
                raise ValueError(f"Unattributed reviewed semantics: {record['@id']}")
        return
    """Independently verify interpretation stamps against current assessment bindings."""
    assessments = report.get("assessments")
    if not isinstance(assessments, list):
        raise ValueError("Semantic assessment report must contain an assessment list")
    if report.get("source_markdown_verification_status") != source_verification_status:
        raise ValueError("Interpretation report source verification differs from the manifest")
    by_id = {}
    supported = {}
    for assessment in assessments:
        identity = assessment.get("id")
        if not isinstance(identity, str) or identity in by_id:
            raise ValueError("Semantic assessments must have unique IDs")
        by_id[identity] = assessment
        if assessment.get("source_markdown_verification_status") != source_verification_status:
            raise ValueError(f"Assessment source verification differs from the manifest: {identity}")
        if assessment.get("status") != "covered-unverified":
            continue
        if (assessment.get("actual_section_sha256") != assessment.get("section_sha256") or
                assessment.get("actual_records_sha256") != assessment.get("records_sha256") or
                not assessment.get("snapshot_commit")):
            raise ValueError(f"Stale covered assessment: {identity}")
        bound_ids = set()
        directly_cited = set()
        related_cited = set()
        for facet in assessment.get("resolved_facets", []):
            for binding in facet.get("bindings", []):
                record_id = binding.get("record")
                if record_id:
                    if record_id not in records:
                        raise ValueError(f"Assessment references missing record: {identity}")
                    bound_ids.add(record_id)
                    if binding.get("selector", "").startswith("copilot:"):
                        directly_cited.add(record_id)
                for related_id in binding.get("related_records", []):
                    if related_id not in records:
                        raise ValueError(f"Assessment references missing related record: {identity}")
                    bound_ids.add(related_id)
                    related_cited.add(related_id)
        for record_id in list(bound_ids):
            record = records[record_id]
            for key in ("subject", "object"):
                target = record.get(key)
                if target in records:
                    bound_ids.add(target)
        if "hash_bound_record_ids" in assessment:
            declared = assessment["hash_bound_record_ids"]
            cited = directly_cited | related_cited
            if (not isinstance(declared, list) or len(declared) != len(set(declared)) or
                    not cited.issubset(declared) or
                    any(identity not in bound_ids for identity in declared)):
                raise ValueError(f"Invalid assessment hash-bound record inventory: {identity}")
            bound_ids = set(declared)
        normalized = []
        for record_id in sorted(bound_ids):
            record = records[record_id]
            reviewed = {key: value for key, value in record.items()
                        if key not in {"interpretationVerificationStatus",
                                       "interpretationVerificationBasis",
                                       "interpretationVerificationAssessments"}}
            if reviewed.get("status") == "source-verified-copilot-interpretation":
                reviewed["status"] = "unverified-copilot-interpretation"
            normalized.append(reviewed)
        actual_hash = hashlib.sha256(
            (json.dumps(normalized, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        ).hexdigest()
        if actual_hash != assessment.get("records_sha256"):
            raise ValueError(f"Assessment record hash mismatch: {identity}")
        if (assessment.get("source_markdown_verification_status") == "verified" and
                source_verification_status == "verified" and assessment.get("snapshot_commit")):
            supported[identity] = (directly_cited, related_cited)

    interpretation_statuses = {
        "unverified-copilot-interpretation", "source-verified-copilot-interpretation"}
    for identity, record in records.items():
        if record.get("status") not in interpretation_statuses:
            continue
        review_ids = record.get("interpretationVerificationAssessments")
        if not isinstance(review_ids, list) or review_ids != sorted(set(review_ids)):
            raise ValueError(f"Invalid interpretation assessment links: {identity}")
        verified = record["status"] == "source-verified-copilot-interpretation"
        if verified:
            if (record.get("interpretationVerificationStatus") != "source-verified" or
                    record.get("interpretationVerificationBasis") !=
                    "hash-bound-faceted-source-assessment" or not review_ids):
                raise ValueError(f"Missing source verification basis: {identity}")
            for assessment_id in review_ids:
                if assessment_id not in supported:
                    raise ValueError(f"Interpretation cites an ineligible assessment: {identity}")
                direct, related = supported[assessment_id]
                if (record["@type"] == "Claim" and identity not in direct or
                        record["@type"] == "Relationship" and identity not in related):
                    raise ValueError(f"Assessment does not cite interpretation: {identity}")
                if record["@type"] not in {"Claim", "Relationship", "Entity", "Process"}:
                    raise ValueError(f"Unexpected verified interpretation type: {identity}")
        elif (record.get("interpretationVerificationStatus") != "not-assessed" or
              record.get("interpretationVerificationBasis") !=
              "no-current-hash-bound-faceted-source-assessment" or review_ids):
            raise ValueError(f"Unverified interpretation has a verification stamp: {identity}")

    usages = {}
    for identity, record in records.items():
        if record.get("@type") in {"Claim", "Relationship"} and record.get("status") in interpretation_statuses:
            for key in ("subject", "object"):
                target = record.get(key)
                if target in records and records[target].get("status") in interpretation_statuses:
                    usages.setdefault(target, []).append(identity)
    for identity, record in records.items():
        if (record.get("@type") not in {"Entity", "Process"} or
                record.get("status") != "source-verified-copilot-interpretation"):
            continue
        use_ids = usages.get(identity, [])
        if not use_ids or any(records[use_id]["status"] !=
                              "source-verified-copilot-interpretation" for use_id in use_ids):
            raise ValueError(f"Entity/process is verified despite an unverified use: {identity}")
        expected = sorted({assessment_id for use_id in use_ids
                           for assessment_id in records[use_id]["interpretationVerificationAssessments"]})
        if record["interpretationVerificationAssessments"] != expected:
            raise ValueError(f"Entity/process assessment links do not match its uses: {identity}")


if __name__ == "__main__":
    main()
