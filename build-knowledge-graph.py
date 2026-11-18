#!/usr/bin/env python3
"""Build a source-preserving knowledge graph with explicit extraction status."""
import argparse
from collections import Counter, defaultdict
from datetime import datetime
import hashlib
import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
GRAPH = ROOT / "knowledge-graph"
BASE = "https://github.com/almbrand/cloudops-openai-hub-knowledge-source/knowledge-graph/"


class GraphReviewRequired(ValueError):
    def __init__(self, message, items):
        super().__init__(message)
        self.summary = {"schema_version": 1, "type": "graph-review-required",
                        "message": message, "items": items,
                        "requested_input": "Review the cited Markdown and resolve or explicitly disposition each gap; then approve the changed review Markdown."}


def approved_publication(commit):
    """Trust the pipeline's approval signal only with a committed, valid audit."""
    if os.environ.get("KNOWLEDGE_REVIEW_APPROVED") != "1":
        return None
    if os.environ.get("KNOWLEDGE_SOURCE_COMMIT") != commit:
        raise ValueError("Approved graph compilation requires KNOWLEDGE_SOURCE_COMMIT")
    file = ROOT / "publication" / "review.json"
    data = file.read_bytes()
    if git("show", f"{commit}:publication/review.json") != data:
        raise ValueError("Publication audit differs from the pinned Markdown commit")
    audit = json.loads(data)
    if (not isinstance(audit, dict) or set(audit) != {
            "schema_version", "audience", "proposal_id", "review", "approval"} or
            audit["schema_version"] != 1 or audit["audience"] not in {"shared", "admin"} or
            not isinstance(audit["proposal_id"], str) or
            not re.fullmatch(r"[a-f0-9]{64}", audit["proposal_id"]) or
            not isinstance(audit["review"], dict) or
            set(audit["review"]) != {"pull_request", "head_commit"} or
            type(audit["review"]["pull_request"]) is not int or audit["review"]["pull_request"] < 1 or
            not isinstance(audit["review"]["head_commit"], str) or
            not re.fullmatch(r"[a-f0-9]{40}", audit["review"]["head_commit"]) or
            not isinstance(audit["approval"], dict) or
            set(audit["approval"]) != {"login", "submitted_at"} or
            not isinstance(audit["approval"]["login"], str) or
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,38}", audit["approval"]["login"]) or
            not isinstance(audit["approval"]["submitted_at"], str)):
        raise ValueError("Invalid human-approved publication audit")
    timestamp = datetime.fromisoformat(audit["approval"]["submitted_at"].replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError("Publication approval timestamp requires a timezone")
    return audit


def apply_publication_review(outputs, audit):
    """Apply the one human gate to complete source-derived artifacts, not source facts."""
    status_values = {
        "covered-unverified": "covered-verified",
        "source-semantics-assessed-unverified": "source-semantics-reviewed-verified",
        "unverified-copilot-interpretation": "source-verified-copilot-interpretation",
        "navigation-only-unverified-interpretations": "approved-verified-navigation",
        "partial-source-verified-copilot-interpretation-review": "approved-verified",
        "partial-source-verified-interpretation-review": "approved-verified",
        "partial-resource-and-shared-organization": "approved-verified",
        "not-assessed": "verified",
    }

    def reviewed(value):
        if isinstance(value, list):
            return [reviewed(item) for item in value]
        if not isinstance(value, dict):
            return value
        result = {}
        for key, item in value.items():
            if key == "@context":
                result[key] = item
                continue
            if key in {"liveVerificationStatus", "live_verification_status"}:
                continue
            if key == "status" and item == "proposed" and value.get("@type") == "KnowledgeProfile":
                result[key] = "approved"
            elif key == "interpretationVerificationStatus":
                result[key] = "verified"
            elif isinstance(item, str) and (key.lower().endswith("status") or key == "disposition"):
                result[key] = status_values.get(item, item)
            elif key == "interpretationVerificationBasis":
                result[key] = "human-approved-markdown-publication"
            else:
                result[status_values.get(key, key)] = reviewed(item)
        if "@id" in result and "@type" in result:
            result.update(reviewStatus="approved", verificationStatus="verified",
                          reviewedBy=audit["approval"]["login"],
                          reviewedAt=audit["approval"]["submitted_at"],
                          publicationReview=audit["review"],
                          publicationProposalId=audit["proposal_id"])
        return result

    for name, data in list(outputs.items()):
        if name.endswith((".json", ".jsonld")):
            value = reviewed(json.loads(data))
            if name in {"coverage/copilot-review.json", "coverage/semantic-assessments.json"}:
                counts = value["interpretation_record_counts"]
                totals = Counter(counts.get("source_verified", {}))
                totals.update(counts.get("not_assessed", {}))
                value["interpretation_record_counts"] = {"verified": dict(sorted(totals.items()))}
                value["source_verification_basis"] = "human-approved-markdown-publication"
                value["note"] = "Complete source-answer semantics approved by the human reviewer recorded in the publication audit."
            if name == "manifest.json":
                value["covered_verified_section_count"] = value.pop("covered_unverified_section_count", 0)
                value["limitations"] = []
            outputs[name] = encoded(value)

def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def build_diagrams(graph_records, profile_records, source_snapshot_commit):
    spec = importlib.util.spec_from_file_location(
        "knowledge_graph_diagrams", Path(__file__).with_name("knowledge_graph_diagrams.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    config = load(GRAPH / "config" / "diagrams.json")
    diagrams = module.build(config, graph_records, profile_records, source_snapshot_commit)
    combined = {**graph_records, **{record["@id"]: record
                                  for values in diagrams.values() for record in values}}
    _, coverage = module.build_companions(config, combined, source_snapshot_commit)
    return diagrams, coverage


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def write_review_report(summary, destination=None):
    destination = destination or os.environ.get("KNOWLEDGE_REVIEW_REPORT")
    if not destination:
        return
    items = summary.get("items", [])
    affected = sorted({item.get("path", "") for item in items if isinstance(item, dict)
                       and re.fullmatch(r"(?:guides|reference|admin)/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+\.md",
                                        item.get("path", ""))})[:100]
    details = []
    for item in items[:25]:
        if not isinstance(item, dict):
            continue
        location = item.get("path", item.get("id", "source"))
        detail = item.get("status", item.get("reason", "requires review"))
        details.append(f"{location}: {detail}")
    message = summary["message"] + ("\n" + "\n".join(details) if details else "")
    # The JavaScript exception recorder limits String.length (UTF-16 code units).
    message = message.encode("utf-16-le")[:16000].decode("utf-16-le", errors="ignore")
    report = {"summary": message,
              "affected": affected,
              "options": [
                  "Correct the affected source-answer Markdown and regenerate.",
                  "Supply missing source-bound semantic assessment/curation in the exception resolution, preserving scope and evidence limits.",
                  "Retry unchanged only when the failure was transient; approval must not assert missing facts."
              ]}
    Path(destination).write_bytes(encoded(report))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate_operational(items, docs):
    required = {"id", "path", "section", "match", "predicate", "value"}
    if not isinstance(items, list) or len(items) > 5000:
        raise ValueError("Invalid curated operational array")
    seen = set()
    for item in items:
        if (not isinstance(item, dict) or set(item) != required or
                any(not isinstance(item[key], str) or not item[key].strip() or
                    len(item[key]) > 20000 for key in required) or
                item["path"] not in docs or item["id"] in seen or
                any(not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", item[key])
                    for key in ("id", "predicate"))):
            raise ValueError("Invalid source-bound curated operational entry")
        seen.add(item["id"])
    return items


def validate_copilot(items, docs):
    if not isinstance(items, list):
        raise ValueError("Invalid Copilot interpretation list")
    required = {"origin", "id", "path", "section", "match", "entity", "predicate", "value"}
    optional = {"kind", "condition", "order", "object", "setting", "settingValue", "unit", "valueBasis",
                "evidence_scope", "owner_confirmation", "owner_confirmation_provenance"}
    identities, entities = set(), {}
    for item in items:
        if not isinstance(item, dict) or not required <= item.keys() or item.keys() - required - optional:
            raise ValueError("Invalid Copilot interpretation fields")
        if item["origin"] != "copilot" or any(
                not isinstance(item[field], str) or not item[field].strip()
                for field in required - {"entity"}):
            raise ValueError("Invalid Copilot interpretation values")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", item["id"]) or item["id"] in identities:
            raise ValueError("Invalid or duplicate Copilot interpretation ID")
        identities.add(item["id"])
        if item["path"] not in docs:
            raise ValueError("Copilot interpretation outside source inventory")
        if not isinstance(item.get("kind", "narrative-or-list"), str) or item.get(
                "kind", "narrative-or-list") not in {"narrative-or-list", "table", "code"}:
            raise ValueError("Invalid Copilot source block kind")
        if item.get("evidence_scope", "section") not in {"section", "matched-block"}:
            raise ValueError("Invalid Copilot evidence scope")
        if "condition" in item and (not isinstance(item["condition"], str) or not item["condition"].strip()):
            raise ValueError("Invalid Copilot interpretation condition")
        owner_confirmation_fields = {"owner_confirmation", "owner_confirmation_provenance"}
        if owner_confirmation_fields.intersection(item) and (
                not owner_confirmation_fields <= item.keys() or
                not isinstance(item["owner_confirmation"], str) or
                not item["owner_confirmation"].strip() or
                item["owner_confirmation_provenance"] != "user-clarification-recorded-in-session"):
            raise ValueError("Invalid owner-confirmation provenance")
        if "order" in item and (type(item["order"]) is not int or item["order"] < 1):
            raise ValueError("Invalid Copilot process order")
        setting_fields = {"setting", "settingValue", "valueBasis"}
        if setting_fields.intersection(item) and not setting_fields <= item.keys():
            raise ValueError("Incomplete Copilot setting assertion")
        if setting_fields <= item.keys() and (
                not isinstance(item["setting"], str) or not item["setting"].strip() or
                type(item["settingValue"]) not in {str, int, bool} or
                isinstance(item["settingValue"], str) and not item["settingValue"].strip() or
                not isinstance(item["valueBasis"], str) or
                item["valueBasis"] not in {"parameter-default", "configured-target", "documented-maximum"}):
            raise ValueError("Invalid Copilot setting assertion")
        if "unit" in item and (not setting_fields <= item.keys() or
                              not isinstance(item["unit"], str) or
                              item["unit"] not in {"second", "minute", "hour", "day"} or
                              type(item["settingValue"]) is not int):
            raise ValueError("Invalid Copilot setting unit")
        doc = docs[item["path"]]
        for field in ("entity", "object"):
            if field not in item:
                continue
            entity = item[field]
            if not isinstance(entity, dict) or set(entity) != {"id", "label", "kind"} or any(
                    not isinstance(value, str) or not value.strip() for value in entity.values()):
                raise ValueError("Invalid Copilot entity")
            if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", entity["id"]):
                raise ValueError("Invalid Copilot entity ID")
            identity = (doc["audience"], tuple(sorted(doc["meta"]["assistants"])), entity["id"])
            declaration = (entity["label"], entity["kind"])
            if identity in entities and entities[identity] != declaration:
                raise ValueError("Conflicting Copilot entity declaration")
            entities[identity] = declaration


def load_copilot():
    interpretations = load(GRAPH / "config" / "copilot-interpretations.json")
    if not isinstance(interpretations, list):
        raise ValueError("Copilot configuration must contain an interpretation array")
    bundles = {}
    for category in ("resource-types", "shared"):
        directory = GRAPH / "config" / category
        if directory.is_symlink():
            raise ValueError("Symlink in Copilot bundle configuration")
        for path in sorted(directory.glob("*.json")):
            if path.is_symlink() or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", path.stem):
                raise ValueError("Invalid Copilot bundle configuration path")
            items = load(path)
            if not isinstance(items, list):
                raise ValueError("Copilot bundle must contain an interpretation array")
            bundles[(category, path.stem)] = items
            interpretations += items
    return interpretations, bundles


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


def load_profiles(graph=None):
    graph = GRAPH if graph is None else graph
    profiles = []
    required = {
        "profile_id", "label", "profile_kind", "covers", "audience", "assistants",
        "coverage", "environment_scope", "maintainer", "revision", "status",
    }
    for folder, profile_kind in (("resource-types", "resource-type"), ("shared", "shared-topic")):
        directory = graph / "profiles" / folder
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"Invalid profile directory: {directory}")
        for path in sorted(directory.glob("*.json")):
            if path.is_symlink() or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", path.stem):
                raise ValueError(f"Invalid profile path: {path}")
            item = load(path)
            if not isinstance(item, dict) or set(item) != required:
                raise ValueError(f"Invalid profile fields: {path}")
            if (item["profile_kind"] != profile_kind or
                    not isinstance(item["profile_id"], str) or
                    not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", item["profile_id"]) or
                    item["profile_id"] != ("resource-type-" if profile_kind == "resource-type"
                                           else "shared-topic-") + path.stem or
                    not isinstance(item["label"], str) or not item["label"].strip() or
                    not isinstance(item["covers"], list) or not item["covers"] or
                    any(not isinstance(ref, str) or not ref for ref in item["covers"]) or
                    len(item["covers"]) != len(set(item["covers"])) or
                    not isinstance(item["audience"], str) or
                    item["audience"] not in {"guide", "admin"} or
                    not isinstance(item["assistants"], list) or not item["assistants"] or
                    any(not isinstance(value, str) or not value for value in item["assistants"]) or
                    len(item["assistants"]) != len(set(item["assistants"])) or
                    item["coverage"] != "referenced-bundles-only" or
                    not isinstance(item["environment_scope"], list) or
                    any(not isinstance(value, str) or not value for value in item["environment_scope"]) or
                    not isinstance(item["maintainer"], str) or not item["maintainer"].strip() or
                    type(item["revision"]) is not int or item["revision"] < 1 or
                    item["status"] != "proposed"):
                raise ValueError(f"Invalid profile values: {path}")
            profiles.append(item)
    if not profiles:
        raise ValueError("At least one knowledge profile is required")
    if len({item["profile_id"] for item in profiles}) != len(profiles):
        raise ValueError("Duplicate knowledge profile ID")
    return profiles


def build_profiles(definitions, records):
    profile_records = []
    profile_by_bundle = {}
    covered_entities = {}
    member_relationships = {}
    bundles = {identity: record for identity, record in records.items()
               if record.get("@type") == "Entity" and record.get("kind") in {
                   "resource-knowledge-bundle", "shared-topic-bundle"}}
    for item in definitions:
        profile_id = iri("profiles", item["profile_id"])
        for bundle_id in item["covers"]:
            bundle = records.get(bundle_id)
            expected_kind = ("resource-knowledge-bundle" if item["profile_kind"] == "resource-type"
                             else "shared-topic-bundle")
            if bundle is None or bundle_id not in bundles or bundle["kind"] != expected_kind:
                raise ValueError(f"Unknown or mismatched profile bundle reference: {bundle_id}")
            if (bundle["audience"] != item["audience"] or
                    set(bundle["assistants"]) != set(item["assistants"])):
                raise ValueError(f"Profile scope does not match referenced bundle: {bundle_id}")
            if bundle["label"] != item["label"]:
                raise ValueError(f"Profile label must match its referenced bundle: {bundle_id}")
            if bundle_id in profile_by_bundle:
                raise ValueError(f"Bundle is covered by more than one profile: {bundle_id}")
            profile_by_bundle[bundle_id] = profile_id
            members = set(bundle.get("members", []))
            entities = set()
            for member_id in members:
                member = records.get(member_id)
                if member is None or member.get("audience") != item["audience"] or (
                        set(member.get("assistants", [])) != set(item["assistants"])):
                    raise ValueError(f"Profile bundle contains an unavailable member: {member_id}")
                if member.get("@type") == "Entity":
                    continue
                elif member.get("@type") == "Claim":
                    entities.add(member["subject"])
                elif member.get("@type") == "Relationship":
                    member_relationships.setdefault(member_id, set()).add(profile_id)
            covered_entities[profile_id] = entities
        if item["environment_scope"]:
            for identity in item["environment_scope"]:
                environment = records.get(identity)
                if (environment is None or environment.get("@type") != "Entity" or
                        environment.get("kind") != "environment" or
                        environment.get("audience") != item["audience"] or
                        environment.get("assistants") != item["assistants"]):
                    raise ValueError(f"Invalid profile environment scope: {identity}")
        profile_records.append({
            "@id": profile_id, "@type": "KnowledgeProfile", "profileId": item["profile_id"],
            "profileKind": item["profile_kind"], "label": item["label"],
            "covers": item["covers"], "coverage": item["coverage"],
            "environmentScope": item["environment_scope"], "maintainer": item["maintainer"],
            "revision": item["revision"], "status": item["status"],
            "audience": item["audience"], "assistants": item["assistants"],
        })
    if set(profile_by_bundle) != set(bundles):
        missing = sorted(set(bundles) - set(profile_by_bundle))
        raise ValueError(f"Every resource/shared bundle requires exactly one profile: {missing}")

    entity_profiles = {}
    for profile_id, entities in covered_entities.items():
        for identity in entities:
            entity_profiles.setdefault(identity, []).append(profile_id)
    profile_links = {}
    for relation in records.values():
        if (relation.get("@type") != "Relationship" or
                relation.get("predicate") not in PROFILE_DEPENDENCY_PREDICATES):
            continue
        sources = member_relationships.get(relation["@id"], set())
        targets = entity_profiles.get(relation["object"], [])
        for source in sources:
            for target in targets:
                if source == target:
                    continue
                source_profile = next(record for record in profile_records if record["@id"] == source)
                target_profile = next(record for record in profile_records if record["@id"] == target)
                if (source_profile["audience"] != target_profile["audience"] or
                        set(source_profile["assistants"]) != set(target_profile["assistants"]) or
                        source_profile["audience"] != relation["audience"] or
                        set(source_profile["assistants"]) != set(relation["assistants"])):
                    continue
                profile_links.setdefault((source, target), set()).add(relation["@id"])
    relationship_records = []
    for (source, target), backing_relationships in sorted(profile_links.items()):
        identity = digest((source + "\n" + target).encode("utf-8"))[:24]
        source_profile = next(record for record in profile_records if record["@id"] == source)
        relationship_records.append({
            "@id": iri("profile-relationships", identity), "@type": "ProfileRelationship",
            "subject": source, "object": target, "predicate": "depends-on-profile",
            "backedBy": sorted(backing_relationships),
            "audience": source_profile["audience"], "assistants": source_profile["assistants"],
            "status": "derived-navigation-index-not-independent-assertion",
        })
    return profile_records, relationship_records


INTERPRETATION_REVIEW_FIELDS = {
    "interpretationVerificationStatus",
    "interpretationVerificationBasis",
    "interpretationVerificationAssessments",
}


def interpretation_hash_record(record):
    """Keep the review-state stamp out of the hash of the reviewed interpretation."""
    normalized = {key: value for key, value in record.items()
                  if key not in INTERPRETATION_REVIEW_FIELDS}
    if normalized.get("status") == "source-verified-copilot-interpretation":
        normalized["status"] = "unverified-copilot-interpretation"
    return normalized


def assess_sections(items, docs, structured_records, structured_references=None):
    """Apply individually authored, hash-bound assessments, never record-count heuristics."""
    if not isinstance(items, list):
        raise ValueError("Section assessments must be an array")
    all_records = {record["@id"]: record for values in structured_records.values() for record in values}
    fields = structured_records["claims/semantic-table-fields.jsonld"]
    report, assessed, identities = [], {}, set()
    required = {"id", "author", "path", "section", "section_sha256", "records_sha256", "disposition",
                "facets", "missing_interpretations", "source_gaps"}
    for item in items:
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError("Invalid section assessment fields")
        for field in ("id", "author", "path", "section", "section_sha256", "records_sha256", "disposition"):
            if not isinstance(item[field], str) or not item[field].strip():
                raise ValueError("Invalid section assessment value")
        if (not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", item["id"]) or
                item["id"] in identities or item["author"] != "copilot" or
                not re.fullmatch(r"[0-9a-f]{64}", item["section_sha256"]) or
                not re.fullmatch(r"[0-9a-f]{64}", item["records_sha256"]) or
                item["disposition"] not in {"covered-unverified", "missing-interpretation"}):
            raise ValueError("Invalid section assessment identity or disposition")
        identities.add(item["id"])
        for name in ("missing_interpretations", "source_gaps"):
            if not isinstance(item[name], list) or any(
                    not isinstance(value, str) or not value.strip() for value in item[name]):
                raise ValueError("Invalid section assessment gaps")
        if bool(item["missing_interpretations"]) != (item["disposition"] == "missing-interpretation"):
            raise ValueError("Section assessment must distinguish missing interpretation from source gaps")
        if not isinstance(item["facets"], list) or not item["facets"]:
            raise ValueError("Section assessment needs explicit semantic facets")
        for facet in item["facets"]:
            if (not isinstance(facet, dict) or set(facet) != {"aspect", "assessment", "records"} or
                    any(not isinstance(facet[key], str) or not facet[key].strip()
                        for key in ("aspect", "assessment")) or
                    not isinstance(facet["records"], list) or not facet["records"] or
                    any(not isinstance(selector, str) or
                        not re.fullmatch(r"(?:copilot|field):[a-z0-9]+(?:-[a-z0-9]+)*|"
                                         r"record:(?:(?:claims|semantic-table-fields|copilot-relationships|decisions|"
                                         r"resource-details|procedure-steps|procedure-relationships)/"
                                         r"|relationships/structure/)"
                                         r"[a-z0-9]+(?:-[a-z0-9]+)*",
                                         selector)
                        for selector in facet["records"])):
                raise ValueError("Invalid section assessment semantic facet")
        doc = docs.get(item["path"])
        entry = {**item, "status": "source-unavailable", "resolved_facets": []}
        report.append(entry)
        if doc is None:
            continue
        groups = [group for group in doc["blocks"]
                  if " > ".join(group[3]) == item["section"] or
                  " > ".join(group[3]).startswith(item["section"] + " > ")]
        text = "\n".join(line.rstrip("\r\n") for start, end, _, _ in groups
                         for line in doc["lines"][start:end])
        entry.update(audience=doc["audience"], assistants=doc["meta"]["assistants"],
                     source_sha256=doc["hash"], snapshot_commit=doc["commit"],
                     actual_section_sha256=digest(text.encode("utf-8")))
        if not groups or entry["actual_section_sha256"] != item["section_sha256"]:
            entry["status"] = "source-section-changed-or-unavailable"
            continue
        if not doc["commit"]:
            entry["status"] = "source-snapshot-uncommitted"
            continue

        def supported(record):
            refs = record.get("source", [])
            refs = refs if isinstance(refs, list) else [refs]
            evidence = [all_records.get(identity, {}) for identity in refs]
            subjects = [all_records.get(record[key], {}) for key in ("subject", "object") if key in record]
            return (record.get("@type") in {"Claim", "Relationship"} and
                    record.get("audience") == doc["audience"] and
                    sorted(record.get("assistants", [])) == sorted(doc["meta"]["assistants"]) and
                    bool(subjects) and all(subject.get("@type") == "Entity" and
                    subject.get("audience") == doc["audience"] and
                    sorted(subject.get("assistants", [])) == sorted(doc["meta"]["assistants"])
                    for subject in subjects) and
                    bool(evidence) and all(ev.get("@type") == "Evidence" and
                    ev.get("path") == item["path"] and ev.get("sha256") == doc["hash"] and
                    ev.get("snapshotCommit") == doc["commit"] and
                    ev.get("audience") == doc["audience"] and
                    sorted(ev.get("assistants", [])) == sorted(doc["meta"]["assistants"])
                    for ev in evidence) and
                    any(ev.get("section") == item["section"] or
                        ev.get("section", "").startswith(item["section"] + " > ") for ev in evidence))

        missing = False
        for facet in item["facets"]:
            bindings = []
            for selector in facet["records"]:
                kind, name = selector.split(":", 1)
                candidates = ([all_records.get(BASE + name, {})] if kind == "record" else
                              [all_records.get(iri("claims", "copilot-" + name), {})] if kind == "copilot" else
                              [record for record in fields if record["predicate"] == name])
                candidates = [record for record in candidates if supported(record)]
                if len(candidates) != 1:
                    missing = True
                    bindings.append({"selector": selector, "status": "unavailable-or-ambiguous"})
                else:
                    binding = {"selector": selector, "record": candidates[0]["@id"]}
                    relationship = all_records.get(iri("copilot-relationships", name)) if kind == "copilot" else None
                    if relationship:
                        if not supported(relationship):
                            missing = True
                            binding["status"] = "relationship-unavailable-in-source-scope"
                        binding["related_records"] = [relationship["@id"]]
                    bindings.append(binding)
            entry["resolved_facets"].append({"aspect": facet["aspect"], "bindings": bindings})
        entry["status"] = "records-unavailable-or-ambiguous" if missing else item["disposition"]
        bound_ids = {binding["record"] for facet in entry["resolved_facets"] for binding in facet["bindings"]
                     if "record" in binding}
        bound_ids.update(identity for facet in entry["resolved_facets"] for binding in facet["bindings"]
                         for identity in binding.get("related_records", []))
        bound_ids.update(all_records[identity][key] for identity in list(bound_ids)
                         for key in ("subject", "object") if key in all_records[identity] and
                         all_records[identity][key] in all_records)
        entry["actual_records_sha256"] = digest(encoded([
            interpretation_hash_record(all_records[key]) for key in sorted(bound_ids)]))
        entry["hash_bound_record_ids"] = sorted(bound_ids)
        if not missing and entry["actual_records_sha256"] != item["records_sha256"]:
            entry["status"] = "interpretation-records-changed"
        if entry["status"] == "covered-unverified":
            for start, _, kind, _ in groups:
                if kind != "whitespace":
                    block_records = ((structured_references or {}).get((item["path"], start), [])
                                     if structured_references is not None else bound_ids)
                    if not bound_ids.intersection(block_records):
                        continue
                    key = (item["path"], start)
                    if key in assessed:
                        raise ValueError("Overlapping covered section assessments")
                    assessed[key] = item["id"]
    return report, assessed


def apply_interpretation_verification(assessments, structured_records):
    """Stamp only interpretations bound by a current, hash-matched source assessment."""
    records = {record["@id"]: record for values in structured_records.values() for record in values}
    reviewed = defaultdict(set)
    for assessment in assessments:
        if (assessment["status"] != "covered-unverified" or
                assessment.get("source_markdown_verification_status") != "verified" or
                assessment.get("actual_records_sha256") != assessment.get("records_sha256") or
                not assessment.get("snapshot_commit")):
            continue
        for facet in assessment["resolved_facets"]:
            for binding in facet["bindings"]:
                identity = binding.get("record")
                record = records.get(identity)
                if (binding.get("selector", "").startswith("copilot:") and record and
                        record.get("@type") == "Claim" and
                        record.get("status") == "unverified-copilot-interpretation"):
                    reviewed[identity].add(assessment["id"])
                for related_id in binding.get("related_records", []):
                    related = records.get(related_id)
                    if (related and related.get("@type") == "Relationship" and
                            related.get("status") == "unverified-copilot-interpretation"):
                        reviewed[related_id].add(assessment["id"])

    entity_uses = defaultdict(list)
    for identity, record in records.items():
        if record.get("@type") not in {"Claim", "Relationship"} or record.get("status") not in {
                "unverified-copilot-interpretation", "source-verified-copilot-interpretation"}:
            continue
        for field in ("subject", "object"):
            target = record.get(field)
            if target in records and records[target].get("status") == "unverified-copilot-interpretation":
                entity_uses[target].append(identity)

    for entity_id, uses in entity_uses.items():
        if uses and all(identity in reviewed for identity in uses):
            reviewed[entity_id].update(
                assessment_id for identity in uses for assessment_id in reviewed[identity])

    counts = Counter()
    for identity, record in records.items():
        if record.get("status") not in {
                "unverified-copilot-interpretation", "source-verified-copilot-interpretation"}:
            continue
        assessment_ids = ([] if record.get("ownerConfirmationProvenance") else
                          sorted(reviewed.get(identity, [])))
        if assessment_ids:
            record["status"] = "source-verified-copilot-interpretation"
            record["interpretationVerificationStatus"] = "source-verified"
            record["interpretationVerificationBasis"] = "hash-bound-faceted-source-assessment"
            record["interpretationVerificationAssessments"] = assessment_ids
        else:
            record["interpretationVerificationStatus"] = "not-assessed"
            record["interpretationVerificationBasis"] = (
                "no-current-hash-bound-faceted-source-assessment")
            record["interpretationVerificationAssessments"] = []
        counts[(record["@type"], record["interpretationVerificationStatus"])] += 1
    return counts


def review_assessment_gaps(assessments, review_config):
    """Classify each authored source-gap note without converting it into approval."""
    categories = {
        "documented-boundary", "owner-confirmed-guidance", "planned-not-implemented",
        "rationale-not-specified", "requires-authorized-evidence",
        "requires-upstream-source-verification", "source-detail-not-specified",
        "source-scope-limit", "unresolved-source-question",
    }
    def dispositions_for(item):
        labels = set(item["categories"])
        mapping = [
            ("owner-confirmed-guidance", "owner-confirmed-scope-only"),
            ("planned-not-implemented", "planned-not-implemented"),
            ("unresolved-source-question", "open-source-question"),
            ("source-detail-not-specified", "open-source-detail"),
            ("requires-upstream-source-verification", "requires-upstream-source-verification"),
            ("requires-authorized-evidence", "requires-external-evidence"),
            ("source-scope-limit", "source-scope-limit"),
            ("documented-boundary", "documented-limit"),
            ("rationale-not-specified", "no-further-rationale-recorded"),
        ]
        return [disposition for category, disposition in mapping if category in labels]
    if not isinstance(review_config, dict) or set(review_config) != {"items"} or not isinstance(
            review_config["items"], list):
        raise ValueError("Invalid assessment gap review configuration")
    assessment_by_id = {item["id"]: item for item in assessments}
    seen = set()
    dispositions = {}
    for item in review_config["items"]:
        required = {"assessment_id", "gap_index", "issue_key", "categories"}
        optional = {"related_issue_keys", "owner_confirmation", "owner_confirmation_provenance"}
        if not isinstance(item, dict) or not required <= item.keys() or item.keys() - required - optional:
            raise ValueError("Invalid assessment gap review entry")
        assessment_id, index = item["assessment_id"], item["gap_index"]
        identity = (assessment_id, index)
        assessment = assessment_by_id.get(assessment_id)
        if (assessment is None or type(index) is not int or index < 0 or
                index >= len(assessment["source_gaps"]) or identity in seen or
                not isinstance(item["issue_key"], str) or not re.fullmatch(
                    r"[a-z0-9]+(?:-[a-z0-9]+)*", item["issue_key"]) or
                not isinstance(item["categories"], list) or not item["categories"] or
                any(not isinstance(category, str) for category in item["categories"]) or
                len(set(item["categories"])) != len(item["categories"]) or
                any(category not in categories for category in item["categories"])):
            raise ValueError("Invalid assessment gap review identity or classification")
        if "owner_confirmation" in item and (
                "owner-confirmed-guidance" not in item["categories"] or
                not isinstance(item["owner_confirmation"], str) or not item["owner_confirmation"].strip()):
            raise ValueError("Owner confirmation must be explicit and separately scoped")
        if ("owner-confirmed-guidance" in item["categories"] and
                ("owner_confirmation" not in item or
                 item.get("owner_confirmation_provenance") != "user-clarification-recorded-in-session")):
            raise ValueError("Owner-confirmed guidance requires its owner-confirmation provenance")
        if "owner_confirmation_provenance" in item and item[
                "owner_confirmation_provenance"] != "user-clarification-recorded-in-session":
            raise ValueError("Invalid owner-confirmation provenance")
        related = item.get("related_issue_keys", [])
        if (not isinstance(related, list) or
                any(not isinstance(key, str) or not re.fullmatch(
                    r"[a-z0-9]+(?:-[a-z0-9]+)*", key) for key in related) or
                len(related) != len(set(related)) or
                item["issue_key"] in related):
            raise ValueError("Invalid related source-gap issue keys")
        seen.add(identity)
        dispositions[identity] = {**item, "dispositions": dispositions_for(item),
                                  "issue_keys": [item["issue_key"], *related]}
    expected = {(assessment["id"], index)
                for assessment in assessments for index in range(len(assessment["source_gaps"]))}
    if seen != expected:
        raise ValueError("Assessment gap review must classify every source-gap statement exactly once")

    items = []
    grouped = {}
    for assessment in assessments:
        for index, text in enumerate(assessment["source_gaps"]):
            identity = (assessment["id"], index)
            disposition = dispositions[identity]
            entry = {
                "id": f"{assessment['id']}-gap-{index + 1}",
                "assessment_id": assessment["id"],
                "issue_keys": disposition["issue_keys"],
                "path": assessment["path"],
                "section": assessment["section"],
                "audience": assessment.get("audience"),
                "assistants": assessment.get("assistants"),
                "source_snapshot_commit": assessment.get("snapshot_commit"),
                "source_sha256": assessment.get("source_sha256"),
                "source_markdown_verification_status": assessment.get(
                    "source_markdown_verification_status", "not-assessed"),
                "source_gap": text,
                "categories": disposition["categories"],
                "dispositions": disposition["dispositions"],
                "owner_confirmed": "owner_confirmation" in disposition,
            }
            if "owner_confirmation" in disposition:
                entry["owner_confirmation"] = disposition["owner_confirmation"]
                entry["owner_confirmation_provenance"] = disposition["owner_confirmation_provenance"]
            items.append(entry)
            for issue_key in disposition["issue_keys"]:
                issue = grouped.setdefault(issue_key, {
                    "issue_key": issue_key, "categories": set(),
                    "dispositions": set(), "statements": set(), "owner_confirmations": set(), "references": [],
                })
                issue["categories"].update(disposition["categories"])
                issue["dispositions"].update(disposition["dispositions"])
                issue["statements"].add(text)
                issue["references"].append({"assessment_id": assessment["id"], "path": assessment["path"],
                                             "section": assessment["section"], "gap_id": entry["id"]})
                if "owner_confirmation" in disposition:
                    issue["owner_confirmations"].add(disposition["owner_confirmation"])
    issues = [{
        **issue,
        "categories": sorted(issue["categories"]),
        "dispositions": sorted(issue["dispositions"]),
        "statements": sorted(issue["statements"]),
        "owner_confirmations": sorted(issue["owner_confirmations"]),
        "references": sorted(issue["references"], key=lambda ref: (ref["path"], ref["section"])),
    } for _, issue in sorted(grouped.items())]
    return {
        "status": "categorized-source-review-not-verification",
        "note": "Every authored gap note is classified and source-section-bound. Owner confirmations record intent or guidance only; they do not prove implementation or live state. Categories may overlap. Repeated issue keys are grouped without dropping section-specific evidence.",
        "summary": {
            "source_gap_statement_count": len(items),
            "primary_issue_key_count": len({item["issue_keys"][0] for item in items}),
            "issue_group_count": len(issues),
            "cross_cutting_issue_group_count": sum(len(issue["references"]) > 1 for issue in issues),
            "owner_confirmed_statement_count": sum(item["owner_confirmed"] for item in items),
            "planned_not_implemented_statement_count": sum(
                "planned-not-implemented" in item["categories"] for item in items),
            "disposition_statement_counts": dict(sorted(Counter(
                disposition for item in items for disposition in item["dispositions"]).items())),
            "category_statement_counts": dict(sorted(Counter(
                category for item in items for category in item["categories"]).items())),
        },
        "items": items,
        "issues": issues,
    }


def iri(kind, name):
    return BASE + kind + "/" + quote(name, safe="-._~")


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE).stdout


def source_files(directories):
    result = []
    for directory in directories:
        root = ROOT / directory
        if root.is_symlink() or not root.is_dir():
            raise ValueError(f"Invalid source directory: {directory}")
        for path in root.rglob("*"):
            if path.is_symlink():
                raise ValueError(f"Symlink in source tree: {path}")
            if path.is_file() and path.suffix.lower() == ".md":
                result.append(path.relative_to(ROOT).as_posix())
    return sorted(result)


def metadata(lines):
    if not lines or lines[0].strip() != "---":
        raise ValueError("Missing frontmatter")
    values = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return values
        key, value = line.split(":", 1)
        if key in values:
            raise ValueError(f"Duplicate metadata key: {key}")
        values[key] = json.loads(value.strip())
    raise ValueError("Unterminated frontmatter")


def blocks(lines):
    """Partition every line, respecting headings, frontmatter and fenced code."""
    groups = []
    start = 0
    frontmatter = bool(lines and lines[0].strip() == "---")
    section = []
    i = 0
    if frontmatter:
        i = 1
        while i < len(lines) and lines[i].strip() != "---":
            i += 1
        if i == len(lines):
            raise ValueError("Unterminated frontmatter")
        groups.append((0, i + 1, "frontmatter", []))
        i += 1
    while i < len(lines):
        start = i
        line = lines[i]
        heading = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
        fence = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if heading:
            level = len(heading.group(1))
            section = section[:level - 1]
            section.append(heading.group(2))
            i += 1
            kind = "heading"
        elif fence:
            marker = fence.group(1)
            i += 1
            while i < len(lines):
                if re.match(r"^ {0,3}" + re.escape(marker[0]) + "{" + str(len(marker)) + r",}\s*$", lines[i]):
                    i += 1
                    break
                i += 1
            kind = "code"
        elif not line.strip():
            i += 1
            while i < len(lines) and not lines[i].strip():
                i += 1
            kind = "whitespace"
        elif re.fullmatch(r'<a\s+id="[^"]+"\s*></a>', line.strip()):
            i += 1
            while i < len(lines) and re.fullmatch(r'<a\s+id="[^"]+"\s*></a>', lines[i].strip()):
                i += 1
            kind = "navigation-anchor"
        else:
            i += 1
            while i < len(lines) and lines[i].strip() and not re.match(r"^(#{1,6})\s+|^ {0,3}(`{3,}|~{3,})", lines[i]):
                i += 1
            kind = "table" if line.lstrip().startswith("|") else "narrative-or-list"
        groups.append((start, i, kind, section.copy()))
    return groups


def source_extraction_is_complete(block_status_counts, invalidated_records):
    """Source completeness is independent of factual or live-environment verification."""
    incomplete = {
        "partially-curated", "preserved-semantic-extraction-unresolved",
        "structurally-extracted-review-required",
    }
    return not invalidated_records and not any(block_status_counts.get(status, 0) for status in incomplete)


def require_complete_review(source_complete, coverage, invalidated, assessments, conflicts):
    unresolved = [{"path": item["path"], "id": item["id"], "status": item["status"]}
                  for item in assessments if item["status"] != "covered-unverified"]
    if source_complete and not unresolved and not conflicts:
        return
    gaps = [{"path": source["path"], "start_line": block["start_line"],
             "end_line": block["end_line"], "status": block["status"]}
            for source in coverage for block in source["blocks"]
            if block["status"] in {"partially-curated", "preserved-semantic-extraction-unresolved",
                                   "structurally-extracted-review-required"}]
    raise GraphReviewRequired("Graph extraction requires Markdown review before publication",
                              gaps + invalidated + unresolved + [
                                  {"id": item["@id"], "reason": "unresolved graph conflict"} for item in conflicts])


def build():
    config = load(GRAPH / "config" / "sources.json")
    baseline = config["comparison_baseline"]
    curation_baseline = config["curation_baseline"]
    if not re.fullmatch(r"[0-9a-f]{40}", baseline):
        raise ValueError("Invalid source comparison baseline")
    if not re.fullmatch(r"[0-9a-f]{40}", curation_baseline):
        raise ValueError("Invalid curation baseline")
    git("cat-file", "-e", baseline + "^{commit}")
    git("cat-file", "-e", curation_baseline + "^{commit}")
    curated = load(GRAPH / "config" / "curated-sql-gsa.json")
    curated_hashes = load(GRAPH / "config" / "curated-line-hashes.json")
    if set(curated_hashes) != {item["id"] for item in curated["claims"]}:
        raise ValueError("Curated source-line fingerprints do not match the claim inventory")
    context = load(GRAPH / "model" / "context.jsonld")["@context"]
    commit = os.environ.get("KNOWLEDGE_SOURCE_COMMIT") or git(
        "log", "-1", "--format=%H", "HEAD", "--", *config["directories"]).decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("No committed source snapshot found")
    if os.environ.get("KNOWLEDGE_SOURCE_COMMIT"):
        git("merge-base", "--is-ancestor", commit, "HEAD")
    publication_review = approved_publication(commit)
    source_verification = load(GRAPH / "config" / "source-verification.json")
    if (set(source_verification) != {"schema_version", "status", "scope", "basis", "verified_at",
                                     "snapshot_commit"} or
            source_verification["schema_version"] != 1 or
            source_verification["status"] != "verified" or
            source_verification["scope"] != "source-markdown-content" or
            source_verification["basis"] != "user-confirmed-source-markdown-review" or
            not isinstance(source_verification["verified_at"], str) or
            not re.fullmatch(r"[0-9a-f]{40}", source_verification["snapshot_commit"])):
        raise ValueError("Invalid source Markdown verification record")
    source_verification_matches = source_verification["snapshot_commit"] == commit
    files = source_files(config["directories"])
    path_history = config.get("source_path_history", {})
    if (not isinstance(path_history, dict) or any(
            destination not in files or not re.fullmatch(r"guides/[a-z0-9-]+\.md", destination) or
            not isinstance(origin, str) or
            not re.fullmatch(r"admin/(?:guides|reference)/[a-z0-9-]+\.md", origin)
            for destination, origin in path_history.items())):
        raise ValueError("Invalid source path migration history")
    docs = {}
    outputs = {}
    for path in files:
        data = (ROOT / path).read_bytes()
        text = data.decode("utf-8")
        lines = text.splitlines(keepends=True)
        meta = metadata(lines)
        if publication_review and (
                meta.get("schema_version") != 1 or meta.get("document_type") != "guide" or
                meta.get("review_status") != "approved" or meta.get("verification_status") != "verified" or
                not isinstance(meta.get("id"), str) or not meta["id"] or
                not isinstance(meta.get("reviewed_by"), str) or not meta["reviewed_by"] or
                not isinstance(meta.get("reviewed_at"), str) or not meta["reviewed_at"]):
            raise GraphReviewRequired("Pinned source Markdown lacks valid approved guide metadata",
                                      [{"path": path, "status": "invalid-publication-metadata"}])
        audience = "admin" if path.startswith("admin/") else "guide"
        if audience == "admin" and meta.get("assistants") != ["platform-admin"]:
            raise ValueError(f"Invalid admin audience: {path}")
        if audience == "guide" and "platform-admin" in meta.get("assistants", []):
            raise ValueError(f"Invalid guide audience: {path}")
        original = subprocess.run(["git", "show", f"{commit}:{path}"], cwd=ROOT,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        historical_path = path_history.get(path, path)
        comparison = subprocess.run(["git", "show", f"{baseline}:{historical_path}"], cwd=ROOT,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        curation = comparison if baseline == curation_baseline else subprocess.run(
            ["git", "show", f"{curation_baseline}:{historical_path}"], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        snapshot_commit = commit if original.returncode == 0 and original.stdout == data else None
        if os.environ.get("KNOWLEDGE_SOURCE_COMMIT") and snapshot_commit is None:
            raise ValueError(f"Source differs from pinned publication commit: {path}")
        snapshot_path = "evidence/snapshots/" + path + ".txt"
        outputs[snapshot_path] = data
        docs[path] = {"data": data, "lines": lines, "meta": meta, "audience": audience,
                      "hash": digest(data), "commit": snapshot_commit, "snapshot": snapshot_path,
                      "blocks": blocks(lines),
                      "baseline_lines": comparison.stdout.decode("utf-8").splitlines(keepends=True)
                      if comparison.returncode == 0 else [],
                      "curation_lines": curation.stdout.decode("utf-8").splitlines(keepends=True)
                      if curation.returncode == 0 else []}
    source_markdown_verified = ((publication_review is not None or source_verification_matches) and
                                all(doc["commit"] == commit for doc in docs.values()))
    source_verification_status = "verified" if source_markdown_verified else "not-assessed"
    source_verification_basis = ("human-approved-markdown-publication" if publication_review else
                                source_verification["basis"] if source_markdown_verified
                                else "snapshot-not-matched-to-user-verification")
    for doc in docs.values():
        doc["source_verification_status"] = source_verification_status
        doc["source_verification_basis"] = source_verification_basis
    evidence, claims, entities, relationships = [], [], [], []
    invalidated = []
    evidence_by_claim = {}
    for item in curated["claims"]:
        doc = docs[item["source"]]
        matches = [i for i, line in enumerate(doc["lines"]) if item["match"] in line]
        if item["id"] in {"sql-subnet", "sql-endpoint", "sql-verification", "sql-interruption"}:
            matches = [i for i in matches if any(
                b[0] <= i < b[1] and "How do I add an Azure SQL server (SQL Database) to GSA?" in b[3]
                for b in doc["blocks"])]
        if len(matches) != 1:
            invalidated.append({"id": item["id"], "path": item["source"],
                                "reason": f"expected one curated source line; found {len(matches)}"})
            continue
        i = matches[0]
        if digest(doc["lines"][i].rstrip("\r\n").encode("utf-8")) != curated_hashes[item["id"]]:
            invalidated.append({"id": item["id"], "path": item["source"],
                                "reason": "curated source line changed"})
            continue
        section = next(b[3] for b in doc["blocks"] if b[0] <= i < b[1])
        ev_id = iri("evidence", item["id"])
        ev = {"@id": ev_id, "@type": "Evidence", "audience": doc["audience"],
              "assistants": doc["meta"]["assistants"],
              "path": item["source"], "section": " > ".join(section),
              "startLine": i + 1, "endLine": i + 1, "sha256": doc["hash"],
              "sourceVerificationStatus": doc["source_verification_status"],
              "sourceVerificationBasis": doc["source_verification_basis"],
              "text": doc["lines"][i].rstrip("\r\n")}
        if doc["commit"]:
            ev["snapshotCommit"] = doc["commit"]
        for field, key in [("source_repository", "declaredSourceRepository"),
                           ("source_path", "declaredSourcePath"), ("source_commit", "declaredSourceCommit")]:
            if field in doc["meta"]:
                ev[key] = doc["meta"][field]
        evidence.append(ev)
        evidence_by_claim[item["id"]] = ev
        claim = {"@id": iri("claims", item["id"]), "@type": "Claim",
                 "subject": iri("entities", item["subject"]), "source": ev_id,
                 "text": ev["text"], "audience": ev["audience"],
                 "assistants": ev["assistants"], "status": "documented"}
        for field in ("predicate", "value", "condition", "order"):
            if field in item:
                claim[field] = item[field]
        claims.append(claim)
    for item in curated["entities"]:
        if item["evidence"] not in evidence_by_claim:
            invalidated.append({"id": item["id"], "reason": "entity evidence unavailable",
                                "depends_on": item["evidence"]})
            continue
        ev = evidence_by_claim[item["evidence"]]
        entities.append({"@id": iri("entities", item["id"]), "@type": "Entity",
                         "label": item["label"], "kind": item["kind"], "source": ev["@id"],
                         "audience": ev["audience"], "assistants": ev["assistants"]})
    for item in curated["relationships"]:
        if item["evidence"] not in evidence_by_claim or any(
                iri("entities", item[key]) not in {e["@id"] for e in entities} for key in ("subject", "object")):
            invalidated.append({"id": item["id"], "reason": "relationship evidence or entity unavailable",
                                "depends_on": [item["evidence"], item["subject"], item["object"]]})
            continue
        ev = evidence_by_claim[item["evidence"]]
        relationships.append({"@id": iri("relationships", item["id"]), "@type": "Relationship",
                              "subject": iri("entities", item["subject"]), "object": iri("entities", item["object"]),
                              "predicate": item["predicate"], "source": ev["@id"],
                              "audience": ev["audience"], "assistants": ev["assistants"], "status": "documented"})
    ids = {e["@id"]: e for e in entities}
    retained_claims = []
    for record in claims:
        if record["subject"] not in ids:
            invalidated.append({"id": record["@id"].rsplit("/", 1)[-1],
                                "reason": "claim subject evidence unavailable",
                                "depends_on": record["subject"]})
        else:
            retained_claims.append(record)
    claims = retained_claims
    used_evidence = {record["source"] for record in claims + entities + relationships}
    evidence = [record for record in evidence if record["@id"] in used_evidence]
    for record in claims + relationships:
        for field in ("subject", "object"):
            if field in record and (record[field] not in ids or ids[record[field]]["audience"] != record["audience"]):
                raise ValueError(f"Unresolved or cross-audience {field}: {record['@id']}")
    spec = importlib.util.spec_from_file_location("graph_structured", Path(__file__).with_name("graph-structured.py"))
    structured = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(structured)
    copilot, bundles = load_copilot()
    validate_copilot(copilot, docs)
    structured_records, structured_references, operational_invalidations = structured.extract(
        docs, validate_operational(load(GRAPH / "config" / "curated-operational.json"), docs) + copilot,
        load(GRAPH / "config" / "conflicts.json"), blocks)
    invalidated.extend(operational_invalidations)
    interpretation_records = {record["@id"]: record for record in
                              structured_records["claims/copilot-interpretations.jsonld"]}
    interpretation_relationships = {record["@id"]: record for record in
                                   structured_records["claims/copilot-relationships.jsonld"]}
    organization = []
    for (category, name), items in bundles.items():
        by_scope = {}
        for item in items:
            doc = docs[item["path"]]
            scope = (doc["audience"], tuple(sorted(doc["meta"]["assistants"])))
            by_scope.setdefault(scope, [])
            claim = interpretation_records.get(iri("claims", "copilot-" + item["id"]))
            if claim is None:
                continue
            by_scope[scope].append(claim)
        for (audience, assistants), bundle_claims in sorted(by_scope.items()):
            scope_key = audience + "-" + digest("|".join(assistants).encode("utf-8"))[:20]
            key = name + "-" + scope_key
            sources, members = set(), set()
            for claim in bundle_claims:
                sources.add(claim["source"])
                members.update((claim["@id"], claim["subject"]))
                relation = interpretation_relationships.get(iri(
                    "copilot-relationships", claim["@id"].rsplit("/", 1)[-1].removeprefix("copilot-")))
                if relation:
                    members.update((relation["@id"], relation["object"]))
            file = category + "/" + key + ".jsonld"
            structured_records[file] = [{
                "@id": iri(category, key), "@type": "Entity",
                "kind": "resource-knowledge-bundle" if category == "resource-types" else "shared-topic-bundle",
                "label": name, "source": sorted(sources), "members": sorted(members),
                "audience": audience, "assistants": list(assistants),
                "status": "navigation-only-unverified-interpretations",
            }] if bundle_claims else []
            organization.append({"configuration": "config/" + category + "/" + name + ".json",
                                 "graph": file, "audience": audience, "assistants": list(assistants),
                                 "claim_count": len(bundle_claims)})
    graph_records = {record["@id"]: record for record in
                     entities + claims + relationships + evidence +
                     [item for values in structured_records.values() for item in values]}
    profile_definitions = load_profiles()
    profile_records, profile_relationships = build_profiles(profile_definitions, graph_records)
    diagram_records, diagram_companion_coverage = build_diagrams(graph_records, profile_records, commit)
    outputs["coverage/diagram-companions.json"] = encoded(diagram_companion_coverage)
    for path, records in diagram_records.items():
        structured_records.setdefault(path, []).extend(records)
        graph_records.update({record["@id"]: record for record in records})
    section_assessments, assessed_blocks = assess_sections(
        load(GRAPH / "config" / "section-assessments.json"), docs, structured_records,
        structured_references)
    for assessment in section_assessments:
        assessment["source_markdown_verification_status"] = source_verification_status
        assessment["source_markdown_verification_basis"] = source_verification_basis
    interpretation_verification_counts = apply_interpretation_verification(
        section_assessments, structured_records)
    gap_review = review_assessment_gaps(
        section_assessments, load(GRAPH / "config" / "assessment-gap-review.json"))
    coverage = []
    review_changes = []
    for path, doc in docs.items():
        relevant = [e for e in evidence if e["path"] == path]
        ranges = []
        for block_index, (start, end, kind, section) in enumerate(doc["blocks"]):
            matched = [e["@id"] for e in relevant if start < e["startLine"] <= end]
            semantic = structured_references.get((path, start), [])
            interpretations = [identity for identity in semantic if "/claims/copilot-" in identity]
            block_text = "".join(doc["lines"][start:end]).strip()
            context_records = []
            disposition_reason = None
            bound_records = [graph_records[identity] for identity in semantic if identity in graph_records]
            if kind == "frontmatter":
                status = "source-structure-extracted"
                disposition_reason = "Document metadata is represented on its document entity and source provenance."
            elif kind in {"heading", "navigation-anchor"}:
                status = "source-structure-extracted"
                disposition_reason = ("Heading establishes the represented document section."
                                      if kind == "heading" else
                                      "Author-defined HTML fragment identifiers are navigation anchors, not factual assertions.")
            elif kind == "whitespace":
                status = "non-semantic-whitespace"
                disposition_reason = "Whitespace is preserved for exact source reconstruction and contains no assertion."
            elif block_text in {
                    "The CloudOps guide documents these controls:",
                    "The SecOps guide documents these controls:"}:
                following = next((candidate for candidate in doc["blocks"][block_index + 1:]
                                  if candidate[2] != "whitespace"), None)
                if following and following[2] == "table" and following[3] == section:
                    context_records = structured_references.get((path, following[0]), [])
                    status = "source-context-preserved"
                    disposition_reason = (
                        "This sentence is a non-assertional lead-in to the immediately following "
                        "source table; the table's rows and fields carry the control details.")
                else:
                    status = None
            elif any(graph_records.get(identity, {}).get("kind") == "document" and
                     graph_records.get(identity, {}).get("descriptionSource")
                     for identity in semantic):
                status = "source-description-extracted"
                disposition_reason = (
                    "The exact source scope statement is represented on the document entity; it does not "
                    "stand in for detailed claims in other sections.")
            else:
                status = None
                normalized = " ".join(block_text.split())
                exact_claims = [record for record in bound_records
                                if record.get("@type") == "Claim" and
                                normalized in " ".join(record.get("text", "").split())]
                if exact_claims:
                    status = "source-claim-extracted"
                    disposition_reason = (
                        "A source-bound claim represents this complete statement with an explicit "
                        "subject, predicate and value; its verification status is unchanged.")
                elif kind == "narrative-or-list":
                    markers = [record for record in bound_records
                               if record.get("@type") == "Entity" and
                               record.get("kind") == "source-section-marker"]
                    marker_relationships = [record for record in bound_records
                                            if record.get("@type") == "Relationship" and
                                            record.get("predicate") == "labels-source-subsection"]
                    positions = [match for line in doc["lines"][start:end]
                                 if (match := re.match(r"^\s*(\d+)\.\s+", line))]
                    ordered_items = [record for record in bound_records
                                     if record.get("status") == "source-ordered-item"]
                    if len(markers) == 1 and len(marker_relationships) == 1:
                        status = "source-structure-extracted"
                        disposition_reason = (
                            "A standalone bold source label is represented as a scoped subsection marker, "
                            "not as an independent factual claim.")
                    elif len(positions) >= 2 and len(ordered_items) == len(positions):
                        status = "source-sequence-extracted"
                        disposition_reason = (
                            "Every numbered item is represented as an ordered source item with exact "
                            "text and order; this does not assert dependencies or successful execution.")
                elif kind == "table":
                    table_rows = [record for record in bound_records if record.get("tableColumns")
                                  and record.get("tableValues")]
                    data_rows = [line for line in doc["lines"][start:end]
                                 if line.lstrip().startswith("|") and
                                 not re.fullmatch(r"\s*\|?[\s:|-]+\|?\s*", line)]
                    if data_rows and len(table_rows) == len(data_rows) - 1:
                        status = "source-table-extracted"
                        disposition_reason = (
                            "The header, each row's exact column labels and values, and recognized "
                            "source-defined fields are represented without inferring unknown field roles.")
                elif kind == "code" and "```mermaid" in block_text:
                    node_count = len(set(re.findall(
                        r'([A-Za-z0-9_-]+)\["([^"]+)"\]', block_text)))
                    edge_count = len(re.findall(
                        r'([A-Za-z0-9_-]+)(?:\[[^\]]+\])?\s*-->\s*([A-Za-z0-9_-]+)', block_text))
                    nodes = [record for record in bound_records
                             if record.get("@type") == "Entity" and record.get("kind") == "diagram-node"]
                    edges = [record for record in bound_records
                             if record.get("@type") == "Relationship" and
                             record.get("predicate") == "explicitly-directed-to-in-source-diagram"]
                    if node_count and edge_count and len(nodes) == node_count and len(edges) == edge_count:
                        status = "source-structure-extracted"
                        disposition_reason = (
                            "Every Mermaid node label and directed arrow is represented with source-line "
                            "evidence; arrow direction is preserved without inferring an unlabelled dependency.")
                if status is None and kind == "narrative-or-list":
                    lines = [line.strip() for line in doc["lines"][start:end] if line.strip()]
                    links = [match for line in lines
                             for match in re.finditer(r"\[[^\]]+\]\([^)]+\)", line)]
                    link_records = [record for record in bound_records
                                    if record.get("@type") == "Relationship" and
                                    record.get("predicate") in {
                                        "explicitly-links-to-document",
                                        "explicitly-links-to-document-reference",
                                    }]
                    navigation_only = all(
                        not re.sub(r"\[[^\]]+\]\([^)]+\)", "", line).strip(" -*+.,;:()")
                        for line in lines)
                    if (links and navigation_only and len(links) == len(link_records)):
                        status = "source-navigation-extracted"
                        disposition_reason = (
                            "Every explicit Markdown link has a source-scoped navigation/reference "
                            "relationship; out-of-scope target content is not imported and no dependency "
                            "or inheritance is inferred.")
                if status is None:
                    status = ("partially-curated" if matched else
                              "structurally-extracted-review-required" if semantic else
                              "preserved-semantic-extraction-unresolved")
            if status is None:
                status = ("partially-curated" if matched else
                          "structurally-extracted-review-required" if semantic else
                          "preserved-semantic-extraction-unresolved")
            assessment = assessed_blocks.get((path, start))
            if assessment and status not in {
                    "source-structure-extracted", "non-semantic-whitespace",
                    "source-context-preserved", "source-description-extracted",
                    "source-claim-extracted", "source-sequence-extracted", "source-table-extracted",
                    "source-navigation-extracted"}:
                status = "source-semantics-assessed-unverified"
            ranges.append({"start_line": start + 1, "end_line": end, "kind": kind, "section": section,
                           "source_markdown_verification_status": source_verification_status,
                           "source_markdown_verification_basis": source_verification_basis,
                           "status": status,
                           **({"disposition_reason": disposition_reason} if disposition_reason else {}),
                           **({"context_records": context_records} if context_records else {}),
                           **({"semantic_assessment": assessment} if assessment else {}),
                           "evidence": matched, "records": semantic,
                           "copilot_interpretations": interpretations,
                           "content_sha256": digest("".join(doc["lines"][start:end]).encode("utf-8"))})
        if "".join("".join(doc["lines"][r["start_line"] - 1:r["end_line"]]) for r in ranges).encode("utf-8") != doc["data"]:
            raise ValueError(f"Coverage does not reconstruct {path}")
        coverage.append({"path": path, "audience": doc["audience"], "assistants": doc["meta"].get("assistants"),
                         "source_markdown_verification_status": source_verification_status,
                         "source_markdown_verification_basis": source_verification_basis,
                         "source_sha256": doc["hash"], "snapshot_commit": doc["commit"],
                         "snapshot": doc["snapshot"], "blocks": ranges})
        old_lines = doc["baseline_lines"]
        def fingerprints(lines, groups):
            return [(kind, tuple(section), digest("\n".join(
                line.rstrip("\r\n") for line in lines[start:end]).encode("utf-8")), start + 1, end)
                    for start, end, kind, section in groups]
        old_blocks = fingerprints(old_lines, blocks(old_lines)) if old_lines else []
        new_blocks = fingerprints(doc["lines"], doc["blocks"])
        available = Counter(x[:3] for x in old_blocks)
        added = []
        for kind, section, fingerprint, start, end in new_blocks:
            key = (kind, section, fingerprint)
            if available[key]:
                available[key] -= 1
            else:
                added.append({"start_line": start, "end_line": end, "kind": kind, "section": list(section),
                              "reason": "new-or-changed-since-comparison-baseline"})
        available = Counter(x[:3] for x in new_blocks)
        removed = []
        for kind, section, fingerprint, start, end in old_blocks:
            key = (kind, section, fingerprint)
            if available[key]:
                available[key] -= 1
            else:
                removed.append({"start_line": start, "end_line": end, "kind": kind, "section": list(section),
                                "reason": "removed-or-changed-since-comparison-baseline"})
        if added or removed:
            review_changes.append({"path": path, "audience": doc["audience"],
                                   "current_blocks": added, "baseline_blocks": removed})
    grouped_entities = [
        ("entities/resource-types.jsonld", [e for e in entities if e["kind"] == "resource-type"]),
        ("entities/platform-components.jsonld", [e for e in entities if e["kind"] == "platform-component-type"]),
        ("entities/concepts.jsonld", [e for e in entities if e["kind"] == "concept"]),
        ("entities/process-steps.jsonld", [e for e in entities if e["kind"] == "process-step"]),
        ("processes/curated.jsonld", [e for e in entities if e["kind"] == "process"]),
    ]
    for name, records in grouped_entities + [("claims/requirements.jsonld", claims),
                          ("claims/relationships.jsonld", relationships), ("evidence/curated.jsonld", evidence)]:
        outputs[name] = encoded({"@context": context, "@graph": records})
    for name, records in sorted(structured_records.items()):
        outputs[name] = encoded({"@context": context, "@graph": records})
    outputs["profiles/resource-types.jsonld"] = encoded({"@context": context, "@graph": [
        record for record in profile_records if record["profileKind"] == "resource-type"]})
    outputs["profiles/shared.jsonld"] = encoded({"@context": context, "@graph": [
        record for record in profile_records if record["profileKind"] == "shared-topic"]})
    outputs["profiles/relationships.jsonld"] = encoded({
        "@context": context, "@graph": profile_relationships})
    outputs["coverage/source-blocks.json"] = encoded({"sources": coverage})
    outputs["coverage/semantic-assessments.json"] = encoded({
        "status": "partial-source-verified-copilot-interpretation-review",
        "source_markdown_verification_status": source_verification_status,
        "source_markdown_verification_basis": source_verification_basis,
        "note": "A Copilot interpretation is source-verified only when a current hash-bound facet assessment cites it, the full reviewed source section and records match, and the pinned Markdown snapshot is user-confirmed. Verified means supported by that source review, not approved policy, human endorsement, live Azure verification or runtime proof. Unassessed and changed interpretations remain explicitly unverified; decision proposals remain pending.",
        "source_verification_basis": "hash-bound-faceted-source-assessment",
        "interpretation_record_counts": {
            "source_verified": {
                record_type: count for (record_type, status), count in
                sorted(interpretation_verification_counts.items()) if status == "source-verified"
            },
            "not_assessed": {
                record_type: count for (record_type, status), count in
                sorted(interpretation_verification_counts.items()) if status == "not-assessed"
            },
        },
        "assessments": section_assessments,
    })
    outputs["coverage/source-gap-review.json"] = encoded(gap_review)
    outputs["coverage/organization.json"] = encoded({
        "status": "partial-resource-and-shared-organization",
        "note": "Bundles reference canonical records without copying facts. Membership is navigation, not inheritance or approval. Organization covers individually authored interpretations, not all structural records or every resource mentioned in sources.",
        "bundles": organization,
    })
    evidence_paths = {record["@id"]: record["path"] for record in
                      evidence + structured_records["evidence/structured.jsonld"]}
    source_claim_counts = {path: Counter() for path in docs}
    for name, values in [("claims/requirements.jsonld", claims)] + list(structured_records.items()):
        if not name.startswith("claims/"):
            continue
        for record in values:
            if record.get("@type") != "Claim":
                continue
            source = record.get("source")
            sources = source if isinstance(source, list) else [source]
            for path in {evidence_paths[identity] for identity in sources if identity in evidence_paths}:
                source_claim_counts[path][Path(name).stem] += 1
    outputs["coverage/copilot-review.json"] = encoded({
        "status": "partial-source-verified-interpretation-review",
        "note": "Only interpretations bound by current hash-matched source assessments are marked source-verified. This does not approve decisions or establish live implementation. Remaining interpretations are unverified.",
        "claim_count": sum(len(values) for name, values in structured_records.items()
                           if name == "claims/copilot-interpretations.jsonld"),
        "interpretation_record_counts": {
            "source_verified": {
                record_type: count for (record_type, status), count in
                sorted(interpretation_verification_counts.items()) if status == "source-verified"
            },
            "not_assessed": {
                record_type: count for (record_type, status), count in
                sorted(interpretation_verification_counts.items()) if status == "not-assessed"
            },
        },
        "sources": [{"path": source["path"], "interpreted_blocks": sum(bool(block["copilot_interpretations"])
                    for block in source["blocks"]),
                    "claim_record_counts": dict(sorted(source_claim_counts[source["path"]].items())),
                    "preserved_only_content_blocks": sum(block["status"] ==
                    "preserved-semantic-extraction-unresolved" and block["kind"] in
                    {"narrative-or-list", "table", "code"} for block in source["blocks"]),
                    "content_blocks": sum(block["kind"] in {"narrative-or-list", "table", "code"}
                    for block in source["blocks"])} for source in coverage],
    })
    outputs["coverage/changes-needing-review.json"] = encoded(
        {"baseline_commit": baseline, "note": "Baseline is a comparison point, not semantic approval.",
         "changed_sources": review_changes, "invalidated_curated_records": invalidated})
    block_status_counts = Counter(block["status"] for source in coverage for block in source["blocks"])
    unresolved_content_blocks = sum(block_status_counts[status] for status in (
        "partially-curated", "preserved-semantic-extraction-unresolved",
        "structurally-extracted-review-required"))
    source_complete = source_extraction_is_complete(block_status_counts, invalidated)
    if publication_review:
        require_complete_review(source_complete, coverage, invalidated, section_assessments,
                                structured_records.get("claims/conflicts.jsonld", []))
    outputs["manifest.json"] = encoded({
        "version": "0.2.0", "status": "complete" if source_complete else "incomplete",
        "source_extraction_status": "complete" if source_complete else "incomplete",
        "source_markdown_verification_status": source_verification_status,
        "source_markdown_verification_basis": source_verification_basis,
        "source_markdown_verification_scope": (
            "Exact Markdown content at the pinned source snapshot; not graph interpretation or runtime verification."),
        "source_markdown_verification_snapshot_commit": (
            commit if source_markdown_verified else None),
        "source_markdown_verified_block_count": sum(len(d["blocks"]) for d in docs.values())
            if source_markdown_verified else 0,
        "live_verification_status": "not-assessed", "source_snapshot_commit": commit,
        "source_count": len(files), "entity_count": len(entities), "claim_count": len(claims),
        "relationship_count": len(relationships),         "knowledge_profile_count": len(profile_records),
        "knowledge_profile_counts": dict(sorted(Counter(
            record["profileKind"] for record in profile_records).items())),
        "profile_relationship_count": len(profile_relationships),
        "evidence_count": len(evidence),
        "block_count": sum(len(d["blocks"]) for d in docs.values()),
        "invalidated_curated_record_count": len(invalidated),
        "covered_unverified_section_count": sum(
            item["status"] == "covered-unverified" for item in section_assessments),
        "section_assessment_status_counts": dict(sorted(Counter(
            item["status"] for item in section_assessments).items())),
        "source_gap_review_summary": gap_review["summary"],
        "block_status_counts": dict(sorted(block_status_counts.items())),
        "unresolved_content_block_count": unresolved_content_blocks,
        "source_completeness_criteria": {
            "required": ["Every content block has source-bound semantic records or an explicit structural/non-assertional disposition.",
                        "No curated record is invalidated."],
            "does_not_require": ["Human approval of every source interpretation.",
                                 "Live Azure verification or external runtime evidence."],
        },
        "structured_record_counts": {name: len(records) for name, records in sorted(structured_records.items())},
        "review_status": "approved" if publication_review and source_complete else "pending-review",
        "verification_status": "verified" if publication_review and source_complete else "not-assessed",
        "publication_review": publication_review,
        "reviewed_by": publication_review["approval"]["login"] if publication_review else None,
        "reviewed_at": publication_review["approval"]["submitted_at"] if publication_review else None,
        "limitations": (["Content blocks with incomplete semantic dispositions remain; see coverage/source-blocks.json."]
                        if not source_complete else []) +
                       ["Only interpretations with current, hash-bound section assessments are source-verified; remaining interpretations are unverified.",
                        "Live Azure behavior was not assessed.",
                        "This combined artifact includes restricted admin content and is not an ingestion or authorization boundary."],
        "outputs": sorted(outputs),
    })
    snapshots = GRAPH / "evidence" / "snapshots"
    if snapshots.exists():
        existing = {p.relative_to(GRAPH).as_posix() for p in snapshots.rglob("*") if p.is_file()}
        stale = sorted(existing - set(outputs))
        if stale:
            raise ValueError(f"Stale generated snapshots require explicit disposition; nothing was deleted: {stale}")
    existing_graphs = set()
    for folder in ("entities", "claims", "processes", "evidence", "resource-types", "shared", "profiles"):
        directory = GRAPH / folder
        if directory.exists():
            existing_graphs.update(p.relative_to(GRAPH).as_posix() for p in directory.rglob("*.jsonld"))
    stale_graphs = sorted(existing_graphs - set(outputs))
    if stale_graphs:
        raise ValueError(f"Stale generated graph files require explicit disposition; nothing was deleted: {stale_graphs}")
    if publication_review and source_complete:
        apply_publication_review(outputs, publication_review)
    return outputs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        outputs = build()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        summary = (error.summary if isinstance(error, GraphReviewRequired) else {
            "schema_version": 1, "type": "graph-review-required", "message": str(error),
            "items": [], "requested_input": "Resolve the cited graph configuration or source conflict in reviewed Markdown."})
        write_review_report(summary)
        raise SystemExit(json.dumps(summary, ensure_ascii=False))
    for path, data in outputs.items():
        destination = GRAPH / path
        if args.check:
            if not destination.is_file() or destination.read_bytes() != data:
                raise SystemExit(f"Generated output differs: {path}")
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
    report = json.loads(outputs["coverage/changes-needing-review.json"])
    assessments = json.loads(outputs["coverage/semantic-assessments.json"])["assessments"]
    unresolved = sum(item["status"] not in {"covered-unverified", "covered-verified"} for item in assessments)
    print(f"{'Checked' if args.check else 'Generated'} {len(outputs)} graph files; "
          f"{len(report['invalidated_curated_records'])} curated records need review; "
          f"{unresolved} section assessments unresolved or stale")


if __name__ == "__main__":
    main()
