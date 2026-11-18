#!/usr/bin/env python3
"""Traverse evidenced prerequisites, dependents and guidance without inheritance."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "knowledge-graph"
LOOKUP_KINDS = {
    "author-declared-route-resource", "concept", "environment", "platform-component-type",
    "resource-knowledge-bundle", "resource-type", "shared-topic-bundle",
}
DEPENDENCY_PREDICATES = {
    "depends-on", "reads-remote-state-produced-by", "requires-prior-data-from",
    "consumes-cost-mapping-state-from", "looks-up-existing-hub-from",
    "requires-separate-workload-identity-association",
    "requires-independent-network-authorization",
    "requires-catalog-creation-or-import-for-managed-secret-lifecycle",
    "requires-independent-activation-approval",
    "requires-terraform-output",
    "requires-environment-log-workspace",
}


def normalize_term(value):
    return " ".join(value.split()).casefold()


def resolve(records, term, audience, assistant):
    normalized = normalize_term(term)
    if not normalized:
        raise ValueError("Query must not be empty")
    matches = []
    for record in records.values():
        if (record.get("@type") != "Entity" or record.get("kind") not in LOOKUP_KINDS
                or record.get("audience") != audience
                or assistant not in record.get("assistants", [])):
            continue
        matching_terms = []
        if normalize_term(record.get("label", "")) == normalized:
            matching_terms.append({"text": record["label"], "matchType": "label"})
        for alias in record.get("aliases", []):
            if normalize_term(alias) == normalized and not any(
                    item["text"] == alias and item["matchType"] == "alias"
                    for item in matching_terms):
                matching_terms.append({"text": alias, "matchType": "alias"})
        if not matching_terms:
            continue
        refs = record.get("source", [])
        refs = refs if isinstance(refs, list) else [refs]
        evidence = []
        for ref in refs:
            source = records.get(ref)
            if source is None or source.get("audience") != audience or assistant not in source.get("assistants", []):
                raise ValueError("Lookup evidence is unavailable in the requested scope")
            evidence.append({key: source[key] for key in (
                "@id", "path", "section", "startLine", "endLine", "sha256", "snapshotCommit")
                             if key in source})
        matches.append({
            "canonicalEntity": record["@id"],
            "label": record["label"],
            "kind": record["kind"],
            "matchedTerms": matching_terms,
            "status": record.get("status", "source-declared"),
            "audience": audience,
            "assistants": record["assistants"],
            "evidence": evidence,
        })
    return sorted(matches, key=lambda match: match["canonicalEntity"])


def navigate(records, identity, audience, assistant):
    def allowed(record):
        return record["audience"] == audience and assistant in record["assistants"]

    selected = records.get(identity)
    if selected is None or not allowed(selected) or selected["@type"] != "Entity":
        raise ValueError("Resource is unavailable in the requested audience/assistant scope")
    visible = {key: record for key, record in records.items() if allowed(record)}
    roots = {identity}
    if selected["kind"] in {"resource-knowledge-bundle", "shared-topic-bundle"}:
        roots = {visible[key]["subject"] for key in selected["members"]
                 if key in visible and visible[key]["@type"] == "Claim"}
    relations = [record for record in visible.values() if record["@type"] == "Relationship"
                 and record["subject"] in visible and record["object"] in visible]
    changed = True
    while changed:
        before = len(roots)
        for relation in relations:
            if relation["predicate"] == "declares-canonical-resource" and (
                    relation["subject"] in roots or relation["object"] in roots):
                roots.update((relation["subject"], relation["object"]))
        changed = len(roots) != before

    def sources(record):
        refs = record["source"] if isinstance(record["source"], list) else [record["source"]]
        if any(ref not in visible for ref in refs):
            raise ValueError("Guidance evidence is unavailable in the requested scope")
        return [{key: visible[ref][key] for key in (
            "@id", "path", "section", "startLine", "endLine", "sha256", "snapshotCommit")
                 if key in visible[ref]} for ref in refs]

    def edge(record, relation_kind):
        return {**{key: record[key] for key in (
            "@id", "subject", "predicate", "object", "condition", "conditions", "status",
            "interpretationVerificationStatus", "interpretationVerificationBasis",
            "interpretationVerificationAssessments")
                   if key in record}, "relationKind": relation_kind, "evidence": sources(record)}

    def guidance(subjects, relation_kind):
        return [{**{key: record[key] for key in (
            "@id", "subject", "predicate", "value", "requiredSetting", "rationale",
            "responsibility", "condition", "conditions", "order", "status",
            "interpretationVerificationStatus", "interpretationVerificationBasis",
            "interpretationVerificationAssessments")
                    if key in record}, "relationKind": relation_kind, "evidence": sources(record)}
                for record in sorted(visible.values(), key=lambda record: record["@id"])
                if record["@type"] == "Claim" and record["subject"] in subjects]

    outgoing = sorted((relation for relation in relations if relation["subject"] in roots
                       and relation["predicate"] in DEPENDENCY_PREDICATES), key=lambda r: r["@id"])
    incoming = sorted((relation for relation in relations if relation["object"] in roots
                       and relation["predicate"] in DEPENDENCY_PREDICATES), key=lambda r: r["@id"])
    related = sorted((relation for relation in relations if (
        relation["subject"] in roots or relation["object"] in roots)
        and relation["predicate"] not in DEPENDENCY_PREDICATES), key=lambda r: r["@id"])
    return {
        "selected": identity, "audience": audience, "assistant": assistant,
        "status": "partial-evidenced-navigation-not-inherited-or-approved",
        "roots": sorted(roots),
        "dependencies": [edge(record, "prerequisite") for record in outgoing],
        "dependents": [edge(record, "dependent") for record in incoming],
        "guidance": guidance(roots, "guidance"),
        "prerequisite_guidance": guidance({record["object"] for record in outgoing},
                                          "guidance-about-prerequisite"),
        "related_not_dependencies": [edge(record, "related-not-dependency") for record in related],
    }


def visible_profile_records(records, audience, assistant):
    return [record for record in records.values()
            if record.get("@type") == "KnowledgeProfile" and
            record.get("audience") == audience and
            assistant in record.get("assistants", [])]


def _environment_matches(records, profile, environment):
    return any(identity == environment or
               records.get(identity, {}).get("label") == environment
               for identity in profile.get("environmentScope", []))


def list_profiles(records, audience, assistant, profile_kind=None, label=None,
                  environment=None, max_results=1000):
    if type(max_results) is not int or not 1 <= max_results <= 1000:
        raise ValueError("Profile result budget must be between 1 and 1000")
    if profile_kind is not None and profile_kind not in {"resource-type", "shared-topic"}:
        raise ValueError("Unknown knowledge profile kind")
    profiles = visible_profile_records(records, audience, assistant)
    if profile_kind is not None:
        profiles = [record for record in profiles if record["profileKind"] == profile_kind]
    if label is not None:
        profiles = [record for record in profiles if record["label"] == label]
    if environment is not None:
        profiles = [record for record in profiles
                    if _environment_matches(records, record, environment)]
    profiles.sort(key=lambda record: record["@id"])
    selected = profiles[:max_results]
    return {
        "audience": audience,
        "assistant": assistant,
        "status": "unmatched" if not profiles else "truncated" if len(profiles) > max_results else "resolved",
        "visibleProfileCount": len(profiles),
        "resultCount": len(selected),
        "maxResults": max_results,
        "truncated": len(profiles) > max_results,
        "profiles": [{
            "@id": record["@id"], "profileId": record["profileId"],
            "profileKind": record["profileKind"], "label": record["label"],
            "covers": record["covers"], "coverage": record["coverage"],
            "environmentScope": record.get("environmentScope", []),
            "maintainer": record["maintainer"], "revision": record["revision"],
            "status": record["status"], "audience": record["audience"],
            "assistants": record["assistants"],
        } for record in selected],
    }


def navigate_profile(records, identity, audience, assistant, direction="both",
                     depth=1, max_results=1000, profile_kind=None, label=None,
                     environment=None):
    if direction not in {"upstream", "downstream", "both", "none"}:
        raise ValueError("Invalid profile dependency direction")
    if type(depth) is not int or not 0 <= depth <= 5:
        raise ValueError("Profile navigation depth must be between 0 and 5")
    if type(max_results) is not int or not 1 <= max_results <= 1000:
        raise ValueError("Profile result budget must be between 1 and 1000")
    matches = [record for record in visible_profile_records(records, audience, assistant)
               if identity in {record["@id"], record["profileId"]}]
    if len(matches) != 1:
        raise ValueError("Profile is unavailable in the requested audience/assistant scope")
    selected = matches[0]
    if ((profile_kind is not None and selected["profileKind"] != profile_kind) or
            (label is not None and selected["label"] != label) or
            (environment is not None and
             not _environment_matches(records, selected, environment))):
        raise ValueError("Profile does not match the requested resource or environment scope")
    if any(identity not in records or
           records[identity].get("audience") != audience or
           assistant not in records[identity].get("assistants", [])
           for identity in selected["covers"]):
        raise ValueError("Profile references are unavailable in the requested scope")

    knowledge = []
    for bundle_id in selected["covers"]:
        navigation = navigate(records, bundle_id, audience, assistant)
        if direction not in {"upstream", "both"}:
            navigation["dependencies"] = []
            navigation["prerequisite_guidance"] = []
        if direction not in {"downstream", "both"}:
            navigation["dependents"] = []
        if direction != "both":
            navigation["related_not_dependencies"] = []
        knowledge.append(navigation)

    def navigation_size(navigation):
        size = len(navigation["roots"])
        for key in ("dependencies", "dependents", "guidance", "prerequisite_guidance",
                    "related_not_dependencies"):
            size += len(navigation[key])
            size += sum(len(item.get("evidence", [])) for item in navigation[key])
        return size

    result_count = 1 + len(selected["covers"]) + sum(navigation_size(item) for item in knowledge)
    if result_count > max_results:
        raise ValueError("Direct profile context exceeds the result budget; increase --max-results or narrow the profile")

    dependencies = [record for record in records.values()
                    if record.get("@type") == "ProfileRelationship" and
                    record.get("audience") == audience and
                    assistant in record.get("assistants", [])]
    outgoing, incoming = {}, {}
    for relation in dependencies:
        outgoing.setdefault(relation["subject"], []).append(relation)
        incoming.setdefault(relation["object"], []).append(relation)
    for values in list(outgoing.values()) + list(incoming.values()):
        values.sort(key=lambda record: record["@id"])

    def supporting_relationships(relation):
        supported = []
        for relationship_id in relation["backedBy"]:
            source = records.get(relationship_id)
            if source is None or source.get("@type") != "Relationship" or (
                    source.get("audience") != audience or
                    assistant not in source.get("assistants", [])):
                raise ValueError("Profile dependency evidence is unavailable in the requested scope")
            refs = source["source"] if isinstance(source["source"], list) else [source["source"]]
            if any(ref not in records or records[ref].get("audience") != audience or
                   assistant not in records[ref].get("assistants", []) for ref in refs):
                raise ValueError("Profile dependency evidence is unavailable in the requested scope")
            supported.append({
                **{key: source[key] for key in (
                    "@id", "subject", "predicate", "object", "condition", "conditions", "status")
                   if key in source},
                "evidence": [{key: records[ref][key] for key in (
                    "@id", "path", "section", "startLine", "endLine", "sha256", "snapshotCommit")
                             if key in records[ref]} for ref in refs],
            })
        return supported

    backing_cache = {}
    links = {}
    visited = {selected["@id"]: 0}
    frontier = [(selected["@id"], 0)]
    truncated = False
    while frontier:
        current, current_depth = frontier.pop(0)
        if current_depth >= depth:
            continue
        candidates = []
        if direction in {"upstream", "both"}:
            candidates.extend((relation, "upstream") for relation in outgoing.get(current, []))
        if direction in {"downstream", "both"}:
            candidates.extend((relation, "downstream") for relation in incoming.get(current, []))
        for relation, link_direction in candidates:
            next_profile = relation["object"] if link_direction == "upstream" else relation["subject"]
            if relation["@id"] not in links:
                supported = backing_cache.setdefault(
                    relation["@id"], supporting_relationships(relation))
                additional = 1 + sum(1 + len(item["evidence"]) for item in supported)
                if next_profile not in visited:
                    additional += 1
                if result_count + additional > max_results:
                    if current_depth == 0:
                        raise ValueError(
                            "Direct profile dependencies exceed the result budget; increase --max-results")
                    truncated = True
                    continue
                result_count += additional
            entry = links.setdefault(relation["@id"], {"record": relation, "directions": set()})
            entry["directions"].add(link_direction)
            if next_profile not in visited:
                visited[next_profile] = current_depth + 1
                frontier.append((next_profile, current_depth + 1))

    def profile_link(entry):
        relation = entry["record"]
        return {
            "@id": relation["@id"], "subject": relation["subject"],
            "object": relation["object"], "predicate": relation["predicate"],
            "directions": sorted(entry["directions"]),
            "backedBy": relation["backedBy"],
            "supportingRelationships": backing_cache[relation["@id"]],
        }
    return {
        "selectedProfile": selected["@id"],
        "audience": audience, "assistant": assistant,
        "status": "proposed-profile-explicit-source-backed-navigation-not-approval",
        "direction": direction, "depth": depth,
        "maxResults": max_results, "resultCount": result_count, "truncated": truncated,
        "expandedProfiles": sorted(visited),
        "profileRelationships": [profile_link(entry) for _, entry in sorted(links.items())],
        "knowledgeNavigation": knowledge,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--resource", help="Exact stable entity or bundle ID")
    selection.add_argument("--query", help="Exact label or source-declared alias")
    selection.add_argument("--profile", help="Exact stable knowledge profile ID")
    selection.add_argument("--list-profiles", action="store_true", help="List visible knowledge profiles")
    parser.add_argument("--audience", required=True, choices=("guide", "admin"))
    parser.add_argument("--assistant", required=True)
    parser.add_argument("--profile-kind", choices=("resource-type", "shared-topic"))
    parser.add_argument("--profile-label", help="Exact resource or shared-topic profile label")
    parser.add_argument("--environment", help="Exact explicitly scoped environment ID or label")
    parser.add_argument("--direction", choices=("upstream", "downstream", "both", "none"), default="both")
    parser.add_argument("--depth", type=int, default=1, help="Profile relationship depth (0-5)")
    parser.add_argument("--max-results", type=int, default=1000, help="Profile result budget (1-1000)")
    args = parser.parse_args()
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    records = {}
    for file in manifest["outputs"]:
        if file.endswith(".jsonld"):
            for record in json.loads((ROOT / file).read_text(encoding="utf-8"))["@graph"]:
                if record["@id"] in records:
                    raise ValueError("Duplicate graph identifier")
                records[record["@id"]] = record
    try:
        if args.query is not None:
            if (args.profile_kind is not None or args.profile_label is not None or
                    args.environment is not None or args.direction != "both" or
                    args.depth != 1 or args.max_results != 1000):
                raise ValueError("Profile filters and bounds require --profile or --list-profiles")
            matches = resolve(records, args.query, args.audience, args.assistant)
            result = {
                "queryTerm": args.query,
                "audience": args.audience,
                "assistant": args.assistant,
                "status": "unmatched" if not matches else "resolved" if len(matches) == 1 else "ambiguous",
                "matches": matches,
            }
            if len(matches) == 1:
                result["navigation"] = navigate(
                    records, matches[0]["canonicalEntity"], args.audience, args.assistant)
        else:
            if args.profile is not None:
                result = navigate_profile(
                    records, args.profile, args.audience, args.assistant, args.direction,
                    args.depth, args.max_results, args.profile_kind,
                    args.profile_label, args.environment)
            elif args.list_profiles:
                if args.direction != "both" or args.depth != 1:
                    raise ValueError("--direction and --depth require --profile")
                result = list_profiles(
                    records, args.audience, args.assistant, args.profile_kind,
                    args.profile_label, args.environment, args.max_results)
            else:
                if (args.profile_kind is not None or args.profile_label is not None or
                        args.environment is not None or args.direction != "both" or
                        args.depth != 1 or args.max_results != 1000):
                    raise ValueError("Profile filters and bounds require --profile or --list-profiles")
                result = navigate(records, args.resource, args.audience, args.assistant)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
