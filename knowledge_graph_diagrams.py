"""Build source-validated, query-scoped diagram projections."""
import re
import unicodedata

BASE = "https://github.com/almbrand/cloudops-openai-hub-knowledge-source/knowledge-graph/"
UNVERIFIED = "unverified-copilot-interpretation"
QUERY_RESOLVER_POLICY = "exact-query-entity-task-source-unique-v1"
SOURCE_QUERY_RESOLVER_POLICY = "exact-source-topic-task-unique-v1"
COMPANION_POLICY = "explicit-process-companion-evidence-v1"
COMPANION_KIND = "process-diagram-companion"
COMPANION_PREDICATE = "has-companion-diagram"
QUERY_CONTEXT_FIELDS = {
    "query_profile_id", "query_entity", "query_route_id", "query_alias_source",
    "query_route_canonical_resource", "query_resource_aliases", "query_task_aliases",
    "query_ambiguous_terms", "query_match_policy", "query_ambiguity_policy",
    "query_resolver_policy",
}
SOURCE_QUERY_CONTEXT_FIELDS = {
    "query_resolver_policy", "query_source_evidence",
    "query_topic_phrases", "query_task_phrases",
}


def normalize_query_phrase(value):
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def contains_query_phrase(text, phrase):
    return re.search(r"(?<!\w)" + re.escape(phrase) + r"(?!\w)", text) is not None


def is_companion(record):
    return (record.get("kind") == COMPANION_KIND or
            record.get("predicate") == COMPANION_PREDICATE or
            "companionPolicy" in record or
            record["@id"].startswith(BASE + "diagram-companions/"))


def source_query_context(evidence_id, topic_phrases, task_phrases, records,
                         sequence_sources, scope, source_snapshot_commit):
    evidence = records.get(evidence_id) if isinstance(evidence_id, str) else None
    if (evidence is None or evidence.get("@type") != "Evidence" or
            evidence_id not in sequence_sources or
            evidence.get("snapshotCommit") != source_snapshot_commit or
            evidence.get("sourceVerificationStatus") not in {"verified", "not-assessed"} or
            not re.fullmatch(r"[a-f0-9]{64}", evidence.get("sha256", ""))):
        raise ValueError("Diagram query source evidence is unavailable or stale")
    if (evidence.get("audience"), frozenset(evidence.get("assistants", []))) != scope:
        raise ValueError("Diagram query source evidence scope mismatch")
    text = normalize_query_phrase(evidence.get("text", ""))
    normalized_groups = []
    for phrases in (topic_phrases, task_phrases):
        if (not isinstance(phrases, list) or not phrases or
                any(not isinstance(phrase, str) or not phrase.strip() for phrase in phrases)):
            raise ValueError("Invalid diagram query source phrases")
        normalized = [normalize_query_phrase(phrase) for phrase in phrases]
        if (len(normalized) != len(set(normalized)) or
                any(not contains_query_phrase(text, phrase) for phrase in normalized)):
            raise ValueError("Diagram query source phrases are duplicated or absent from evidence")
        normalized_groups.append(normalized)
    if any(contains_query_phrase(topic, task) or contains_query_phrase(task, topic)
           for topic in normalized_groups[0] for task in normalized_groups[1]):
        raise ValueError("Diagram query topic and task phrases must be distinct and non-overlapping")
    return {
        "queryResolverPolicy": SOURCE_QUERY_RESOLVER_POLICY,
        "querySourceEvidence": evidence_id,
        "queryTopicPhrases": topic_phrases,
        "queryTaskPhrases": task_phrases,
    }


def build_companions(config, records, source_snapshot_commit):
    """Project declared companion applicability, never diagram-to-diagram edges."""
    rules = config.get("process_companion_rules", [])
    if not isinstance(rules, list):
        raise ValueError("Invalid process companion rules")

    def scope(record):
        return record.get("audience"), frozenset(record.get("assistants", []))

    def refs(record):
        value = record.get("source", [])
        return [value] if isinstance(value, str) else value

    def verified(item, expected_scope):
        return (item.get("@type") == "Evidence" and
                scope(item) == expected_scope and
                item.get("snapshotCommit") == source_snapshot_commit and
                item.get("sourceVerificationStatus") in {"verified", "not-assessed"} and
                bool(re.fullmatch(r"[a-f0-9]{64}", item.get("sha256", ""))))

    required = {"id", "policy", "sequence_id", "audience", "assistants",
                "source_paths", "source_heading", "required_source_text",
                "route_task", "route_support"}
    rule_ids = set()
    targets = {}
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != required:
            raise ValueError("Invalid process companion rule fields")
        if (any(not isinstance(rule[key], str) or not rule[key].strip()
                for key in ("id", "policy", "sequence_id", "audience",
                            "source_heading", "route_task")) or
                not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", rule["id"]) or
                rule["id"] in rule_ids or rule["policy"] != COMPANION_POLICY or
                not re.fullmatch(r"#{4,6} [^\n]+", rule["source_heading"])):
            raise ValueError("Invalid process companion rule identity or policy")
        for key in ("assistants", "source_paths", "required_source_text", "route_support"):
            values = rule[key]
            if (not isinstance(values, list) or not values or
                    any(not isinstance(value, str) or not value.strip() for value in values) or
                    len(values) != len(set(values))):
                raise ValueError(f"Invalid process companion rule {key}")
        if not set(rule["route_support"]).issubset({"supported", "conditional"}):
            raise ValueError("Process companion rules require supported or conditional routes")
        target = records.get(BASE + "diagrams/" + rule["sequence_id"])
        if (target is None or target.get("@type") != "Entity" or
                target.get("kind") != "source-backed-sequence" or target.get("sourceProcess") or
                scope(target) != scope(rule) or
                target.get("sourceSnapshotCommit") != source_snapshot_commit or
                not refs(target) or
                any(not verified(records.get(ref, {}), scope(rule)) for ref in refs(target))):
            raise ValueError(f"Process companion target is unavailable or unverified: {rule['id']}")
        targets[rule["id"]] = target
        rule_ids.add(rule["id"])

    processes = sorted((record for record in records.values()
                        if record.get("@type") == "Entity" and
                        record.get("kind") == "documented-resource-onboarding-process"),
                       key=lambda record: record["@id"])
    process_links = {}
    routes = {}
    evidence_by_section = {}
    for record in records.values():
        if (record.get("@type") == "Relationship" and
                record.get("predicate") == "documents-resource-onboarding"):
            process_links.setdefault(record.get("subject"), []).append(record)
        if record.get("@type") == "Claim" and record.get("routeId"):
            routes.setdefault(record.get("subject"), []).append(record)
        if record.get("@type") == "Evidence":
            evidence_by_section.setdefault(
                (record.get("path"), record.get("section")), []).append(record)

    def applicability(process, rule):
        if scope(process) != scope(rule):
            return None, "outside-declared-scope"
        parents = refs(process)
        if not isinstance(parents, list) or len(parents) != 1:
            return None, "ambiguous-process-source"
        parent = records.get(parents[0], {})
        if parent.get("path") not in rule["source_paths"]:
            return None, "outside-declared-source-paths"
        if not verified(parent, scope(rule)):
            return None, "process-source-not-verified"
        links = process_links.get(process["@id"], [])
        route_matches = routes.get(links[0].get("object"), []) if len(links) == 1 else []
        if (process.get("status") != "source-explicit-procedure" or len(links) != 1 or
                scope(links[0]) != scope(rule) or refs(links[0]) != parents or
                len(route_matches) != 1):
            return None, "missing-unique-process-route"
        route = route_matches[0]
        section = records.get(route.get("targetSection"), {})
        if (scope(route) != scope(rule) or scope(section) != scope(rule) or
                section.get("section") != parent.get("section") or
                route.get("task") != rule["route_task"] or
                route.get("support") not in rule["route_support"] or
                route.get("conditions") != process.get("conditions")):
            return None, "route-not-applicable"
        lines = parent.get("text", "").split("\n")
        starts = [index for index, line in enumerate(lines) if line == rule["source_heading"]]
        if len(starts) != 1:
            return None, "missing-unique-applicability-section"
        start = starts[0]
        heading, title = rule["source_heading"].split(" ", 1)
        end = next((index for index in range(start + 1, len(lines))
                    if re.match(r"^#{1," + str(len(heading)) + r"} ", lines[index])), len(lines))
        text = "\n".join(lines[start:end])
        if any(quote not in text for quote in rule["required_source_text"]):
            return None, "required-applicability-text-missing"
        candidates = [
            item for item in evidence_by_section.get(
                (parent["path"], parent["section"] + " > " + title), [])
            if verified(item, scope(rule)) and item.get("sha256") == parent["sha256"] and
            item.get("startLine") == parent["startLine"] + start and
            item.get("endLine") == parent["startLine"] + end - 1 and
            item.get("text") == text
        ]
        if not candidates:
            return None, "exact-applicability-evidence-missing"
        # Multiple curated IDs can cite the identical physical source block.
        return min(candidates, key=lambda item: item["@id"]), None

    output, coverage = [], []
    for process in processes:
        matches, gaps = [], []
        for rule in rules:
            evidence, reason = applicability(process, rule)
            if reason:
                gaps.append({"ruleId": rule["id"], "reason": reason})
            else:
                matches.append((rule, evidence))
        if len(matches) > 1:
            raise ValueError(f"Ambiguous process companions: {process['@id']}")
        entry = {"process": process["@id"], "audience": process["audience"],
                 "assistants": sorted(process["assistants"])}
        if not matches:
            coverage.append({**entry, "status": "uncovered", "gaps": gaps})
            continue
        rule, evidence = matches[0]
        target = targets[rule["id"]]
        identity = BASE + "diagram-companions/" + rule["id"] + "/" + process["@id"].rsplit("/", 1)[-1]
        output.append({
            "@id": identity, "@type": "Relationship", "kind": COMPANION_KIND,
            "predicate": COMPANION_PREDICATE, "subject": process["@id"],
            "object": target["@id"], "companionPolicy": COMPANION_POLICY,
            "label": "Separate companion: " + target["label"],
            "source": [evidence["@id"]], "sourceText": [evidence["text"]],
            "conditions": list(process["conditions"]),
            "sourceSnapshotCommit": source_snapshot_commit,
            "sourceVerificationStatus": evidence["sourceVerificationStatus"],
            "status": UNVERIFIED, "interpretationVerificationStatus": "not-assessed",
            "interpretationVerificationBasis": "no-current-hash-bound-faceted-source-assessment",
            "interpretationVerificationAssessments": [], "liveVerificationStatus": "not-assessed",
            "audience": process["audience"], "assistants": sorted(process["assistants"]),
        })
        coverage.append({**entry, "status": "declared", "relationship": identity,
                         "sequence": target["@id"], "source": evidence["@id"]})
    return output, {
        "policy": COMPANION_POLICY, "sourceSnapshotCommit": source_snapshot_commit,
        "processCount": len(processes), "declaredCount": len(output),
        "uncoveredCount": len(processes) - len(output), "processes": coverage,
        "limitations": [
            "Applicability navigation only; no cross-diagram edges, inherited support or live identity state.",
            "Consumers must independently retrieve applicability and companion evidence and preserve all conditions.",
            "Processes absent from this inventory and unsupported routes have no declared companion.",
        ],
    }


def build(config, records, profiles, source_snapshot_commit):
    if config.get("schema_version") != 1 or not isinstance(config.get("sequences"), list):
        raise ValueError("Invalid source-backed diagram configuration")
    allowed_predicates = config.get("predicate_allowlist")
    if (not isinstance(allowed_predicates, list) or not allowed_predicates or
            len(allowed_predicates) != len(set(allowed_predicates)) or
            any(not isinstance(predicate, str) or
                not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", predicate)
                for predicate in allowed_predicates)):
        raise ValueError("Invalid diagram predicate allow-list")
    icon_catalog = config.get("icon_catalog", {})
    allowed_icons = icon_catalog.get("allowed_ids")
    if (not isinstance(allowed_icons, list) or not allowed_icons or
            len(allowed_icons) != len(set(allowed_icons)) or
            not re.fullmatch(r"[a-f0-9]{40}", icon_catalog.get("commit", "")) or
            any(not isinstance(icon, str) or not re.fullmatch(r"[a-z0-9-]+", icon)
                for icon in allowed_icons)):
        raise ValueError("Invalid diagram icon allow-list")
    projection = config.get("ordered_procedure_projection")
    if projection != {
            "process_kind": "documented-resource-onboarding-process",
            "process_status": "source-explicit-procedure",
            "step_status": "source-explicit-procedure",
            "edge_predicate": "precedes"}:
        raise ValueError("Invalid ordered-procedure projection contract")

    evidence = {identity: record for identity, record in records.items()
                if record.get("@type") == "Evidence"}
    profiles_by_id = {record.get("profileId"): record for record in profiles
                      if record.get("@type") == "KnowledgeProfile"}
    output = {
        "entities/diagram-sequences.jsonld": [],
        "entities/diagram-nodes.jsonld": [],
        "claims/diagram-edges.jsonld": [],
    }
    sequence_ids, node_ids, edge_ids = set(), set(), set()

    def strings(value, name, allow_empty=False):
        if not isinstance(value, list) or (not allow_empty and not value) or any(
                not isinstance(item, str) or not item.strip() for item in value):
            raise ValueError(f"Invalid diagram {name}")
        return value

    def evidence_refs(value, name, scope=None):
        refs = strings(value, name)
        if len(refs) != len(set(refs)):
            raise ValueError(f"Duplicate diagram {name}")
        selected = []
        for identity in refs:
            item = evidence.get(identity)
            if item is None:
                raise ValueError(f"Diagram {name} is missing evidence: {identity}")
            if (item.get("sourceVerificationStatus") not in {"verified", "not-assessed"} or
                    item.get("snapshotCommit") != source_snapshot_commit or
                    not re.fullmatch(r"[a-f0-9]{64}", item.get("sha256", ""))):
                raise ValueError(f"Diagram evidence is not verified at the consumed source commit: {identity}")
            item_scope = (item.get("audience"), frozenset(item.get("assistants", [])))
            if scope is not None and item_scope != scope:
                raise ValueError(f"Diagram evidence scope mismatch: {identity}")
            selected.append(item)
        return refs, selected

    def validate_quotes(quotes, refs, selected, name):
        quotes = strings(quotes, name)
        for quote in quotes:
            if not any(quote in item.get("text", "") for item in selected):
                raise ValueError(f"Diagram {name} is not present in its cited evidence")
        for ref, item in zip(refs, selected):
            if not any(quote in item.get("text", "") for quote in quotes):
                raise ValueError(f"Diagram evidence is not tied to an exact source quote: {ref}")
        return quotes

    def validate_common_id(value, name, used):
        if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", value):
            raise ValueError(f"Invalid diagram {name}")
        if value in used:
            raise ValueError(f"Duplicate diagram {name}: {value}")
        used.add(value)
        return value

    for spec in config["sequences"]:
        sequence_id = validate_common_id(spec.get("id"), "sequence ID", sequence_ids)
        required = {"label", "context", "conditions", "source", "sourceText",
                    "ordering_semantics", "nodes", "edges"}
        if not required.issubset(spec):
            raise ValueError(f"Incomplete diagram sequence: {sequence_id}")
        present_query_fields = (QUERY_CONTEXT_FIELDS | SOURCE_QUERY_CONTEXT_FIELDS).intersection(spec)
        query_policy = spec.get("query_resolver_policy")
        if present_query_fields:
            if query_policy is not None and not isinstance(query_policy, str):
                raise ValueError(f"Unsupported diagram query resolver policy: {sequence_id}")
            expected_query_fields = {
                QUERY_RESOLVER_POLICY: QUERY_CONTEXT_FIELDS,
                SOURCE_QUERY_RESOLVER_POLICY: SOURCE_QUERY_CONTEXT_FIELDS,
            }.get(query_policy)
            if query_policy is not None and expected_query_fields is None:
                raise ValueError(f"Unsupported diagram query resolver policy: {sequence_id}")
            if present_query_fields != expected_query_fields:
                raise ValueError(f"Incomplete diagram query context or mixed policies: {sequence_id}")
        text_fields = ["label", "context", "ordering_semantics"]
        if query_policy == QUERY_RESOLVER_POLICY:
            text_fields.extend(("query_match_policy", "query_ambiguity_policy"))
        if any(not isinstance(spec[key], str) or not spec[key].strip() for key in text_fields):
            raise ValueError(f"Invalid diagram sequence text: {sequence_id}")
        conditions = strings(spec["conditions"], "sequence conditions", allow_empty=True)
        sequence_source, sequence_evidence = evidence_refs(spec["source"], "sequence source")
        sequence_quotes = validate_quotes(
            spec["sourceText"], sequence_source, sequence_evidence, "sequence sourceText")
        source_verification_statuses = {
            item["sourceVerificationStatus"] for item in sequence_evidence}
        if len(source_verification_statuses) != 1:
            raise ValueError(f"Diagram sequence mixes source verification states: {sequence_id}")
        source_verification_status = next(iter(source_verification_statuses))
        scope = (sequence_evidence[0]["audience"],
                 frozenset(sequence_evidence[0]["assistants"]))
        if any((item["audience"], frozenset(item["assistants"])) != scope
               for item in sequence_evidence):
            raise ValueError(f"Diagram sequence mixes audience or assistant scopes: {sequence_id}")

        query_context = {}
        if query_policy == QUERY_RESOLVER_POLICY:
            profile = profiles_by_id.get(spec["query_profile_id"])
            entity = records.get(spec["query_entity"])
            route_matches = [record for record in records.values()
                             if record.get("routeId") == spec["query_route_id"]]
            if (profile is None or entity is None or entity.get("@type") != "Entity" or
                    entity.get("kind") == "diagram-node" or len(route_matches) != 1 or
                    route_matches[0].get("@type") != "Claim"):
                raise ValueError(f"Diagram query context is unavailable or ambiguous: {sequence_id}")
            route = route_matches[0]
            alias_source = records.get(spec["query_alias_source"])
            route_canonical = records.get(spec["query_route_canonical_resource"])
            canonical_links = [record for record in records.values()
                               if record.get("@type") == "Relationship" and
                               record.get("predicate") == "declares-canonical-resource" and
                               record.get("subject") == spec["query_alias_source"] and
                               record.get("object") == spec["query_route_canonical_resource"]]
            if (alias_source is None or alias_source.get("@type") != "Entity" or
                    alias_source.get("kind") != "author-declared-route-resource" or
                    route_canonical is None or route_canonical.get("@type") != "Entity" or
                    len(canonical_links) != 1 or
                    route.get("subject") != alias_source["@id"] or
                    spec["query_resource_aliases"] != alias_source.get("aliases", []) or
                    spec["query_task_aliases"] != route.get("taskAliases", [])):
                raise ValueError(f"Diagram query aliases are not the exact declared route aliases: {sequence_id}")
            declared_terms = set(spec["query_resource_aliases"]) | set(spec["query_task_aliases"])
            ambiguous_terms = strings(spec["query_ambiguous_terms"], "ambiguous query terms")
            if not set(ambiguous_terms).issubset(declared_terms):
                raise ValueError(f"Diagram ambiguity terms are not source-declared: {sequence_id}")
            for item, name in ((profile, "profile"), (entity, "entity"), (route, "route"),
                               (route_canonical, "route canonical resource"),
                               (canonical_links[0], "route canonical link")):
                if (item.get("audience"), frozenset(item.get("assistants", []))) != scope:
                    raise ValueError(f"Diagram query {name} scope mismatch: {sequence_id}")
            if (alias_source.get("audience"), frozenset(alias_source.get("assistants", []))) != scope:
                raise ValueError(f"Diagram query alias source scope mismatch: {sequence_id}")
            query_context = {
                "queryProfileId": spec["query_profile_id"],
                "queryEntity": spec["query_entity"],
                "queryRouteId": spec["query_route_id"],
                "queryAliasSource": spec["query_alias_source"],
                "queryRouteCanonicalResource": spec["query_route_canonical_resource"],
                "queryAliases": spec["query_resource_aliases"],
                "queryTaskAliases": spec["query_task_aliases"],
                "queryAmbiguousTerms": ambiguous_terms,
                "queryMatchPolicy": spec["query_match_policy"],
                "queryAmbiguityPolicy": spec["query_ambiguity_policy"],
                "queryResolverPolicy": spec["query_resolver_policy"],
            }
        elif query_policy == SOURCE_QUERY_RESOLVER_POLICY:
            query_context = source_query_context(
                spec["query_source_evidence"], spec["query_topic_phrases"],
                spec["query_task_phrases"], records, sequence_source, scope,
                source_snapshot_commit)
        if not isinstance(spec["nodes"], list) or len(spec["nodes"]) < 2:
            raise ValueError(f"Diagram sequence needs at least two nodes: {sequence_id}")
        if not isinstance(spec["edges"], list) or not spec["edges"]:
            raise ValueError(f"Diagram sequence needs at least one edge: {sequence_id}")

        sequence_iri = BASE + "diagrams/" + sequence_id
        local_nodes = {}
        node_orders = []
        sequence_record = {
            "@id": sequence_iri,
            "@type": "Entity",
            "kind": "source-backed-sequence",
            "sequenceId": sequence_id,
            "diagramId": sequence_iri,
            "label": spec["label"],
            "context": spec["context"],
            "conditions": conditions,
            "source": sequence_source,
            "sourceText": sequence_quotes,
            "sourceSnapshotCommit": source_snapshot_commit,
            "sourceVerificationStatus": source_verification_status,
            "liveVerificationStatus": "not-assessed",
            "status": UNVERIFIED,
            "interpretationVerificationStatus": "not-assessed",
            "interpretationVerificationBasis": "no-current-hash-bound-faceted-source-assessment",
            "interpretationVerificationAssessments": [],
            "orderingSemantics": spec["ordering_semantics"],
            "audience": scope[0],
            "assistants": sorted(scope[1]),
        }
        sequence_record.update(query_context)
        if spec.get("source_process_id"):
            sequence_record["sourceProcess"] = spec["source_process_id"]
        if icon_catalog.get("commit"):
            sequence_record["iconCatalogCommit"] = icon_catalog["commit"]
        output["entities/diagram-sequences.jsonld"].append(sequence_record)

        for node in spec["nodes"]:
            node_id = validate_common_id(node.get("id"), "node ID", node_ids)
            if node_id in local_nodes:
                raise ValueError(f"Duplicate node in diagram: {sequence_id}/{node_id}")
            refs, selected = evidence_refs(node.get("source"), "node source", scope)
            quotes = validate_quotes(node.get("source_text"), refs, selected, "node sourceText")
            if {item["sourceVerificationStatus"] for item in selected} != {
                    source_verification_status}:
                raise ValueError(f"Diagram node source verification state differs: {sequence_id}/{node_id}")
            icon_id = node.get("icon_id")
            if icon_id is not None and icon_id not in allowed_icons:
                raise ValueError(f"Diagram icon is not allow-listed: {icon_id}")
            order = node.get("order")
            if type(order) is not int or order < 1:
                raise ValueError(f"Invalid node order: {sequence_id}/{node_id}")
            node_iri = BASE + "diagram-nodes/" + sequence_id + "/" + node_id
            local_nodes[node_id] = node_iri
            node_orders.append(order)
            record = {
                "@id": node_iri,
                "@type": "Entity",
                "kind": "diagram-node",
                "nodeId": sequence_id + ":" + node_id,
                "diagramId": sequence_iri,
                "order": order,
                "label": node.get("label"),
                "source": refs,
                "sourceText": quotes,
                "conditions": strings(node.get("conditions", []), "node conditions", allow_empty=True),
                "sourceSnapshotCommit": source_snapshot_commit,
                "sourceVerificationStatus": source_verification_status,
                "liveVerificationStatus": "not-assessed",
                "status": UNVERIFIED,
                "interpretationVerificationStatus": "not-assessed",
                "interpretationVerificationBasis": "no-current-hash-bound-faceted-source-assessment",
                "interpretationVerificationAssessments": [],
                "audience": scope[0],
                "assistants": sorted(scope[1]),
            }
            if not isinstance(record["label"], str) or not record["label"].strip():
                raise ValueError(f"Invalid node label: {sequence_id}/{node_id}")
            if icon_id is not None:
                record["iconId"] = icon_id
            output["entities/diagram-nodes.jsonld"].append(record)
        if sorted(node_orders) != list(range(1, len(spec["nodes"]) + 1)):
            raise ValueError(f"Diagram node order is not consecutive: {sequence_id}")

        edge_orders = []
        for edge in spec["edges"]:
            edge_id = validate_common_id(edge.get("id"), "edge ID", edge_ids)
            source_node, target_node = edge.get("from"), edge.get("to")
            if source_node not in local_nodes or target_node not in local_nodes or source_node == target_node:
                raise ValueError(f"Diagram edge endpoint is missing or invalid: {sequence_id}/{edge_id}")
            refs, selected = evidence_refs(edge.get("source"), "edge source", scope)
            quotes = validate_quotes(edge.get("source_text"), refs, selected, "edge sourceText")
            if {item["sourceVerificationStatus"] for item in selected} != {
                    source_verification_status}:
                raise ValueError(f"Diagram edge source verification state differs: {sequence_id}/{edge_id}")
            order = edge.get("order")
            if type(order) is not int or order < 1:
                raise ValueError(f"Invalid edge order: {sequence_id}/{edge_id}")
            if (any(not isinstance(edge.get(field), str) or not edge[field].strip()
                    for field in ("predicate", "label")) or
                    edge["predicate"] not in allowed_predicates):
                raise ValueError(f"Invalid diagram edge predicate or label: {sequence_id}/{edge_id}")
            edge_iri = BASE + "diagram-edges/" + sequence_id + "/" + edge_id
            edge_orders.append(order)
            output["claims/diagram-edges.jsonld"].append({
                "@id": edge_iri,
                "@type": "Relationship",
                "kind": "diagram-edge",
                "edgeId": sequence_id + ":" + edge_id,
                "diagramId": sequence_iri,
                "subject": local_nodes[source_node],
                "object": local_nodes[target_node],
                "fromNode": local_nodes[source_node],
                "toNode": local_nodes[target_node],
                "predicate": edge["predicate"],
                "label": edge["label"],
                "order": order,
                "source": refs,
                "sourceText": quotes,
                "conditions": strings(edge.get("conditions", []), "edge conditions", allow_empty=True),
                "sourceSnapshotCommit": source_snapshot_commit,
                "sourceVerificationStatus": source_verification_status,
                "liveVerificationStatus": "not-assessed",
                "status": UNVERIFIED,
                "interpretationVerificationStatus": "not-assessed",
                "interpretationVerificationBasis": "no-current-hash-bound-faceted-source-assessment",
                "interpretationVerificationAssessments": [],
                "audience": scope[0],
                "assistants": sorted(scope[1]),
            })
        if sorted(edge_orders) != list(range(1, len(spec["edges"]) + 1)):
            raise ValueError(f"Diagram edge order is not consecutive: {sequence_id}")

        member_sources = {
            ref for record in output["entities/diagram-nodes.jsonld"] +
            output["claims/diagram-edges.jsonld"]
            if record["diagramId"] == sequence_iri for ref in record["source"]
        }
        if not member_sources.issubset(set(sequence_source)):
            raise ValueError(f"Diagram source omits member evidence: {sequence_id}")

    processes = sorted((record for record in records.values()
                        if record.get("@type") == "Entity" and
                        record.get("kind") == projection["process_kind"]),
                       key=lambda record: record["@id"])
    process_steps = {}
    for record in records.values():
        if (record.get("@type") == "Claim" and
                record.get("status") == projection["step_status"]):
            process_steps.setdefault(record.get("subject"), []).append(record)
    for process in processes:
        if process.get("status") != projection["process_status"]:
            raise ValueError(f"Ordered procedure process status is unsupported: {process['@id']}")
        steps = sorted(process_steps.get(process["@id"], []), key=lambda item: item.get("order", 0))
        if (len(steps) < 2 or
                any(type(item.get("order")) is not int for item in steps) or
                [item.get("order") for item in steps] != list(range(1, len(steps) + 1))):
            raise ValueError(f"Ordered procedure steps are missing or nonconsecutive: {process['@id']}")
        process_source = process.get("source")
        process_refs = [process_source] if isinstance(process_source, str) else process_source
        if not isinstance(process_refs, list) or not process_refs:
            raise ValueError(f"Ordered procedure has no source evidence: {process['@id']}")
        source_refs = list(process_refs)
        for step in steps:
            step_source = step.get("source")
            step_refs = [step_source] if isinstance(step_source, str) else step_source
            if not isinstance(step_refs, list) or not step_refs:
                raise ValueError(f"Ordered procedure step has no source evidence: {step['@id']}")
            step_value = step.get("value")
            if not isinstance(step_value, str) or not step_value.strip():
                raise ValueError(f"Ordered procedure step has no source-backed label: {step['@id']}")
            if not any(step_value in evidence[identity].get("text", "") and
                       re.match(r"^\s*" + str(step["order"]) + r"\s*[.)]",
                                evidence[identity].get("text", ""))
                       for identity in step_refs if identity in evidence):
                raise ValueError(f"Ordered procedure step order or label is not source-backed: {step['@id']}")
            source_refs.extend(step_refs)
        source_refs = list(dict.fromkeys(source_refs))
        if any(identity not in evidence for identity in source_refs):
            missing = next(identity for identity in source_refs if identity not in evidence)
            raise ValueError(f"Ordered procedure references missing evidence: {missing}")
        sequence_id = validate_common_id(
            "source-procedure-" + process["@id"].rsplit("/", 1)[-1],
            "sequence ID", sequence_ids)
        nodes = []
        edges = []
        for step in steps:
            order = step["order"]
            node_id = validate_common_id(
                f"{sequence_id}-step-{order}", "node ID", node_ids)
            evidence_refs_for_step = [step["source"]] if isinstance(step["source"], str) else step["source"]
            nodes.append({
                "id": node_id,
                "order": order,
                "label": step.get("value"),
                "conditions": step.get("conditions", []),
                "source": evidence_refs_for_step,
                "source_text": [evidence[identity]["text"] for identity in evidence_refs_for_step],
            })
            if order < len(steps):
                next_step = steps[order]
                next_evidence_refs = ([next_step["source"]] if isinstance(next_step["source"], str)
                                      else next_step["source"])
                edge_id = validate_common_id(
                    f"{sequence_id}-step-{order}-precedes-step-{order + 1}",
                    "edge ID", edge_ids)
                edges.append({
                    "id": edge_id,
                    "order": order,
                    "from": node_id,
                    "to": f"{sequence_id}-step-{order + 1}",
                    "predicate": projection["edge_predicate"],
                    "label": "Next source-ordered procedure step",
                    "conditions": [],
                    "source": list(dict.fromkeys(evidence_refs_for_step + next_evidence_refs)),
                    "source_text": list(dict.fromkeys(
                        [evidence[identity]["text"] for identity in evidence_refs_for_step + next_evidence_refs])),
                })
        process_label = process.get("label")
        if not isinstance(process_label, str) or not process_label.strip():
            raise ValueError(f"Ordered procedure has no label: {process['@id']}")
        context_quotes = [evidence[identity]["text"] for identity in process_refs]
        output["entities/diagram-sequences.jsonld"].append({
            "@id": BASE + "diagrams/" + sequence_id,
            "@type": "Entity",
            "kind": "source-backed-sequence",
            "sequenceId": sequence_id,
            "diagramId": BASE + "diagrams/" + sequence_id,
            "label": process_label.replace("-", " "),
            "context": " ".join(context_quotes),
            "conditions": strings(process.get("conditions", []), "procedure conditions", allow_empty=True),
            "source": source_refs,
            "sourceText": [evidence[identity]["text"] for identity in source_refs],
            "sourceSnapshotCommit": source_snapshot_commit,
            "sourceVerificationStatus": evidence[process_refs[0]]["sourceVerificationStatus"],
            "liveVerificationStatus": "not-assessed",
            "status": UNVERIFIED,
            "interpretationVerificationStatus": "not-assessed",
            "interpretationVerificationBasis": "no-current-hash-bound-faceted-source-assessment",
            "interpretationVerificationAssessments": [],
            "orderingSemantics": (
                "Node order follows the source-recorded procedure step order; adjacent edges "
                "encode that explicit order only, not a live execution trace."),
            "audience": process.get("audience"),
            "assistants": sorted(process.get("assistants", [])),
            "iconCatalogCommit": icon_catalog["commit"],
            "sourceProcess": process["@id"],
        })
        output["entities/diagram-nodes.jsonld"].extend({
            "@id": BASE + "diagram-nodes/" + sequence_id + "/" + node["id"],
            "@type": "Entity",
            "kind": "diagram-node",
            "nodeId": sequence_id + ":" + node["id"],
            "diagramId": BASE + "diagrams/" + sequence_id,
            "order": node["order"],
            "label": node["label"],
            "source": node["source"],
            "sourceText": node["source_text"],
            "conditions": node["conditions"],
            "sourceSnapshotCommit": source_snapshot_commit,
            "sourceVerificationStatus": evidence[node["source"][0]]["sourceVerificationStatus"],
            "liveVerificationStatus": "not-assessed",
            "status": UNVERIFIED,
            "interpretationVerificationStatus": "not-assessed",
            "interpretationVerificationBasis": "no-current-hash-bound-faceted-source-assessment",
            "interpretationVerificationAssessments": [],
            "audience": process.get("audience"),
            "assistants": sorted(process.get("assistants", [])),
        } for node in nodes)
        output["claims/diagram-edges.jsonld"].extend({
            "@id": BASE + "diagram-edges/" + sequence_id + "/" + edge["id"],
            "@type": "Relationship",
            "kind": "diagram-edge",
            "edgeId": sequence_id + ":" + edge["id"],
            "diagramId": BASE + "diagrams/" + sequence_id,
            "subject": BASE + "diagram-nodes/" + sequence_id + "/" + edge["from"],
            "object": BASE + "diagram-nodes/" + sequence_id + "/" + edge["to"],
            "fromNode": BASE + "diagram-nodes/" + sequence_id + "/" + edge["from"],
            "toNode": BASE + "diagram-nodes/" + sequence_id + "/" + edge["to"],
            "predicate": edge["predicate"],
            "label": edge["label"],
            "order": edge["order"],
            "source": edge["source"],
            "sourceText": edge["source_text"],
            "conditions": edge["conditions"],
            "sourceSnapshotCommit": source_snapshot_commit,
            "sourceVerificationStatus": evidence[edge["source"][0]]["sourceVerificationStatus"],
            "liveVerificationStatus": "not-assessed",
            "status": UNVERIFIED,
            "interpretationVerificationStatus": "not-assessed",
            "interpretationVerificationBasis": "no-current-hash-bound-faceted-source-assessment",
            "interpretationVerificationAssessments": [],
            "audience": process.get("audience"),
            "assistants": sorted(process.get("assistants", [])),
        } for edge in edges)
    combined_records = {identity: record for identity, record in records.items()
                        if not is_companion(record)}
    combined_records.update({record["@id"]: record for profile in profiles
                             for record in ([profile] if profile.get("@type") == "KnowledgeProfile"
                                            else [])})
    combined_records.update({record["@id"]: record
                             for values in output.values() for record in values})
    companions, _ = build_companions(config, combined_records, source_snapshot_commit)
    output["claims/diagram-companions.jsonld"] = companions
    combined_records.update({record["@id"]: record for record in companions})
    validate_records(combined_records, config, source_snapshot_commit)
    return output


def validate_records(records, config, source_snapshot_commit):
    # Validate the same structural derivation before and after the single review gate.
    records = {identity: dict(record) for identity, record in records.items()}
    for record in records.values():
        if record.get("publicationProposalId"):
            if record.get("verificationStatus") != "verified" or not record.get("reviewedBy"):
                raise ValueError("Approved diagram record lacks human attribution")
            for key in ("reviewStatus", "verificationStatus", "reviewedBy", "reviewedAt",
                        "publicationReview", "publicationProposalId"):
                record.pop(key, None)
            if record.get("interpretationVerificationBasis") == "human-approved-markdown-publication":
                record.update(status=UNVERIFIED, interpretationVerificationStatus="not-assessed",
                              interpretationVerificationBasis="no-current-hash-bound-faceted-source-assessment",
                              interpretationVerificationAssessments=[], liveVerificationStatus="not-assessed")
    """Reject malformed or incomplete diagram membership and evidence in a graph snapshot."""
    allowed_icons = set(config["icon_catalog"]["allowed_ids"])
    allowed_predicates = set(config["predicate_allowlist"])
    sequences = {identity: record for identity, record in records.items()
                 if record.get("@type") == "Entity" and
                 record.get("kind") == "source-backed-sequence"}
    nodes = [record for record in records.values()
             if record.get("@type") == "Entity" and record.get("kind") == "diagram-node" and
             (record.get("status") == UNVERIFIED or "nodeId" in record)]
    edges = [record for record in records.values()
             if record.get("@type") == "Relationship" and
             (record.get("kind") == "diagram-edge" or "edgeId" in record)]
    if not sequences or not nodes or not edges:
        raise ValueError("Source-backed diagram sequences, nodes, or edges are missing")

    def refs(record, field):
        value = record.get(field, [])
        return value if isinstance(value, list) else [value]

    def check_evidence(record):
        citations = refs(record, "source")
        quotes = refs(record, "sourceText")
        if not citations or not quotes or any(not isinstance(quote, str) or not quote for quote in quotes):
            raise ValueError(f"Diagram record is missing evidence or source text: {record['@id']}")
        cited = []
        for identity in citations:
            item = records.get(identity)
            if (item is None or item.get("@type") != "Evidence" or
                    item.get("sourceVerificationStatus") not in {"verified", "not-assessed"} or
                    item.get("snapshotCommit") != source_snapshot_commit or
                    not re.fullmatch(r"[a-f0-9]{64}", item.get("sha256", ""))):
                raise ValueError(f"Diagram record cites unavailable or unverified evidence: {record['@id']}")
            if (item.get("audience") != record.get("audience") or
                    set(item.get("assistants", [])) != set(record.get("assistants", []))):
                raise ValueError(f"Diagram evidence scope mismatch: {record['@id']}")
            cited.append(item)
        if ({item["sourceVerificationStatus"] for item in cited} !=
                {record.get("sourceVerificationStatus")}):
            raise ValueError(f"Diagram source verification state mismatch: {record['@id']}")
        if (any(not any(quote in item.get("text", "") for item in cited) for quote in quotes) or
                any(not any(quote in item.get("text", "") for quote in quotes) for item in cited)):
            raise ValueError(f"Diagram source text does not match its cited evidence: {record['@id']}")

    def check_status(record):
        if (record.get("status") != UNVERIFIED or
                record.get("interpretationVerificationStatus") != "not-assessed" or
                record.get("interpretationVerificationBasis") !=
                "no-current-hash-bound-faceted-source-assessment" or
                record.get("interpretationVerificationAssessments") != [] or
                record.get("liveVerificationStatus") != "not-assessed" or
                record.get("sourceSnapshotCommit") != source_snapshot_commit):
            raise ValueError(f"Diagram source/interpretation/live status mismatch: {record['@id']}")

    query_profiles = {record.get("profileId"): record for record in records.values()
                      if record.get("@type") == "KnowledgeProfile"}
    if len(query_profiles) != sum(record.get("@type") == "KnowledgeProfile"
                                  for record in records.values()):
        raise ValueError("Knowledge profile IDs are not unique")
    route_groups = {}
    for record in records.values():
        if record.get("routeId"):
            route_groups.setdefault(record["routeId"], []).append(record)
    declared_canonicals = [
        record for record in records.values()
        if record.get("@type") == "Relationship" and
        record.get("predicate") == "declares-canonical-resource"
    ]
    for identity, sequence in sequences.items():
        sequence_id = sequence.get("sequenceId")
        if (sequence.get("diagramId") != identity or
                not isinstance(sequence_id, str) or
                not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", sequence_id) or
                identity != BASE + "diagrams/" + sequence_id or
                sequence.get("iconCatalogCommit") != config["icon_catalog"]["commit"]):
            raise ValueError(f"Diagram sequence has missing or incorrect self-membership: {identity}")
        check_status(sequence)
        check_evidence(sequence)
        source_process_id = sequence.get("sourceProcess")
        if source_process_id:
            process = records.get(source_process_id)
            process_sources = process.get("source") if process else None
            process_sources = ([process_sources] if isinstance(process_sources, str)
                               else process_sources)
            if (process is None or process.get("@type") != "Entity" or
                    process.get("kind") != "documented-resource-onboarding-process" or
                    process.get("status") != "source-explicit-procedure" or
                    not isinstance(process_sources, list) or
                    not set(process_sources).issubset(refs(sequence, "source")) or
                    process.get("audience") != sequence.get("audience") or
                    set(process.get("assistants", [])) != set(sequence.get("assistants", []))):
                raise ValueError(f"Diagram source process link is invalid: {identity}")
        query_fields = {
            "queryProfileId", "queryEntity", "queryRouteId", "queryAliasSource",
            "queryRouteCanonicalResource", "queryAliases", "queryTaskAliases",
            "queryAmbiguousTerms", "queryMatchPolicy", "queryAmbiguityPolicy",
            "queryResolverPolicy",
        }
        source_query_fields = {
            "queryResolverPolicy", "querySourceEvidence",
            "queryTopicPhrases", "queryTaskPhrases",
        }
        present_query_fields = (query_fields | source_query_fields).intersection(sequence)
        query_policy = sequence.get("queryResolverPolicy")
        if present_query_fields:
            if query_policy is not None and not isinstance(query_policy, str):
                raise ValueError(f"Diagram query resolver policy is unsupported: {identity}")
            expected_query_fields = {
                QUERY_RESOLVER_POLICY: query_fields,
                SOURCE_QUERY_RESOLVER_POLICY: source_query_fields,
            }.get(query_policy)
            if query_policy is not None and expected_query_fields is None:
                raise ValueError(f"Diagram query resolver policy is unsupported: {identity}")
            if present_query_fields != expected_query_fields:
                raise ValueError(f"Diagram query context is incomplete or mixes policies: {identity}")
        if query_policy == SOURCE_QUERY_RESOLVER_POLICY:
            source_query_context(
                sequence["querySourceEvidence"], sequence["queryTopicPhrases"],
                sequence["queryTaskPhrases"], records, refs(sequence, "source"),
                (sequence["audience"], frozenset(sequence["assistants"])),
                source_snapshot_commit)
        elif query_policy == QUERY_RESOLVER_POLICY:
            profile = query_profiles.get(sequence["queryProfileId"])
            entity = records.get(sequence["queryEntity"])
            route_matches = route_groups.get(sequence["queryRouteId"], [])
            route = route_matches[0] if len(route_matches) == 1 else None
            alias_source = records.get(sequence["queryAliasSource"])
            route_canonical = records.get(sequence["queryRouteCanonicalResource"])
            canonical_links = [record for record in declared_canonicals
                               if record.get("subject") == sequence["queryAliasSource"] and
                               record.get("object") == sequence["queryRouteCanonicalResource"]]
            ambiguous_terms = refs(sequence, "queryAmbiguousTerms")
            if (profile is None or entity is None or entity.get("@type") != "Entity" or
                    route is None or route.get("@type") != "Claim" or alias_source is None or
                    alias_source.get("@type") != "Entity" or route.get("subject") != alias_source["@id"] or
                    route_canonical is None or route_canonical.get("@type") != "Entity" or
                    len(canonical_links) != 1 or
                    sequence.get("queryAliases") != alias_source.get("aliases", []) or
                    sequence.get("queryTaskAliases") != route.get("taskAliases", []) or
                    not sequence.get("queryAliases") or not sequence.get("queryTaskAliases") or
                    not ambiguous_terms or len(ambiguous_terms) != len(set(ambiguous_terms)) or
                    not set(ambiguous_terms).issubset(
                        set(sequence["queryAliases"]) | set(sequence["queryTaskAliases"]))):
                raise ValueError(f"Diagram query context or declared aliases are invalid: {identity}")
            for item in (profile, entity, route, alias_source, route_canonical, canonical_links[0]):
                if (item.get("audience") != sequence.get("audience") or
                        set(item.get("assistants", [])) != set(sequence.get("assistants", []))):
                    raise ValueError(f"Diagram query context scope mismatch: {identity}")
            if (canonical_links[0].get("audience") != sequence.get("audience") or
                    set(canonical_links[0].get("assistants", [])) != set(sequence.get("assistants", []))):
                raise ValueError(f"Diagram route canonical link scope mismatch: {identity}")
        if (not isinstance(sequence.get("conditions"), list) or
                any(not isinstance(value, str) or not value.strip()
                    for value in sequence["conditions"])):
            raise ValueError(f"Diagram sequence conditions are invalid: {identity}")
        member_nodes = [record for record in nodes if record.get("diagramId") == identity]
        member_edges = [record for record in edges if record.get("diagramId") == identity]
        if len(member_nodes) < 2 or not member_edges:
            raise ValueError(f"Diagram sequence has missing nodes or edges: {identity}")
        if any(record.get("diagramId") not in sequences for record in member_nodes + member_edges):
            raise ValueError(f"Diagram node or edge has missing sequence membership: {identity}")
        if not set(ref for record in member_nodes + member_edges for ref in refs(record, "source")).issubset(
                set(refs(sequence, "source"))):
            raise ValueError(f"Diagram sequence omits member evidence: {identity}")
        seen_node_ids = set()
        for record in member_nodes:
            check_status(record)
            check_evidence(record)
            if (not record.get("nodeId") or record.get("order") is None or
                    record.get("iconId") is not None and record.get("iconId") not in allowed_icons or
                    not isinstance(record.get("conditions"), list) or
                    any(not isinstance(value, str) or not value.strip()
                        for value in record["conditions"])):
                raise ValueError(f"Diagram node has invalid ID, order, or icon: {record['@id']}")
            prefix = sequence_id + ":"
            local_id = record["nodeId"][len(prefix):] if record["nodeId"].startswith(prefix) else ""
            if (not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", local_id) or
                    record["nodeId"] in seen_node_ids):
                raise ValueError(f"Diagram node ID is invalid or duplicated: {record['@id']}")
            seen_node_ids.add(record["nodeId"])
        seen_edge_ids = set()
        for record in member_edges:
            check_status(record)
            check_evidence(record)
            if (not record.get("edgeId") or record.get("predicate") not in allowed_predicates or
                    record.get("fromNode") != record.get("subject") or
                    record.get("toNode") != record.get("object") or
                    not isinstance(record.get("conditions"), list) or
                    any(not isinstance(value, str) or not value.strip()
                        for value in record["conditions"])):
                raise ValueError(f"Diagram edge has invalid ID, predicate, or direction: {record['@id']}")
            prefix = sequence_id + ":"
            local_id = record["edgeId"][len(prefix):] if record["edgeId"].startswith(prefix) else ""
            if (not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", local_id) or
                    record["edgeId"] in seen_edge_ids):
                raise ValueError(f"Diagram edge ID is invalid or duplicated: {record['@id']}")
            seen_edge_ids.add(record["edgeId"])
            source_node = records.get(record.get("fromNode"))
            target_node = records.get(record.get("toNode"))
            if (source_node not in member_nodes or target_node not in member_nodes or
                    source_node.get("diagramId") != identity or target_node.get("diagramId") != identity):
                raise ValueError(f"Diagram edge endpoint is not a member node: {record['@id']}")
        for member_records, key in ((member_nodes, "order"), (member_edges, "order")):
            orders = [record.get(key) for record in member_records]
            if (any(type(order) is not int or order < 1 for order in orders) or
                    sorted(orders) != list(range(1, len(orders) + 1))):
                raise ValueError(f"Diagram order is missing, duplicated, or nonconsecutive: {identity}")
        if sequence.get("sourceProcess"):
            node_orders = {record["@id"]: record["order"] for record in member_nodes}
            for edge in member_edges:
                if (edge["predicate"] != "precedes" or
                        node_orders[edge["toNode"]] != node_orders[edge["fromNode"]] + 1):
                    raise ValueError(
                        f"Source procedure edge must point to the next higher-order node: {edge['@id']}")
    expected_nodes = {record["@id"] for record in nodes}
    expected_edges = {record["@id"] for record in edges}
    member_node_ids = {record["@id"] for identity in sequences
                       for record in nodes if record.get("diagramId") == identity}
    member_edge_ids = {record["@id"] for identity in sequences
                       for record in edges if record.get("diagramId") == identity}
    if expected_nodes != member_node_ids or expected_edges != member_edge_ids:
        raise ValueError("Diagram nodes or edges are missing valid sequence membership")
    companions, _ = build_companions(config, records, source_snapshot_commit)
    expected_companions = {record["@id"]: record for record in companions}
    actual_companions = {
        identity: {key: value for key, value in record.items() if key not in {
            "reviewStatus", "verificationStatus", "reviewedBy", "reviewedAt",
            "publicationReview", "publicationProposalId"}}
        for identity, record in records.items()
        if is_companion(record)
    }
    if actual_companions != expected_companions:
        raise ValueError("Process companion records differ from source-declared applicability")
