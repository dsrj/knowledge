"""Extract only semantics explicitly expressed by Markdown structure and metadata."""
import hashlib
import posixpath
import re
from collections import defaultdict
from urllib.parse import quote

BASE = "https://github.com/almbrand/cloudops-openai-hub-knowledge-source/knowledge-graph/"


def iri(kind, name):
    return BASE + kind + "/" + quote(name, safe="-._~")


def token(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:20]


def cells(line):
    # Backslash-escaped pipes are data, not delimiters. Ignore malformed tables.
    line = line.strip()
    if not (line.startswith("|") and line.endswith("|")):
        return None
    result = re.split(r"(?<!\\)\|", line[1:-1])
    return [cell.strip() for cell in result]


# Only these source-authored column contracts establish a semantic field role.
TABLE_FIELDS = {
    ("Policy", "Effect", "Assignment scope", "Source-defined target or behavior", "Reason"):
        ("label", "documented-policy-effect", "documented-assignment-scope",
         "documented-policy-target", "documented-policy-rationale"),
    ("Definition resource label", "Effect", "Source-defined behavior"):
        ("label", "documented-policy-effect", "documented-policy-target"),
    ("Private Endpoint service", "Subresource", "Private DNS zone"):
        ("label", "documented-private-endpoint-subresources", "documented-private-dns-zones"),
    ("Definition", "Recommended setting / effect", "Why", "Implementation and specific check"):
        ("label", "documented-policy-target-and-effect", "documented-policy-rationale",
         "documented-implementation-and-validation"),
    ("Definition", "Target/effect and reason", "Implementation and validation"):
        ("label", "documented-policy-target-effect-and-reason", "documented-implementation-and-validation"),
    ("Policy/control", "Target, reason and effect", "Implementation and validation"):
        ("label", "documented-policy-target-effect-and-reason", "documented-implementation-and-validation"),
    ("Policy", "Target and effect", "Why", "Implementation and validation"):
        ("label", "documented-policy-target-and-effect", "documented-policy-rationale",
         "documented-implementation-and-validation"),
    ("Definition/control", "Target, effect and reason", "Implementation and validation"):
        ("label", "documented-policy-target-effect-and-reason", "documented-implementation-and-validation"),
    ("Module", "Setting, intent and effect", "Implementation/validation boundary"):
        ("label", "documented-policy-target-effect-and-reason", "documented-implementation-and-validation"),
    ("Setting", "Required value or action", "Why", "Applicability/owner"):
        ("label", "documented-required-setting", "documented-rationale", "documented-applicability-and-owner"),
    ("Control", "Required setting or action", "Reason", "Policy / responsibility"):
        ("label", "documented-required-setting", "documented-rationale", "documented-policy-and-owner"),
    ("Identity", "Created by", "Used by", "Authentication"):
        ("label", "documented-identity-producer", "documented-identity-consumer", "documented-authentication"),
    ("Secret name", "Purpose", "Status"):
        ("label", "documented-secret-purpose", "documented-credential-status"),
    ("Data", "Owner", "Why Terraform cannot rebuild it"):
        ("label", "documented-data-owner", "documented-nonterraform-recovery-requirement"),
    ("Subnet", "Intended use", "GSA ports"):
        ("label", "documented-subnet-purpose", "documented-gsa-ports"),
    ("Purpose", "Enterprise application service principal name"):
        ("label", "documented-gsa-application-name-pattern"),
    ("Output", "Secret name pattern"):
        ("label", "documented-output-secret-name-pattern"),
    ("Tag", "Management", "Scope or notes"):
        ("label", "documented-tag-management", "documented-tag-applicability"),
    ("Tag", "Purpose, target behavior and reason"):
        ("label", "documented-tag-target-behavior-and-reason"),
    ("Mode", "What it does", "When to use"):
        ("label", "documented-workflow-behavior", "documented-workflow-applicability"),
    ("Release implementation rule", "Meaning for a request"):
        ("label", "documented-production-implementation-boundary"),
    ("Method", "Required team-managed inputs"):
        ("label", "documented-required-inputs"),
    ("Change", "Owner-confirmed timing and interpretation"):
        ("label", "documented-timing-and-evidence-limit"),
    ("Scenario", "Approach"):
        ("label", "documented-recovery-branch"),
    ("Application name in the error", "Request in Omada"):
        ("label", "documented-omada-request"),
    ("Diagnostic", "Likely cause and action"):
        ("label", "documented-proposed-cause-and-action"),
    ("Area", "Confirmation needed"):
        ("label", "documented-unresolved-owner-question"),
    ("Surface", "Required boundary"):
        ("label", "documented-implementation-boundary"),
    ("Risk", "Controls and reason", "Remaining responsibility"):
        ("label", "documented-risk-control-and-reason", "documented-remaining-responsibility"),
    ("Repo", "Owns", "Key inputs", "State key (`bl-conn-level01-tfstate-001`)"):
        ("label", "documented-repository-ownership", "documented-repository-prerequisites", "documented-state-key"),
    ("Layer", "Repository", "What it creates"):
        ("label", "documented-layer-repository", "documented-layer-responsibilities"),
    ("Subscription", "Management group", "Owning repo (Level 01/02)"):
        ("label", "documented-subscription-management-group", "documented-subscription-owning-repository"),
    ("State account", "Container", "Used by"):
        ("label", "documented-state-container", "documented-state-consumer"),
    ("Wave", "Repository", "Must exist first", "Why"):
        ("label", "documented-recovery-wave-repositories", "documented-recovery-prerequisites",
         "documented-recovery-order-rationale"),
    ("Assistant", "Use it to", "Who can use it"):
        ("label", "documented-assistant-responsibilities", "documented-assistant-access-boundary"),
    ("Term", "Meaning in this Hub", "Distinction that affects the answer"):
        ("label", "documented-domain-meaning", "documented-domain-disambiguation"),
    ("Repo", "Commit"):
        ("label", "source-declared-upstream-revision"),
    ("Repo", "Commit", "State key"):
        ("label", "source-declared-upstream-revision", "documented-state-key"),
    ("Consumer", "Reads state key", "Producer"):
        ("label", "documented-remote-state-read", "documented-remote-state-producer"),
    ("Container", "Keys"):
        ("label", "documented-state-keys"),
    ("Remote state read", "Producer repo"):
        ("label", "documented-remote-state-producer"),
    ("Question area", "Reference"):
        ("label", "documented-question-reference"),
    ("Area", "Questions"):
        ("label", "documented-topic-questions"),
    ("Repository", "Source-backed policy coverage"):
        ("label", "documented-repository-policy-coverage"),
    ("Repository", "What the checked source establishes"):
        ("label", "documented-repository-evidence-and-limits"),
    ("Source grouping", "Exact active values"):
        ("label", "documented-active-sku-values"),
    ("Overlap", "SecOps definition / explanation reused", "CloudOps implementation and important difference"):
        ("label", "documented-secops-overlap-explanation", "documented-cloudops-overlap-implementation-and-difference"),
    ("Domain or resource condition", "Workflow"):
        ("label", "documented-domain-or-resource-workflow-selection"),
    ("Information", "Example or notes"):
        ("label", "documented-request-field-notes"),
    ("Root domain", "How GSA access works today"):
        ("label", "documented-root-domain-route-qualifications"),
    ("Resource or domain", "Reference"):
        ("label", "documented-resource-reference"),
    ("Answer heading", "Required content"):
        ("label", "documented-setup-answer-section-requirements"),
}
POLICY_DETAILS = {
    "Setting, match, effect and scope": "documented-policy-match-effect-and-scope",
    "Setting, effect and scope": "documented-policy-effect-and-scope",
    "Target, effect and scope": "documented-policy-target-effect-and-scope",
    "Why": "documented-policy-rationale",
    "Implementation and ownership": "documented-policy-implementation-and-owner",
    "Validation and limits": "documented-policy-validation-and-limitations",
}
GSA_STEP_LABELS = {
    "Choose the subnet.": "selects-gsa-private-endpoint-subnet",
    "Create the private endpoint.": "creates-supported-private-endpoint",
    "Request the GSA rule.": "requires-cloudops-fqdn-and-port-rule",
    "Check the connection.": "verifies-dns-and-destination-connectivity",
    "Use the environment's subnet.": "retains-dedicated-environment-subnet",
}


def extract(docs, curated, conflicts, block_parser):
    records = defaultdict(list)
    for file in ("claims/answer-routes.jsonld", "claims/controls.jsonld", "claims/decisions.jsonld",
                 "claims/operational.jsonld", "claims/resource-details.jsonld",
                 "claims/conflicts.jsonld",
                 "claims/copilot-interpretations.jsonld", "entities/copilot-interpreted.jsonld",
                 "processes/copilot-interpreted.jsonld", "claims/copilot-relationships.jsonld",
                 "entities/navigation-anchors.jsonld",
                 "entities/semantic-table-subjects.jsonld", "claims/semantic-table-fields.jsonld",
                 "processes/resource-onboarding.jsonld", "claims/procedure-steps.jsonld",
                 "claims/procedure-relationships.jsonld",
                 "claims/structural-relationships.jsonld", "claims/table-rows.jsonld",
                 "entities/admin-repositories.jsonld", "entities/diagram-nodes.jsonld",
                 "entities/canonical-route-resources.jsonld",
                 "entities/document-references.jsonld", "entities/documents.jsonld",
                 "entities/section-markers.jsonld",
                 "entities/route-resources.jsonld", "entities/sections.jsonld",
                 "evidence/structured.jsonld", "processes/ordered-items.jsonld", "processes/ordered-lists.jsonld"):
        records[file]
    references = defaultdict(list)
    invalidated = []
    existing = set()

    def add(file, record):
        if record["@id"] in existing:
            raise ValueError(f"Duplicate structured record ID: {record['@id']}")
        existing.add(record["@id"])
        records[file].append(record)
        return record["@id"]

    def source(doc, path, start, end, section, key):
        identity = iri("evidence/structure", key)
        if identity not in existing:
            record = {"@id": identity, "@type": "Evidence", "audience": doc["audience"],
                      "assistants": doc["meta"]["assistants"], "path": path,
                      "section": " > ".join(section), "startLine": start + 1, "endLine": end,
                      "sha256": doc["hash"],
                      "sourceVerificationStatus": doc["source_verification_status"],
                      "sourceVerificationBasis": doc["source_verification_basis"],
                      "text": "\n".join(line.rstrip("\r\n") for line in doc["lines"][start:end])}
            if doc["commit"]:
                record["snapshotCommit"] = doc["commit"]
            for name, field in (("source_repository", "declaredSourceRepository"),
                                ("source_path", "declaredSourcePath"),
                                ("source_commit", "declaredSourceCommit")):
                if name in doc["meta"]:
                    record[field] = doc["meta"][name]
            add("evidence/structured.jsonld", record)
        return identity

    def relation(doc, key, subject, predicate, obj, evidence):
        return add("claims/structural-relationships.jsonld",
                   {"@id": iri("relationships/structure", key), "@type": "Relationship",
                    "subject": subject, "object": obj, "predicate": predicate, "source": evidence,
                    "audience": doc["audience"], "assistants": doc["meta"]["assistants"],
                    "status": "source-structure"})

    for item in curated:
        doc = docs[item["path"]]
        interpreted = item.get("origin") == "copilot"
        def find(lines, groups):
            return [(start, end, section) for start, end, kind, section in groups
                    if kind == item.get("kind", "narrative-or-list") and item["section"] in section
                    and item["match"] in "".join(lines[start:end])]
        matches = find(doc["lines"], doc["blocks"])
        baseline = [] if interpreted else find(doc["curation_lines"], block_parser(doc["curation_lines"]))
        if len(matches) != 1 or (not interpreted and len(baseline) != 1):
            invalidated.append({"id": item["id"], "path": item["path"],
                                "reason": "curated operational source ambiguous or missing"})
            continue
        start, end, section = matches[0]
        matched_start = start
        if interpreted:
            if item.get("evidence_scope", "section") == "section":
                section_blocks = [block for block in doc["blocks"] if block[3][:len(section)] == section]
                start, end = min(block[0] for block in section_blocks), max(block[1] for block in section_blocks)
        else:
            old_start, old_end, old_section = baseline[0]
            normalize = lambda lines: [line.rstrip("\r\n") for line in lines]
            if section != old_section or normalize(doc["lines"][start:end]) != normalize(
                    doc["curation_lines"][old_start:old_end]):
                invalidated.append({"id": item["id"], "path": item["path"],
                                    "reason": "curated operational source changed"})
                continue
        key = ("copilot-" if interpreted else "operational-") + item["id"]
        ev = source(doc, item["path"], start, end, section, key)
        subject = iri("sections", doc["meta"]["id"] + "-" + token(" > ".join(section)))
        if interpreted:
            entity = item["entity"]
            scope_key = doc["audience"] + "-" + token("|".join(sorted(doc["meta"]["assistants"])))
            subject = iri("copilot-entities", scope_key + "-" + entity["id"])
            if subject not in existing:
                add("processes/copilot-interpreted.jsonld" if entity["kind"] == "process" else
                    "entities/copilot-interpreted.jsonld",
                    {"@id": subject, "@type": "Entity", "label": entity["label"], "kind": entity["kind"],
                     "source": ev, "audience": doc["audience"], "assistants": doc["meta"]["assistants"],
                     "status": "unverified-copilot-interpretation"})
        claim = {"@id": iri("claims", key), "@type": "Claim", "subject": subject, "source": ev,
                 "text": "\n".join(normalize(doc["lines"][start:end])),
                 "predicate": item["predicate"], "value": item["value"],
                 "status": "unverified-copilot-interpretation" if interpreted else "documented-curated",
                 "audience": doc["audience"], "assistants": doc["meta"]["assistants"]}
        for field in ("condition", "order", "setting", "settingValue", "unit", "valueBasis"):
            if field in item:
                claim[field] = item[field]
        if "owner_confirmation" in item:
            claim["ownerConfirmation"] = item["owner_confirmation"]
            claim["ownerConfirmationProvenance"] = item["owner_confirmation_provenance"]
            claim["interpretationVerificationStatus"] = "not-assessed"
            claim["interpretationVerificationBasis"] = (
                "no-current-hash-bound-faceted-source-assessment")
            claim["interpretationVerificationAssessments"] = []
        add("claims/copilot-interpretations.jsonld" if interpreted else "claims/operational.jsonld", claim)
        if interpreted and "object" in item:
            target = item["object"]
            object_id = iri("copilot-entities", scope_key + "-" + target["id"])
            if object_id not in existing:
                add("entities/copilot-interpreted.jsonld", {"@id": object_id, "@type": "Entity",
                    "label": target["label"], "kind": target["kind"], "source": ev,
                    "audience": doc["audience"], "assistants": doc["meta"]["assistants"],
                    "status": "unverified-copilot-interpretation"})
            add("claims/copilot-relationships.jsonld", {"@id": iri("copilot-relationships", item["id"]),
                "@type": "Relationship", "subject": subject, "object": object_id,
                "predicate": item["predicate"], "source": ev,
                "status": "unverified-copilot-interpretation", "audience": doc["audience"],
                "assistants": doc["meta"]["assistants"],
                **({"condition": item["condition"]} if "condition" in item else {})})
        references[(item["path"], matched_start)].append(claim["@id"])

    operational = {record["@id"].rsplit("/", 1)[-1].removeprefix("operational-"): record
                   for record in records["claims/operational.jsonld"]}
    for conflict in conflicts:
        participants = [operational.get(name) for name in conflict["claims"]]
        if any(record is None for record in participants):
            invalidated.append({"id": conflict["id"], "reason": "conflict claim unavailable",
                                "depends_on": conflict["claims"]})
            continue
        if len(participants) < 2 or len({record["audience"] for record in participants}) != 1:
            raise ValueError(f"Invalid conflict scope or participants: {conflict['id']}")
        common = set(participants[0]["assistants"])
        for participant in participants[1:]:
            common.intersection_update(participant["assistants"])
        if not common:
            raise ValueError(f"Conflict has no shared assistant scope: {conflict['id']}")
        add("claims/conflicts.jsonld", {"@id": iri("conflicts", conflict["id"]), "@type": "Conflict",
            "members": [record["@id"] for record in participants],
            "source": [record["source"] for record in participants], "text": conflict["summary"],
            "status": conflict["status"], "audience": participants[0]["audience"],
            "assistants": sorted(common)})

    for path, doc in docs.items():
        meta = doc["meta"]
        doc_id = meta["id"]
        scope = {"audience": doc["audience"], "assistants": meta["assistants"]}
        front = source(doc, path, 0, doc["blocks"][0][1], [], doc_id + "-frontmatter")
        document = iri("documents", doc_id)
        description_block = next(((start, end, section) for start, end, kind, section in doc["blocks"]
                                  if kind == "narrative-or-list" and section == [meta["title"], "Purpose and scope"]),
                                 None)
        description = {}
        if description_block:
            start, end, section = description_block
            description_source = source(doc, path, start, end, section, doc_id + "-description")
            description = {"description": " ".join(line.strip() for line in doc["lines"][start:end]).strip(),
                           "descriptionSource": description_source}
        add("entities/documents.jsonld", {"@id": document, "@type": "Entity", "kind": "document",
            "label": meta["title"], "source": front, "documentId": doc_id,
            "documentType": meta["document_type"], "reviewStatus": meta.get("review_status", ""),
            "verificationStatus": meta.get("verification_status", ""), **description, **scope})
        references[(path, 0)].append(document)
        if description_block:
            references[(path, description_block[0])].append(document)
        section_ids = {}
        duplicates = defaultdict(int)
        for start, end, kind, section in doc["blocks"]:
            if kind != "heading":
                continue
            section_key = " > ".join(section)
            duplicates[section_key] += 1
            if duplicates[section_key] > 1:
                raise ValueError(f"Duplicate heading path in {path}: {section_key}")
            key = doc_id + "-" + token(section_key)
            ev = source(doc, path, start, end, section, key)
            entity = iri("sections", key)
            add("entities/sections.jsonld", {"@id": entity, "@type": "Entity", "kind": "section",
                "label": section[-1], "section": section_key, "source": ev, **scope})
            section_ids[section_key] = entity
            relation(doc, key + "-within", entity, "section-of", document, ev)
            parent = section_ids.get(" > ".join(section[:-1]))
            if parent:
                relation(doc, key + "-parent", entity, "subsection-of", parent, ev)
            references[(path, start)].append(entity)

        for start, end, kind, section in doc["blocks"]:
            if kind != "navigation-anchor":
                continue
            for line_number in range(start, end):
                match = re.fullmatch(r'\s*<a\s+id="([^"]+)"\s*></a>\s*', doc["lines"][line_number])
                if not match:
                    continue
                anchor_id = match.group(1)
                ev = source(doc, path, line_number, line_number + 1, section,
                            doc_id + "-navigation-anchor-" + anchor_id)
                anchor = iri("navigation-anchors", doc_id + "-" + anchor_id)
                add("entities/navigation-anchors.jsonld", {
                    "@id": anchor, "@type": "Entity", "kind": "source-navigation-anchor",
                    "label": anchor_id, "source": ev, **scope})
                references[(path, start)].append(anchor)
                references[(path, start)].append(
                    relation(doc, doc_id + "-" + anchor_id + "-declared", document,
                             "declares-navigation-anchor", anchor, ev))

        # Routes are author-declared, including conditions and scope. No alias merging.
        route_line = next((i for i, line in enumerate(doc["lines"]) if line.startswith("answers:")), None)
        routes = []
        for route in meta.get("answers", []):
            target = section_ids.get(route["section"])
            if target is None or route_line is None:
                raise ValueError(f"Unresolved answer route {route['id']} in {path}")
            key = doc_id + "-" + route["id"]
            ev = source(doc, path, route_line, route_line + 1, [], doc_id + "-answers")
            resource = iri("route-resources", key)
            add("entities/route-resources.jsonld", {"@id": resource, "@type": "Entity",
                "kind": "author-declared-route-resource", "label": route["resource"],
                "aliases": route["aliases"], "source": ev, **scope})
            routes.append((route["section"], resource, route["task"]))
            canonical_key = route["resource"] + "-" + token("\n".join(sorted(meta["assistants"])))
            canonical = iri("canonical-route-resources", canonical_key)
            if canonical not in existing:
                add("entities/canonical-route-resources.jsonld", {"@id": canonical, "@type": "Entity",
                    "kind": "author-declared-resource-identifier", "label": route["resource"],
                    "source": ev, **scope})
            relation(doc, key + "-canonical", resource, "declares-canonical-resource", canonical, ev)
            answer = iri("answer-routes", key)
            add("claims/answer-routes.jsonld", {"@id": answer, "@type": "Claim",
                "subject": resource, "source": ev, "text": "Author-declared answer route: " + route["id"],
                "routeId": route["id"], "task": route["task"], "taskAliases": route["task_aliases"],
                "support": route["support"], "conditions": route["conditions"], "targetSection": target,
                "status": "author-declared-route", **scope})
            relation(doc, key + "-target", resource, "route-target-section", target, ev)
            references[(path, 0)].append(answer)

        for start, end, kind, section in doc["blocks"]:
            if kind != "narrative-or-list":
                continue
            section_key = " > ".join(section)
            targets = [(heading, resource, task) for heading, resource, task in routes
                       if section_key == heading or section_key.startswith(heading + " > ")]
            if not targets:
                continue
            target_heading, resource, task = max(targets, key=lambda pair: len(pair[0]))
            for i in range(start, end):
                line = doc["lines"][i].rstrip("\r\n")
                match = re.match(r"^\*\*(Subresources|Private DNS zones|If moving an existing endpoint):\*\*\s*(.*)$", line)
                predicate, value, condition = None, None, None
                if match:
                    label, value = match.groups()
                    predicate = {"Subresources": "documented-private-endpoint-subresources",
                                 "Private DNS zones": "documented-private-dns-zones",
                                 "If moving an existing endpoint": "endpoint-migration-warning"}[label]
                    if label == "If moving an existing endpoint":
                        condition = "If moving an existing endpoint"
                elif task == "gsa-access":
                    text = line.strip()
                    if re.match(r"^Connect .+ using a private endpoint plus a CloudOps FQDN rule\.", text):
                        predicate, value = "requires-private-endpoint-and-cloudops-fqdn-rule", text
                    elif text.endswith("GSA sign-in also requires membership in the matching access groups:"):
                        predicate, value = "requires-gsa-signin-membership-in-addition-to-network-path", text
                    elif text == "- **Request subscription access in Omada.**":
                        predicate, value = "requires-omada-subscription-access-request", text
                    elif text == "Only internal Container App Environments are supported through GSA.":
                        predicate, value = "requires-internal-container-app-environment", text
                    elif text.startswith("Open [Omada]") and "Reader access is sufficient for GSA sign-in." in text:
                        predicate, value = "subscription-reader-membership-for-gsa", text
                    elif text.startswith("If you also need subscription Contributor permissions,"):
                        predicate, value = "optional-subscription-contributor-membership", text
                        condition = "If subscription Contributor permissions are also needed"
                    elif text.startswith("- **Wait for the GSA group mapping.**"):
                        predicate, value = "gsa-group-mapping", text
                    elif text.startswith("- **For another team's resource, use its approved delegated GSA application.**"):
                        predicate, value = "delegated-gsa-access", text
                        condition = "For another team's resource"
                if predicate is None:
                    continue
                key = doc_id + "-" + token(target_heading + "\n" + line)
                ev = source(doc, path, i, i + 1, section, key)
                route = next(route for route in meta["answers"] if route["section"] == target_heading)
                context_blocks = [block for block in doc["blocks"] if
                                  " > ".join(block[3]) == target_heading or
                                  " > ".join(block[3]).startswith(target_heading + " > ")]
                context_ev = source(doc, path, min(b[0] for b in context_blocks), max(b[1] for b in context_blocks),
                                    context_blocks[0][3], doc_id + "-" + route["id"] + "-resource-context")
                claim = {"@id": iri("resource-details", key), "@type": "Claim",
                         "subject": resource, "source": [ev, context_ev], "text": line,
                         "predicate": predicate, "value": value,
                         "identifiers": re.findall(r"`([^`]+)`", value),
                         "conditions": route["conditions"],
                         "status": "source-labelled-detail", **scope}
                if condition:
                    claim["condition"] = condition
                add("claims/resource-details.jsonld", claim)
                references[(path, start)].append(claim["@id"])

        for heading, resource, task in routes:
            if task != "gsa-access":
                continue
            route = next(route for route in meta["answers"] if route["section"] == heading)
            route_blocks = [(start, end, kind, section) for start, end, kind, section in doc["blocks"]
                            if " > ".join(section) == heading or
                            " > ".join(section).startswith(heading + " > ")]
            steps = []
            for start, end, kind, section in route_blocks:
                if kind != "narrative-or-list":
                    continue
                for i in range(start, end):
                    match = re.match(r"^(\d+)\.\s+\*\*([^*]+)\*\*\s*(.*)", doc["lines"][i].rstrip("\r\n"))
                    if match and match[2] in GSA_STEP_LABELS:
                        steps.append((i, section, int(match[1]), GSA_STEP_LABELS[match[2]], match[3]))
            if not steps:
                continue
            numbers = [step[2] for step in steps]
            if numbers != list(range(1, len(steps) + 1)):
                raise ValueError(f"Ambiguous GSA onboarding step sequence: {route['id']}")
            key = doc_id + "-" + route["id"]
            process = iri("resource-onboarding", key)
            first, last = min(b[0] for b in route_blocks), max(b[1] for b in route_blocks)
            context_evidence = source(doc, path, first, last, route_blocks[0][3], key + "-procedure-context")
            add("processes/resource-onboarding.jsonld", {"@id": process, "@type": "Entity",
                "kind": "documented-resource-onboarding-process", "label": route["id"],
                "source": context_evidence, "status": "source-explicit-procedure",
                "conditions": route["conditions"], **scope})
            add("claims/procedure-relationships.jsonld", {"@id": iri("procedure-relationships", key),
                "@type": "Relationship", "subject": process, "object": resource,
                "predicate": "documents-resource-onboarding", "source": context_evidence,
                "status": "source-explicit-procedure", "conditions": route["conditions"], **scope})
            for line, section, order, predicate, value in steps:
                step_key = key + "-step-" + str(order)
                ev = source(doc, path, line, line + 1, section, step_key)
                identity = add("claims/procedure-steps.jsonld", {"@id": iri("procedure-steps", step_key),
                    "@type": "Claim", "subject": process, "source": ev, "text": doc["lines"][line].rstrip("\r\n"),
                    "predicate": predicate, "value": value, "order": order, "conditions": route["conditions"],
                    "status": "source-explicit-procedure", **scope})
                block_start = next(start for start, end, _, _ in route_blocks if start <= line < end)
                references[(path, block_start)].append(identity)

        # Tables retain each named column and exact row. These are table observations,
        # not inferred facts about a deployed system.
        for start, end, kind, section in doc["blocks"]:
            if kind != "table" or end - start < 3:
                continue
            header = cells(doc["lines"][start])
            sep = cells(doc["lines"][start + 1])
            if not header or not sep or len(header) != len(sep) or not all(
                    re.fullmatch(r":?-{3,}:?", value.replace(" ", "")) for value in sep):
                continue
            section_key = " > ".join(section)
            section_id = section_ids[section_key]
            semantic_fields = TABLE_FIELDS.get(tuple(header))
            detail_table = header == ["Detail", "Explanation"] and path == "guides/cloudops-policies.md"
            context_evidence = None
            occurrences = defaultdict(int)
            for i in range(start + 2, end):
                row = cells(doc["lines"][i])
                if row is None or len(row) != len(header):
                    continue
                signature = token(section_key + "\n" + doc["lines"][i].rstrip("\r\n"))
                occurrences[signature] += 1
                key = f"{doc_id}-{signature}-{occurrences[signature]}"
                ev = source(doc, path, i, i + 1, section, key)
                entity = iri("table-rows", key)
                add("claims/table-rows.jsonld", {"@id": entity, "@type": "Claim",
                    "subject": section_id, "source": ev, "text": doc["lines"][i].rstrip("\r\n"),
                    "tableColumns": header, "tableValues": row, "status": "source-table-row", **scope})
                references[(path, start)].append(entity)
                fields = ([(POLICY_DETAILS[row[0]], row[1])] if detail_table and row[0] in POLICY_DETAILS
                          else [(predicate, value) for predicate, value in zip(semantic_fields or (), row)
                                if predicate != "label"])
                access_matrix = (path == "guides/azure-network-security-perimeter.md" and header ==
                    ["Resource public access", "No profile association", "Transition access mode", "Enforced access mode"])
                if access_matrix:
                    fields = list(zip(("documented-nsp-unassociated-access", "documented-nsp-transition-access",
                                       "documented-nsp-enforced-access"), row[1:]))
                if fields:
                    if context_evidence is None:
                        section_blocks = [block for block in doc["blocks"]
                                          if block[3][:len(section)] == section]
                        context_evidence = source(doc, path, min(b[0] for b in section_blocks),
                            max(b[1] for b in section_blocks), section,
                            doc_id + "-" + token(section_key) + "-semantic-table-context")
                    subject = iri("semantic-table-subjects", doc_id + "-" + token(
                        section_key + "\n" + ("policy-detail" if detail_table else row[0])))
                    if subject not in existing:
                        add("entities/semantic-table-subjects.jsonld", {"@id": subject, "@type": "Entity",
                            "kind": "source-labelled-table-subject",
                            "label": section[-1] if detail_table else row[0], "source": ev,
                            "status": "source-explicit-field", **scope})
                    for predicate, value in fields:
                        condition = {}
                        if access_matrix:
                            column = next(n for n, field in enumerate(fields, 1) if field[0] == predicate)
                            condition = {"condition": "Resource public access = " + row[0] +
                                         "; association state = " + header[column]}
                        identity = add("claims/semantic-table-fields.jsonld", {
                            "@id": iri("semantic-table-fields", key + "-" + predicate), "@type": "Claim",
                            "subject": subject, "source": [ev, context_evidence],
                            "text": doc["lines"][i].rstrip("\r\n"),
                            "predicate": predicate, "value": value, "status": "source-explicit-field",
                            **condition, **scope})
                        references[(path, start)].append(identity)
                if header == ["Control", "Required setting or action", "Reason", "Policy / responsibility"]:
                    add("claims/controls.jsonld", {"@id": iri("controls", key), "@type": "Claim",
                        "subject": section_id, "source": ev, "text": row[0],
                        "requiredSetting": row[1], "rationale": row[2],
                        "responsibility": row[3], "status": "source-control-row", **scope})
                if meta["document_type"] == "decision" and len(header) == 3 and header[0] == "ID":
                    decision_id = row[0].strip("`")
                    add("claims/decisions.jsonld", {"@id": iri("decisions", decision_id), "@type": "Claim",
                        "subject": section_id, "source": ev, "text": row[1], "decisionId": decision_id,
                        "rationale": row[2], "status": "pending-draft", **scope})

        # Capture ordered list items, including continuation lines, without assuming
        # every numbered list is an actionable workflow or inventing branch conditions.
        for start, end, kind, section in doc["blocks"]:
            if kind != "narrative-or-list":
                continue
            positions = [(i, re.match(r"^(\d+)\.\s+", doc["lines"][i])) for i in range(start, end)]
            positions = [(i, match) for i, match in positions if match]
            if len(positions) < 2:
                continue
            numbers = [int(match.group(1)) for _, match in positions]
            if numbers != list(range(numbers[0], numbers[0] + len(numbers))):
                continue
            section_key = " > ".join(section)
            section_id = section_ids.get(section_key)
            if not section_id:
                continue
            list_key = doc_id + "-" + token(section_key + "\n" + doc["lines"][positions[0][0]])
            list_evidence = source(doc, path, positions[0][0], positions[0][0] + 1, section,
                                   list_key + "-list")
            sequence = iri("ordered-lists", list_key)
            add("processes/ordered-lists.jsonld", {"@id": sequence, "@type": "Entity",
                "kind": "ordered-list", "label": section[-1], "source": list_evidence, **scope})
            relation(doc, list_key + "-section", sequence, "ordered-list-in-section", section_id, list_evidence)
            for n, (i, match) in enumerate(positions):
                stop = positions[n + 1][0] if n + 1 < len(positions) else end
                for continuation in range(i + 1, stop):
                    if not re.match(r"^\s", doc["lines"][continuation]):
                        stop = continuation
                        break
                step_text = "\n".join(line.rstrip("\r\n") for line in doc["lines"][i:stop])
                key = doc_id + "-" + token(section_key + "\n" + step_text)
                ev = source(doc, path, i, stop, section, key)
                entity = iri("ordered-items", key)
                add("processes/ordered-items.jsonld", {"@id": entity, "@type": "Claim",
                    "subject": sequence, "source": ev, "text": step_text, "order": int(match.group(1)),
                    "status": "source-ordered-item", **scope})
                references[(path, start)].append(entity)

        # This specific source table explicitly declares producer/consumer state reads.
        if doc_id == "esm-repository-dependency-map":
            target_section = "Enterprise-scale repository dependency map and run order (admin) > Common questions > Which remote-state reads link the repositories?"
            selected = [b for b in doc["blocks"] if b[2] == "table" and " > ".join(b[3]) == target_section]
            if len(selected) != 1:
                raise ValueError("Remote-state dependency table is missing or ambiguous")
            start, end, _, section = selected[0]
            for i in range(start + 2, end):
                row = cells(doc["lines"][i])
                if not row or len(row) != 3:
                    raise ValueError("Malformed remote-state dependency row")
                consumer, states, producer = row
                if not (re.fullmatch(r"`[^`]+`", consumer) and re.fullmatch(r"`[^`]+`", producer)):
                    continue
                key = doc_id + "-" + token(doc["lines"][i])
                ev = source(doc, path, i, i + 1, section, key)
                for name in (consumer, producer):
                    repo = name.strip("`")
                    rid = iri("admin-repositories", repo)
                    if rid not in existing:
                        add("entities/admin-repositories.jsonld", {"@id": rid, "@type": "Entity",
                            "kind": "repository", "label": repo, "source": ev, **scope})
                relation(doc, key + "-dependency", iri("admin-repositories", consumer.strip("`")),
                         "reads-remote-state-produced-by", iri("admin-repositories", producer.strip("`")), ev)
                references[(path, start)].append(iri("relationships/structure", key + "-dependency"))
    for path, doc in docs.items():
        doc_id = doc["meta"]["id"]
        counts = defaultdict(int)
        for start, end, kind, section in doc["blocks"]:
            if not section:
                continue
            if kind == "narrative-or-list":
                marker_lines = [line_number for line_number in range(start, end)
                                if doc["lines"][line_number].strip()]
                if len(marker_lines) == 1:
                    line_number = marker_lines[0]
                    marker = re.fullmatch(r"\s*\*\*([^*]+)\*\*\s*", doc["lines"][line_number])
                    if marker:
                        section_key = " > ".join(section)
                        key = doc_id + "-section-marker-" + token(str(line_number) + marker.group(1))
                        evidence = source(doc, path, line_number, line_number + 1, section, key)
                        identity = iri("section-markers", key)
                        add("entities/section-markers.jsonld", {
                            "@id": identity, "@type": "Entity", "kind": "source-section-marker",
                            "label": marker.group(1), "source": evidence,
                            "audience": doc["audience"], "assistants": doc["meta"]["assistants"],
                        })
                        relationship = relation(doc, key + "-labels-subsection",
                                                iri("sections", doc_id + "-" + token(section_key)),
                                                "labels-source-subsection", identity, evidence)
                        references[(path, start)].extend((identity, relationship))
            if kind == "code" and any("```mermaid" in line for line in doc["lines"][start:end]):
                node_labels = {}
                edges = []
                for line_number in range(start, end):
                    line = doc["lines"][line_number]
                    for match in re.finditer(r'([A-Za-z0-9_-]+)\["([^"]+)"\]', line):
                        node_labels.setdefault(match.group(1), (match.group(2), line_number))
                    edges.extend((match.group(1), match.group(2), line_number)
                                 for match in re.finditer(
                                     r'([A-Za-z0-9_-]+)(?:\[[^\]]+\])?\s*-->\s*([A-Za-z0-9_-]+)', line))
                node_ids = {}
                for node_id, (label, line_number) in node_labels.items():
                    evidence = source(doc, path, line_number, line_number + 1, section,
                                      f"{doc_id}-diagram-node-{node_id}")
                    identity = iri("diagram-nodes", doc_id + "-" + node_id)
                    if identity not in existing:
                        add("entities/diagram-nodes.jsonld", {
                            "@id": identity, "@type": "Entity", "kind": "diagram-node",
                            "label": label, "source": evidence, "audience": doc["audience"],
                            "assistants": doc["meta"]["assistants"],
                        })
                    node_ids[node_id] = identity
                    references[(path, start)].append(identity)
                for edge_index, (subject, obj, line_number) in enumerate(edges, 1):
                    if subject not in node_ids or obj not in node_ids:
                        raise ValueError(f"Undeclared Mermaid node in {path}:{line_number + 1}")
                    key = f"{doc_id}-diagram-edge-{edge_index}"
                    evidence = source(doc, path, line_number, line_number + 1, section, key)
                    relationship = relation(doc, key, node_ids[subject],
                                            "explicitly-directed-to-in-source-diagram",
                                            node_ids[obj], evidence)
                    references[(path, start)].append(relationship)
            if kind not in ("narrative-or-list", "table"):
                continue
            for line_number in range(start, end):
                for match in re.finditer(r"\[([^\]]+)\]\(([^)\s]+)\)", doc["lines"][line_number]):
                    href = match.group(2)
                    target_path = href.split("#", 1)[0]
                    if not target_path:
                        continue
                    section_key = " > ".join(section)
                    key_base = doc_id + "-" + token(section_key + "\n" + match.group(0))
                    counts[key_base] += 1
                    key = f"{key_base}-{counts[key_base]}"
                    ev = source(doc, path, line_number, line_number + 1, section, key)
                    target = None
                    if "://" not in target_path and target_path.endswith(".md"):
                        target_path = posixpath.normpath(posixpath.join(posixpath.dirname(path), target_path))
                        target = docs.get(target_path)
                    if target and not (doc["audience"] == "guide" and (
                            target["audience"] != "guide" or not
                            set(doc["meta"]["assistants"]).issubset(target["meta"]["assistants"]))):
                        object_id = iri("documents", target["meta"]["id"])
                        predicate = "explicitly-links-to-document"
                    else:
                        scope_key = doc["audience"] + "-" + token("|".join(sorted(doc["meta"]["assistants"])))
                        reference_id = iri("document-references", scope_key + "-" + token(href))
                        if reference_id not in existing:
                            add("entities/document-references.jsonld", {
                                "@id": reference_id, "@type": "Entity", "kind": "document-reference",
                                "label": match.group(1), "text": href, "source": ev,
                                "audience": doc["audience"], "assistants": doc["meta"]["assistants"],
                            })
                        object_id = reference_id
                        predicate = "explicitly-links-to-document-reference"
                    relationship = relation(doc, key, iri("sections", doc_id + "-" + token(section_key)),
                                            predicate, object_id, ev)
                    references[(path, start)].append(relationship)
    return dict(records), references, invalidated
