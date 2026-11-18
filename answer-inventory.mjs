// Authoring coverage, not a Hub routing/alias manifest. Add only source-backed combinations.
const additionalGsaResources = [
  'azure-machine-learning', 'azure-machine-learning-registry', 'azure-ai-services', 'azure-bot-service',
  'azure-synapse-analytics', 'azure-synapse-studio', 'event-hubs', 'azure-data-factory', 'azure-hdinsight',
  'azure-data-explorer', 'power-bi', 'azure-databricks', 'microsoft-fabric', 'azure-batch',
  'azure-virtual-desktop-workspace', 'azure-virtual-desktop-host-pool', 'azure-kubernetes-service',
  'azure-container-registry', 'azure-sql-managed-instance', 'azure-database-for-postgresql',
  'azure-database-for-mysql', 'azure-cosmos-db', 'azure-cosmos-db-postgresql', 'azure-cosmos-db-mongodb-vcore',
  'azure-redis-enterprise', 'azure-managed-redis', 'azure-arc-private-link-scope', 'event-grid',
  'azure-api-management', 'azure-health-data-services', 'iot-hub', 'azure-iot-device-provisioning',
  'azure-device-update', 'azure-iot-central', 'azure-digital-twins', 'azure-ai-video-indexer',
  'automation-accounts', 'azure-backup', 'azure-site-recovery', 'azure-monitor', 'microsoft-purview',
  'azure-migrate', 'azure-resource-manager-private-link', 'azure-managed-grafana', 'azure-managed-prometheus',
  'azure-managed-hsm', 'app-configuration', 'azure-attestation', 'azure-file-sync', 'azure-managed-disks',
  'azure-elastic-san', 'azure-files-standalone', 'azure-ai-search', 'azure-relay', 'azure-signalr',
  'azure-static-web-apps', 'azure-maps', 'azure-web-pubsub',
];
const rows = [
  ['guides/avd-personal-network-access.md', { 'azure-personal-avd': ['request-team-network'] }],
  ['guides/azure-enterprise-tag-setup.md', {
    'azure-resource-group-tags': ['choose-tagging-method', 'create-inherited-tags', 'create-own-appprovider',
      'create-manual-tags', 'configure-catalog-mapping', 'troubleshoot-tag-denial'],
    'azure-subscription-tags': ['configure-tags'], 'azure-owner-cost-mapping': ['correct-mapping'],
  }],
  ['guides/azure-landingzone-user-guide.md', {
    'azure-pim': ['activate-role', 'request-eligibility', 'approve-role', 'configure-role-policy', 'approver-requirements'],
    'azure-subscription': ['request-subscription'], 'azure-contributor-access': ['request-contributor'],
    'azure-firewall': ['request-network-rule'], 'azure-public-network-access': ['request-exception'],
    'azure-cross-subscription-access': ['configure-access'], 'azure-rbac': ['request-custom-role'],
    'azure-service-principal': ['create'],
  }],
  ['guides/azure-mca-cost-management.md', {
    'azure-cost-allocation': ['explain-allocation-tag', 'verify-allocation'],
    'azure-subscription-billing': ['request-billing-move'],
  }],
  ['guides/azure-network-security-perimeter.md', {
    'azure-network-security-perimeter': ['review-access-logs', 'configure-profile-rule', 'explain-access-modes'],
  }],
  ['guides/cloudops-policies.md', Object.fromEntries([
    'container-apps-environments', 'azure-storage-accounts', 'azure-cache-for-redis', 'azure-api-management',
    'vm-network-interfaces', 'dns-zones-and-records', 'network-security-groups', 'windows-server-licensing',
    'azure-firewall', 'azure-sql-licensing', 'vnet-flow-logs', 'application-gateway-placement',
    'azure-key-vault', 'vm-sizes', 'generated-public-network-initiative-members', 'private-endpoint-subnets',
    'ddos-protection', 'network-security-perimeter-creation', 'azure-resource-group-tags', 'cost-management-tags',
    'service-catalog-tags-and-public-network-workspaces', 'gsa-subnets', 'azure-privileged-role-assignments',
    'inactive-central-modules', 'private-endpoint-dns', 'nsp-associations',
  ].map(resource => [resource, ['cloudops-policy-controls']]))],
  ['guides/github-private-runners-network.md', {
    'github-private-runners': ['troubleshoot-network', 'configure-private-network'],
  }],
  ['guides/global-secure-access-azure-resources.md', {
    'private-endpoint-dns': ['explain-record-lifecycle'], 'azure-container-apps': ['explain-private-dns'],
    'global-secure-access': ['explain-sign-in-groups'],
  }],
  ['guides/global-secure-access-landingzone-assistant.md', Object.fromEntries([
    'azure-sql-database', 'azure-storage-accounts', 'azure-container-apps', 'azure-app-service',
  ].map(resource => [resource, ['gsa-access']]))],
  ['guides/global-secure-access-resource-answers.md', Object.fromEntries([
    'service-bus', 'azure-key-vault', 'azure-cache-for-redis',
  ].map(resource => [resource, ['gsa-access']]))],
  ['guides/global-secure-access-additional-resources.md',
    Object.fromEntries(additionalGsaResources.map(resource => [resource, ['gsa-access']]))],
  ['guides/landingzone-service-catalog-setup.md', {
    'landing-zone-service-catalog': ['explain-production-source', 'run-workflow', 'recover-partial-workflow',
      'verify-workflow-completion'], 'terraform-state': ['resolve-state-lock'],
  }],
  ['reference/azure-role-assignments.md', {
    'azure-rbac': ['choose-role-group', 'assign-privileged-role'], 'azure-managed-identity': ['configure-identity'],
  }],
  ['reference/cloudops-landingzone-compute-data-policy-settings.md', {
    'vm-sizes-and-windows-server-licensing': ['cloudops-policy-controls'],
  }],
  ['reference/cloudops-landingzone-network-policy-settings.md', { 'network-resources': ['cloudops-policy-controls'] }],
  ['reference/secops-policies-web-application-firewall.md', {
    'application-gateway': ['security-controls'], 'azure-front-door': ['security-controls'],
  }],
];

// Each pair is an explicit product and its documented reference, not a domain-suffix expansion.
const policyResources = [
  ['api-management', 'azure-api-management'], ['app-configuration', 'app-configuration'],
  ['app-service-web-apps', 'azure-app-service'], ['automation-accounts', 'automation-accounts'],
  ['azure-ai-search', 'azure-ai-search'], ['azure-ai-services', 'azure-ai-services'],
  ['azure-bastion', 'azure-bastion'], ['azure-cache-for-redis', 'azure-cache-for-redis'],
  ['azure-container-registry', 'azure-container-registry'], ['azure-cosmos-db', 'azure-cosmos-db'],
  ['azure-data-explorer', 'azure-data-explorer'], ['azure-data-factory', 'azure-data-factory'],
  ['azure-database-for-mysql', 'azure-database-for-mysql'], ['azure-database-for-postgresql', 'azure-database-for-postgresql'],
  ['azure-databricks', 'azure-databricks'], ['azure-firewall', 'azure-firewall'],
  ['azure-kubernetes-service', 'azure-kubernetes-service'], ['azure-machine-learning', 'azure-machine-learning'],
  ['azure-managed-grafana', 'azure-managed-grafana'], ['azure-sql', 'azure-sql'],
  ['azure-stream-analytics', 'azure-stream-analytics'], ['azure-synapse-analytics', 'azure-synapse-analytics'],
  ['communication-services', 'communication-services'], ['container-apps', 'azure-container-apps'],
  ['dev-center', 'dev-center'], ['event-grid', 'event-grid'], ['event-hubs', 'event-hubs'],
  ['front-door-and-cdn', 'front-door-and-cdn'], ['function-apps', 'function-apps'], ['iot-hub', 'iot-hub'],
  ['key-vault', 'azure-key-vault'], ['landing-zone-policy-baseline', 'landing-zone-policy-baseline'],
  ['microsoft-purview', 'microsoft-purview'], ['monitoring-and-activity-logs', 'monitoring-and-activity-logs'],
  ['network-security-groups', 'network-security-groups'], ['public-ip-addresses', 'public-ip-addresses'],
  ['service-bus', 'service-bus'], ['storage-accounts', 'azure-storage-accounts'], ['virtual-machines', 'virtual-machines'],
  ['virtual-networks-and-subnets', 'virtual-networks-and-subnets'], ['vpn-gateway', 'vpn-gateway'],
];
const withoutRationale = new Set([
  'azure-bastion', 'azure-data-explorer', 'dev-center', 'front-door-and-cdn', 'microsoft-purview', 'public-ip-addresses',
]);
for (const [file, resource] of policyResources) {
  rows.push([`reference/secops-policies-${file}.md`, { [resource]: [
    'security-controls', 'policy-framework-details',
    ...(withoutRationale.has(resource) ? [] : ['controls-rationale']),
    'control-threat-assessment', 'terraform-implementation',
  ] }]);
}

export const answerInventory = rows.flatMap(([file, resources]) =>
  Object.entries(resources).flatMap(([resource, tasks]) =>
    tasks.map(task => ({ file, resource, task, id: `${resource}-${task}` }))));

export const gsaWorkflows = {
  ...Object.fromEntries(additionalGsaResources.map(resource => [resource, 'fqdn'])),
  'azure-sql-database': 'automatic-ip', 'service-bus': 'automatic-ip',
  'azure-storage-accounts': 'fqdn', 'azure-key-vault': 'fqdn', 'azure-cache-for-redis': 'fqdn',
  'azure-container-apps': 'internal-environment', 'azure-app-service': 'unsupported',
};

export const referenceOnlyQuestions = [
  ['guides/global-secure-access-landingzone-assistant.md', 'How do I add, enable or connect a resource through GSA?'],
  ['guides/global-secure-access-landingzone-assistant.md', 'How do I connect SQL Database or Service Bus through GSA?'],
  ['guides/global-secure-access-landingzone-assistant.md', 'How do I enable GSA for a private-endpoint resource such as Storage, Key Vault or Redis?'],
  ['guides/secops-policies.md', 'What would a Storage account answer look like?'],
];
