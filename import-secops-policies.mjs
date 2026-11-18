import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { assertSafe, validateDocument } from './validate.mjs';

// Resource names are lookup hints; the consuming provider/module schema remains authoritative.
export const resources = [
  ['API Management', 'azurerm_api_management; azurerm_api_management_api', 'Use HTTPS/WSS API protocols and governed portal identity providers; configure backend authorization, rate limits and central audit logging.'],
  ['App Configuration', 'azurerm_app_configuration', 'Set public network access to Disabled and local authentication to disabled; use Entra RBAC, managed identity and Key Vault references.'],
  ['App Service Web Apps', 'azurerm_linux_web_app; azurerm_windows_web_app; corresponding slot resources', 'Configure HTTPS, approved TLS, private access, managed identity and platform authentication for apps and slots; keep SSH, remote debugging and FTP/SCM local authentication disabled. Validate end-to-end encryption support for the selected plan.'],
  ['Automation Accounts', 'azurerm_automation_account', 'Configure managed identity, scoped runbook RBAC, private access and local authentication disabled; retain runbook change review and central diagnostics.'],
  ['Azure AI Search', 'azurerm_search_service', 'Configure public network access disabled and local authentication disabled; authorize data-plane access with Entra RBAC and validate application-level document permission trimming.'],
  ['Azure AI Services', 'azurerm_cognitive_account', 'Configure local authentication disabled, restricted network access and managed identity; classify prompts, training data and outputs and verify service-kind support.'],
  ['Azure Bastion', 'azurerm_bastion_host', 'Reuse approved network placement and scoped RBAC; preserve policy-owned audit diagnostics. The uploaded coverage is diagnostic-only; obtain architecture-specific hardening separately.'],
  ['Azure Cache for Redis', 'azurerm_redis_cache', 'Configure public access disabled, access-key authentication disabled and encrypted client connections with the non-TLS port disabled; verify the selected Redis product and client support.'],
  ['Azure Container Registry', 'azurerm_container_registry', 'Configure restricted private network access and disable local admin, anonymous pull, ARM audience tokens, repository-scoped tokens and exports; use Entra identities and image vulnerability remediation. Verify provider support for each control.'],
  ['Azure Cosmos DB', 'azurerm_cosmosdb_account; applicable Cassandra/Mongo resources', 'Configure public network access and local authentication disabled with restricted firewall/private paths; use supported Entra data roles. Establish API-specific applicability and approved Defender ownership.'],
  ['Azure Data Explorer', 'azurerm_kusto_cluster', 'Preserve policy-owned cluster audit diagnostics; establish data classification, RBAC, ingestion paths, network controls and retention from the approved workload design.'],
  ['Azure Data Factory', 'azurerm_data_factory; connector-specific linked-service resources', 'Configure public network access disabled and system-assigned managed identity for supported linked services; verify integration runtime connectivity and use Key Vault references for remaining credentials.'],
  ['Azure Database for MySQL', 'azurerm_mysql_flexible_server', 'Configure public network access disabled, least-privilege database users and encrypted client connections; establish central audit logging and approved open-source database Defender ownership.'],
  ['Azure Database for PostgreSQL', 'azurerm_postgresql_flexible_server; server configuration and Entra administrator resources', 'Configure private access, Entra administration, TLS 1.2 or newer and require_secure_transport; map connection/checkpoint/disconnection logging, connection_throttle.enable, log_line_prefix, shared_preload_libraries and pgaudit.log to verified server parameters. Obtain exact values and definitions for the repeated policy ID.'],
  ['Azure Databricks', 'azurerm_databricks_workspace; approved Databricks provider resources', 'Configure public network access disabled and secure cluster connectivity with public IPs disabled; establish federation, SCIM, data permissions and approved identity/secret scopes.'],
  ['Azure Firewall', 'azurerm_firewall; azurerm_firewall_policy; azurerm_virtual_hub', 'Configure approved threat-intelligence mode, DNS proxy, applicable Premium capabilities and availability zones; verify intended hub routes actually traverse inspection.'],
  ['Azure Kubernetes Service', 'azurerm_kubernetes_cluster; workload manifests through approved tooling', 'Configure Entra integration, managed identity, workload identity, Policy add-on, local authentication disabled, Command Invoke disabled, node OS upgrades and Image Cleaner. Configure HTTPS ingress and read-only, least-privilege containers in workload manifests. Review SSH and Defender applicability separately.'],
  ['Azure Machine Learning', 'azurerm_machine_learning_workspace; applicable compute resources', 'Configure workspace public access disabled and a user-assigned managed identity with dependent-resource RBAC; disable compute local authentication and use Key Vault for secrets.'],
  ['Azure Managed Grafana', 'azurerm_dashboard_grafana', 'Configure private access and Entra role assignments; keep SMTP email settings and service accounts disabled. Verify supported provider fields and policy ownership of Modify-controlled settings.'],
  ['Azure SQL', 'azurerm_mssql_server; azurerm_mssql_database; azurerm_mssql_managed_instance', 'Configure public access disabled, Entra-only authentication at creation and thereafter, Entra administrator and TLS 1.2 or newer; establish auditing, TDE, vulnerability assessment and approved Defender ownership for each SQL variant.'],
  ['Azure Stream Analytics', 'azurerm_stream_analytics_job; input/output resources', 'Configure managed identity and endpoint-scoped RBAC for supported connectors; review query destinations, connector exceptions and workload diagnostics.'],
  ['Azure Synapse Analytics', 'azurerm_synapse_workspace; applicable pool resources', 'Configure public access disabled, Entra-only authentication at creation and thereafter and SQL TLS 1.2 or newer; verify workspace, SQL and data-lake permissions together and preserve selected pool audit diagnostics.'],
  ['Communication Services', 'azurerm_communication_service', 'Configure managed identity and local authentication disabled; establish scoped service RBAC, application token issuance and privacy/retention controls. Verify support in the approved provider version.'],
  ['Container Apps', 'azurerm_container_app_environment; azurerm_container_app', 'Configure private environment access, internal app ingress, HTTPS-only transport and managed identity; validate registry access, application authorization and central environment diagnostics.'],
  ['Dev Center', 'azurerm_dev_center; applicable project/pool/network resources', 'Preserve policy-owned audit diagnostics and use approved project, pool, network and identity patterns. The uploaded baseline establishes logging rather than a complete developer-platform design.'],
  ['Event Grid', 'azurerm_eventgrid_domain; azurerm_eventgrid_topic; applicable namespace resources', 'Configure private access for domains, topics and namespaces as covered; disable local authentication for domains, topics and partner namespaces. Validate subscription destinations, delivery/retry behavior and subtype-specific diagnostics.'],
  ['Event Hubs', 'azurerm_eventhub_namespace', 'Configure public access and local authentication disabled, managed-identity/RBAC producer and consumer access and infrastructure encryption at creation; verify SKU support and capture-destination permissions.'],
  ['Front Door and CDN', 'azurerm_cdn_frontdoor_profile; applicable CDN resources', 'Preserve profile audit diagnostics and apply the separately approved WAF, TLS, restricted-origin and routing design; use the WAF reference for entry-point coverage.'],
  ['Function Apps', 'azurerm_linux_function_app; azurerm_windows_function_app; corresponding slot resources', 'Configure HTTPS, approved TLS, private access and managed identity; keep FTP/SCM local authentication and remote debugging disabled for apps and slots, and validate trigger/binding permissions.'],
  ['IoT Hub', 'azurerm_iothub; azurerm_iothub_dps; azurerm_iothub_device_update_account', 'Configure private access for hub, provisioning and update resources and local service-API authentication disabled; establish device identity separately from service identity and review signed update/rollback processes.'],
  ['Key Vault', 'azurerm_key_vault; applicable key and secret resources', 'Configure RBAC authorization, public access disabled, restricted firewall posture, soft delete and purge protection; use approved expiration and key rotation settings and preserve vault/HSM diagnostics. Keep secret values outside repository content.'],
  ['Landing Zone Policy Baseline', 'All requested Azure resource and resource-group types', 'Obtain the approved resource and resource-group location allow lists and effective initiative parameters; select permitted locations, preserve tag/DNS ownership and record scoped, time-bound exceptions through the existing approval process.'],
  ['Microsoft Purview', 'azurerm_purview_account', 'Preserve policy-owned audit diagnostics and establish scan identities, source permissions, classification ownership and data-governance procedures separately.'],
  ['Monitoring and Activity Logs', 'azurerm_monitor_diagnostic_setting; subscription diagnostics and approved Defender resources', 'Reuse the supplied central Log Analytics workspace; preserve policy-owned audit category settings named ABG SecOps Monitoring - DO NOT REMOVE. Establish subscription Activity Log routing and resource-specific diagnostic support, retention and alert ownership.'],
  ['Network Security Groups', 'azurerm_network_security_group; azurerm_network_security_rule; subnet associations', 'Configure workload NSG associations and least-privilege source/destination/protocol/port rules; scope management access to approved private paths. Establish Network Watcher and the currently supported flow-logging design with the platform owner.'],
  ['Public IP Addresses', 'azurerm_public_ip; azurerm_public_ip_prefix', 'Reuse approved ingress/egress designs and preserve policy-owned audit diagnostics where supported; establish resource attachment, DNS and exposure ownership. Logging coverage supplies evidence rather than exposure approval.'],
  ['Service Bus', 'azurerm_servicebus_namespace', 'Configure public access and local authentication disabled, managed identity with RBAC and infrastructure encryption at namespace creation; verify SKU support and diagnostics ownership.'],
  ['Storage Accounts', 'azurerm_storage_account; blob service configuration', 'Configure HTTPS-only transfer, TLS 1.2 or newer, anonymous blob access disabled, shared-key access disabled, public access disabled and infrastructure encryption; establish soft delete and blob versioning ownership. Apply the existing LRS default and policy-owned private DNS rules.'],
  ['Virtual Machines', 'azurerm_linux_virtual_machine; azurerm_windows_virtual_machine; VM scale sets and managed disks', 'Configure private disk access, encryption at host, periodic update assessment and scoped private administration; establish backup, Windows real-time protection/signature freshness and approved Defender/guest-configuration prerequisites.'],
  ['Virtual Networks and Subnets', 'azurerm_virtual_network; azurerm_subnet; azurerm_route; azurerm_network_interface', 'Configure private subnets with default outbound access disabled, approved inspected egress routes and NICs with private IP configurations; validate NSGs, DNS, peering and effective routes.'],
  ['VPN Gateway', 'azurerm_virtual_network_gateway; applicable point-to-site gateway resources', 'Configure Entra-only authentication for point-to-site users; obtain approved tenant/audience/issuer settings and validate Conditional Access, MFA, reachable routes and diagnostics separately.'],
  ['Web Application Firewall', 'azurerm_web_application_firewall_policy; azurerm_cdn_frontdoor_firewall_policy; gateway/Front Door associations', 'Configure WAF-enabled approved HTTP/S entry-points, restricted origins and explicit WAF associations; obtain approved mode/rule versions, narrow exclusions, owner approval and diagnostic response paths.'],
];

const questions = {
  'Policy coverage': 'Which policies and effects are documented?',
  'Effect model': 'How should I interpret the policy effects?',
  'Threat model': 'Which risks do these controls address?',
  'Best-practice rationale': 'Why should I use these controls?',
  'Developer guidance': 'What setup should I use for this resource?',
  'Governance notes': 'How should I plan ownership and workload-specific controls?',
  References: 'Which supporting references can I consult?',
};

export const settings = {
  'API Management': [
    ['API protocols', 'HTTPS/WSS only', 'Encrypt API requests and responses.'],
    ['Developer portal username/password authentication', 'Disabled; use a governed identity provider', 'Centralize identity governance and access review.'],
    ['Audit diagnostics', 'Enabled to the supplied central Log Analytics workspace', 'Support investigation of service changes and access.'],
  ],
  'App Configuration': [
    ['Public network access', 'Disabled', 'Keep configuration access on approved private paths.'],
    ['Local authentication', 'Disabled; use managed identity and Entra RBAC', 'Reduce persistent access keys and connection strings.'],
    ['Secret storage', 'Key Vault references', 'Keep secret lifecycle under the vault owner.'],
    ['Audit diagnostics', 'Enabled through the shared baseline', 'Make configuration changes traceable.'],
  ],
  'App Service Web Apps': [
    ['HTTPS only / TLS', 'HTTPS only enabled; TLS 1.2 or newer for apps; confirm the approved slot TLS version', 'Protect application and deployment-slot traffic.'],
    ['Public network access', 'Disabled for apps and slots', 'Keep ingress on approved paths.'],
    ['Platform authentication / managed identity', 'Enabled for apps and slots', 'Provide governed inbound identity and secretless outbound access.'],
    ['SSH / remote debugging', 'Disabled for apps and slots', 'Keep administrative access within approved operational paths.'],
    ['FTP / SCM local authentication', 'Disabled for apps and slots; use governed CI/CD identities', 'Reduce persistent deployment credentials.'],
    ['FTP transport / end-to-end encryption', 'FTPS-only where used; end-to-end encryption enabled where applicable', 'Protect deployment and platform-path transport; confirm service/plan support.'],
    ['Audit diagnostics', 'Enabled for covered App Service Environments; confirm separate app/slot logging coverage', 'Retain the distinction between environment, application and control-plane evidence.'],
  ],
  'Automation Accounts': [
    ['Managed identity', 'Enabled with scoped RBAC', 'Attribute runbook access to a governed workload identity.'],
    ['Public network access / local authentication', 'Disabled', 'Reduce public exposure and persistent local credentials.'],
    ['Audit diagnostics', 'Enabled through the shared baseline', 'Support runbook and account investigations.'],
  ],
  'Azure AI Search': [
    ['Public network access', 'Disabled', 'Protect indexed data and query endpoints through approved private paths.'],
    ['Local authentication', 'Disabled; use Entra data-plane RBAC', 'Use attributable identities for search and indexing.'],
    ['Document permission trimming', 'Implemented and verified by the application', 'Preserve source authorization when returning retrieved content.'],
    ['Audit diagnostics', 'Enabled through the shared baseline', 'Support service-level investigation.'],
  ],
  'Azure AI Services': [
    ['Local/key authentication', 'Disabled', 'Use Entra identities for service access.'],
    ['Network access', 'Restricted to approved paths', 'Control access to prompts, models and service endpoints.'],
    ['Managed identity', 'Enabled', 'Support secretless access to dependent Azure resources.'],
    ['Audit diagnostics', 'Enabled through the shared baseline', 'Support access and configuration investigations.'],
  ],
  'Azure Bastion': [
    ['Audit category diagnostics', 'Enabled to the central Log Analytics workspace', 'Retain privileged-access evidence.'],
    ['RBAC / network placement', 'Approved least-privilege design', 'Establish governed administrative access; additional hardening is a design input.'],
  ],
  'Azure Cache for Redis': [
    ['Public network access / access-key authentication', 'Disabled', 'Reduce exposure and shared-credential access.'],
    ['Non-SSL port', 'Disabled; use TLS clients', 'Protect cached data and tokens in transit.'],
    ['Audit diagnostics', 'Enabled through the shared baseline', 'Support cache access and configuration investigations.'],
  ],
  'Azure Container Registry': [
    ['Public network access', 'Disabled; network access restricted', 'Keep registry traffic within approved paths.'],
    ['Admin account / anonymous pull / repository-scoped tokens', 'Disabled', 'Use governed Entra identities and scoped RBAC.'],
    ['ARM audience token authentication', 'Disabled', 'Use tokens intended for the registry audience.'],
    ['Exports', 'Disabled', 'Keep image distribution within governed release paths.'],
    ['Image vulnerability remediation', 'Enabled operational process; resolve findings', 'Reduce vulnerable images reaching workloads.'],
    ['Audit diagnostics', 'Enabled through the shared baseline', 'Retain push, pull and configuration evidence where supported.'],
  ],
  'Azure Cosmos DB': [
    ['Public network access / local authentication', 'Disabled on applicable account/API types', 'Reduce direct exposure and account-key reliance.'],
    ['Firewall / private network controls', 'Restricted approved sources', 'Define the permitted data-access path.'],
    ['Account, Cassandra and Mongo audit diagnostics', 'Enabled for covered subtypes', 'Retain subtype-specific operational evidence.'],
    ['Defender for Cosmos DB', 'Confirm approved plan inclusion and owner', 'Align threat detection with the selected baseline and plan approval.'],
  ],
  'Azure Data Explorer': [
    ['Cluster audit diagnostics', 'Enabled through the shared baseline', 'Retain analytics configuration and access evidence.'],
    ['RBAC / network / ingestion / retention', 'Approved workload-specific values', 'Match data classification and analytics use; the supplied baseline covers logging.'],
  ],
  'Azure Data Factory': [
    ['Public network access', 'Disabled', 'Protect factory connectivity through approved private paths.'],
    ['Linked-service system-assigned managed identity', 'Enabled where the connector supports it', 'Reduce stored connection credentials.'],
    ['Remaining credentials', 'Key Vault references with approved access', 'Provide governed secret lifecycle for connector-specific needs.'],
    ['Pipeline diagnostics', 'Configure the approved workload logging path', 'Retain data-movement evidence; confirm actual diagnostic policy coverage.'],
  ],
  'Azure Database for MySQL': [
    ['Public network access', 'Disabled', 'Use approved private database connectivity.'],
    ['Encrypted client connections / database permissions', 'Enabled / least privilege', 'Protect data in transit and scope user access.'],
    ['Audit diagnostics / open-source database Defender', 'Confirm selected baseline membership and ownership', 'Resolve the conflicting coverage and governance descriptions before implementation.'],
  ],
  'Azure Database for PostgreSQL': [
    ['Public network access', 'Disabled', 'Protect database access through approved private paths.'],
    ['Entra administrator', 'Configured', 'Provide centrally governed database administration.'],
    ['TLS / require_secure_transport', 'TLS 1.2 or newer / Enabled', 'Require encrypted supported client connections.'],
    ['log_connections / log_checkpoints / log_disconnections', 'Enabled', 'Retain connection and database operational evidence.'],
    ['connection_throttle.enable', 'Enabled', 'Control repeated connection attempts.'],
    ['log_line_prefix', 'Include user, database, application, client, timestamp and session identifiers; confirm exact value', 'Make events attributable and correlatable.'],
    ['shared_preload_libraries / pgaudit.log', 'Include pgaudit / role, ddl and misc; confirm exact server values', 'Retain database security and change evidence.'],
    ['Audit diagnostics / approved database Defender', 'Confirm policy references, parameters and ownership', 'Resolve repeated identifiers and establish the actual selected controls.'],
  ],
  'Azure Databricks': [
    ['Workspace public network access / cluster public IPs', 'Disabled', 'Keep workspace and cluster connectivity on approved private paths.'],
    ['Identity federation / SCIM / RBAC / data permissions', 'Approved platform design with least privilege', 'Govern user and workload access across workspace and data boundaries.'],
    ['Job diagnostics', 'Configure the approved workload logging path', 'Retain operational evidence separately from the two listed network controls.'],
  ],
  'Azure Firewall': [
    ['Threat intelligence', 'Enabled in the approved operating mode', 'Detect or block known malicious endpoints.'],
    ['DNS proxy', 'Enabled where required by the approved FQDN/DNS design; audit finding triaged', 'Keep DNS behavior consistent with inspection.'],
    ['Firewall SKU / availability zones', 'Premium and multi-zone where applicable to the approved pattern and region', 'Provide the documented inspection and resilience posture.'],
    ['Virtual hub protection / routes', 'Firewall protection configured; intended routes traverse inspection', 'Keep egress on the approved inspected path.'],
  ],
  'Azure Kubernetes Service': [
    ['Entra integration / managed identity / workload identity', 'Enabled', 'Govern cluster access and pod-to-Azure authentication.'],
    ['Local authentication / SSH / Command Invoke', 'Disabled through the approved supported configuration', 'Keep administrative access attributable and governed.'],
    ['Azure Policy add-on', 'Enabled', 'Apply admission-policy integration.'],
    ['HTTPS ingress', 'Enabled with certificate ownership', 'Protect service traffic.'],
    ['Privileged containers / CAP_SYS_ADMIN', 'Disabled for ordinary workloads; formal risk acceptance for an exception', 'Limit container privilege and escape risk.'],
    ['Read-only root filesystem', 'Enabled in workload manifests', 'Reduce persistence and mutable runtime surface.'],
    ['Node OS auto-upgrade / Image Cleaner', 'Enabled with approved scheduling/settings', 'Keep node images current and clean up unused vulnerable images.'],
    ['Defender profile / Containers plan', 'Confirm selected profile, plan and subscription ownership', 'Resolve the difference between listed coverage and workload-specific plan guidance.'],
  ],
  'Azure Machine Learning': [
    ['Workspace public network access / compute local authentication', 'Disabled', 'Reduce direct exposure and unmanaged credentials.'],
    ['Workspace user-assigned managed identity', 'Enabled with dependent-resource RBAC', 'Govern access to storage, registries and other dependencies.'],
    ['Workspace / registry audit diagnostics', 'Enabled for covered subtypes', 'Retain ML platform evidence.'],
  ],
  'Azure Managed Grafana': [
    ['Public network access', 'Disabled', 'Protect operational dashboards and telemetry.'],
    ['SMTP email settings / service accounts', 'Disabled', 'Use approved notification and central identity patterns.'],
    ['Entra access / data-source permissions', 'Least privilege, reviewed separately', 'Scope dashboard and underlying telemetry access.'],
    ['Audit diagnostics', 'Enabled through the shared baseline', 'Retain workspace configuration and access evidence.'],
  ],
  'Azure SQL': [
    ['SQL Database / Managed Instance public access', 'Disabled', 'Protect database endpoints through approved private paths.'],
    ['Entra-only authentication / Entra administrator', 'Enabled at creation and thereafter / Configured', 'Govern administration and database identity centrally.'],
    ['Minimum TLS', '1.2 or newer; confirm variant-specific settings', 'Protect client database connections.'],
    ['Auditing / Transparent Data Encryption', 'Enabled for applicable SQL scopes', 'Retain access evidence and encryption at rest.'],
    ['Advanced Data Security / vulnerability assessment / Defender', 'Confirm approved variant-specific deployment and storage ownership', 'Resolve plan inclusion and evidence-storage responsibilities.'],
    ['Database / Managed Instance audit diagnostics', 'Enabled for covered subtypes', 'Retain central operational evidence.'],
  ],
  'Azure Stream Analytics': [
    ['Endpoint managed-identity authentication', 'Enabled for supported inputs and outputs', 'Use attributable secretless access.'],
    ['Endpoint RBAC / query destinations', 'Least privilege / approved data flows', 'Protect stream inputs, processing and output data.'],
    ['Job diagnostics', 'Configure the approved workload logging path', 'Support investigation beyond the listed identity control.'],
  ],
  'Azure Synapse Analytics': [
    ['Workspace public network access', 'Disabled', 'Keep analytics access on approved private paths.'],
    ['Entra-only authentication', 'Enabled at creation and thereafter', 'Govern workspace and SQL identity centrally.'],
    ['SQL endpoint TLS', '1.2 or newer', 'Protect client SQL connections.'],
    ['Workspace / supported pool audit diagnostics', 'Enabled through selected baseline policies', 'Retain workspace and pool-specific evidence.'],
    ['Workspace RBAC / SQL / data-lake permissions', 'Reviewed together with least privilege', 'Protect data across analytics boundaries.'],
  ],
  'Communication Services': [
    ['Local authentication', 'Disabled', 'Reduce access-key and connection-string reliance.'],
    ['Managed identity', 'Enabled with scoped RBAC for supported integrations', 'Provide governed service access.'],
    ['Token issuance / privacy / retention', 'Approved application-specific configuration', 'Protect communications, identities and associated metadata.'],
  ],
  'Container Apps': [
    ['Environment public network access / app external ingress', 'Disabled', 'Keep environments and application origins private.'],
    ['HTTPS-only transport', 'Enabled; insecure HTTP disabled', 'Protect application traffic.'],
    ['Managed identity', 'Enabled', 'Use secretless access to supported Azure resources.'],
    ['Environment audit diagnostics', 'Enabled through the shared baseline', 'Retain platform evidence; configure workload logs separately.'],
    ['Image scanning / application authorization', 'Implemented through approved workload controls', 'Protect image supply and service-to-service access beyond network isolation.'],
  ],
  'Dev Center': [
    ['Audit diagnostics', 'Enabled through the shared baseline', 'Retain developer-platform change evidence.'],
    ['Projects / pools / network connections / identities', 'Approved developer-platform settings', 'Govern developer environments separately from diagnostic coverage.'],
  ],
  'Event Grid': [
    ['Domain / topic / namespace public network access', 'Disabled for listed subtypes', 'Protect publishing endpoints through approved network paths.'],
    ['Domain / topic / partner namespace local authentication', 'Disabled for listed subtypes', 'Use supported Entra publisher identities.'],
    ['Domain / topic / partner namespace audit diagnostics', 'Enabled for covered subtypes', 'Retain event-platform change evidence.'],
    ['Subscriptions / destinations / retry behavior', 'Approved delivery chain and scoped ownership', 'Keep sensitive events within authorized consumer paths.'],
  ],
  'Event Hubs': [
    ['Public network access / local authentication', 'Disabled', 'Reduce direct exposure and SAS-key reliance.'],
    ['Infrastructure encryption', 'Enabled at namespace creation where supported', 'Provide the documented additional encryption layer.'],
    ['Producer / consumer identities', 'Managed identity and least-privilege RBAC', 'Scope streaming access to the intended workloads.'],
    ['Audit diagnostics', 'Enabled through the shared baseline', 'Retain namespace evidence.'],
  ],
  'Front Door and CDN': [
    ['Profile audit diagnostics', 'Enabled through the shared baseline', 'Retain edge routing and configuration evidence.'],
    ['WAF / TLS / origins / routes', 'Approved ingress configuration; apply the separate WAF controls', 'Protect public entry-points and origin access beyond logging.'],
  ],
  'Function Apps': [
    ['HTTPS only / TLS', 'HTTPS only enabled; TLS 1.2 or newer for apps; confirm the approved slot TLS version', 'Protect function and slot traffic.'],
    ['Public network access', 'Disabled for apps and slots', 'Keep ingress on approved private paths.'],
    ['Managed identity', 'Enabled for supported function access', 'Reduce stored credentials in app settings and bindings.'],
    ['FTP / SCM local authentication / remote debugging', 'Disabled for apps and slots', 'Keep deployments and administration within governed paths.'],
    ['Trigger / binding permissions and diagnostics', 'Least privilege; configure approved workload logs', 'Protect event sources and retain function execution evidence.'],
  ],
  'IoT Hub': [
    ['Hub / Device Update / provisioning public access', 'Disabled for listed resource types', 'Protect fleet management endpoints through approved network paths.'],
    ['Service API local authentication', 'Disabled', 'Use governed service identities; establish device authentication separately.'],
    ['Hub audit diagnostics', 'Enabled through the shared baseline', 'Retain hub operational evidence.'],
    ['Update signing / deployment rings / rollback', 'Approved device-update process', 'Protect fleet software integrity and recovery.'],
  ],
  'Key Vault': [
    ['Soft delete / purge protection', 'Enabled', 'Preserve recovery following deletion.'],
    ['RBAC permission model', 'Enabled with scoped roles', 'Centralize authorization and access review.'],
    ['Public network access / firewall', 'Public access disabled by default; restricted firewall for an approved alternative', 'Keep vault data-plane access within approved paths.'],
    ['Key / secret expiration', 'Configured with approved validity periods', 'Provide a planned credential lifecycle.'],
    ['Key rotation policy', 'Configured with approved schedule; review audit findings', 'Keep cryptographic keys on a governed rotation lifecycle.'],
    ['Vault / Managed HSM audit diagnostics', 'Enabled for covered resource types', 'Retain sensitive-access evidence.'],
    ['Defender for Key Vault', 'Workload/platform assessment; excluded from the supplied default baseline', 'Preserve the documented distinction between preventive baseline and selected detection plans.'],
  ],
  'Landing Zone Policy Baseline': [
    ['Resource / resource-group locations', 'Values from the approved assignment allow lists', 'Meet placement and data-residency governance.'],
    ['Preventive effects', 'Use the reviewed per-policy Deny target where supported', 'Align new resource settings with the documented secure target state.'],
    ['Modify / DeployIfNotExists controls', 'Confirm assignment identity, permissions and remediation owner', 'Establish ownership for automatically configured settings and supporting resources.'],
    ['Audit findings / exceptions', 'Assigned owner, remediation plan and scoped time-bound approval', 'Turn posture evidence into accountable action.'],
  ],
  'Microsoft Purview': [
    ['Account audit diagnostics', 'Enabled through the shared baseline', 'Retain governance-platform change evidence.'],
    ['Scan identities / source permissions / classification ownership', 'Approved governance design', 'Scope data discovery and classification to authorized owners.'],
  ],
  'Monitoring and Activity Logs': [
    ['Subscription Activity Log routing', 'Enabled to the supplied central Log Analytics workspace', 'Retain control-plane evidence.'],
    ['Selected resource audit category group', 'Enabled to the central workspace where supported', 'Retain service-specific operational evidence.'],
    ['Central diagnostic setting', 'Preserve ABG SecOps Monitoring - DO NOT REMOVE under its approved policy owner', 'Maintain central telemetry and clear Terraform ownership.'],
    ['Defender for Resource Manager', 'Configured through the approved baseline owner', 'Provide subscription control-plane threat detection.'],
    ['Retention / alerting / application logs', 'Approved destination-specific values and response ownership', 'Make collected signals usable while protecting sensitive data.'],
  ],
  'Network Security Groups': [
    ['Subnet / VM NSG protection', 'Associated and verified for applicable workload designs', 'Provide filtering for public and internal workloads.'],
    ['Inbound any-any allow / Internet SSH and RDP', 'Absent; management access scoped to approved private sources', 'Keep broad inbound and administrative exposure closed.'],
    ['Application allow rules', 'Required sources, destinations, protocols and ports only', 'Maintain least-privilege segmentation.'],
    ['Network Watcher / flow logging', 'Approved diagnostic prerequisite and supported flow-log design', 'Support effective-route and traffic investigations; confirm current logging support before provisioning.'],
  ],
  'Public IP Addresses': [
    ['Public IP / prefix audit diagnostics', 'Enabled where the selected definitions support the resource', 'Retain exposure-related change evidence.'],
    ['Attachment / DNS / exposure design', 'Explicitly approved ingress or egress purpose', 'Keep public exposure attributable and reviewed.'],
  ],
  'Service Bus': [
    ['Public network access / local authentication', 'Disabled', 'Reduce direct exposure and SAS/connection-string reliance.'],
    ['Infrastructure encryption', 'Enabled at namespace creation where supported', 'Provide the documented additional message-data encryption layer.'],
    ['Application identity / diagnostics', 'Managed identity and scoped RBAC; central audit diagnostics enabled', 'Attribute message access and retain namespace evidence.'],
  ],
  'Storage Accounts': [
    ['Secure transfer / minimum TLS', 'Enabled / TLS 1.2 or newer', 'Encrypt storage transport.'],
    ['Anonymous blob access / shared-key access / public network access', 'Disabled', 'Use private, attributable identity-based storage access.'],
    ['Infrastructure encryption', 'Enabled', 'Add the documented platform-managed encryption layer.'],
    ['Blob / container soft delete', 'Enabled with approved retention', 'Support recovery after deletion.'],
    ['Blob versioning', 'Enabled where supported; confirm Modify and ownership', 'Support recovery of previous blob versions.'],
    ['Replication', 'LRS default under the existing contract; preserve existing settings unless explicitly changed', 'Apply the established owner-directed replication rule.'],
    ['Defender malware scanning', 'Selected through workload assessment; excluded from the supplied default baseline', 'Match scanning to file-ingestion risk, cost and operational ownership.'],
  ],
  'Virtual Machines': [
    ['Managed disk public network access', 'Disabled', 'Protect disk access through approved private paths.'],
    ['Encryption at host', 'Enabled with supported VM/VMSS configuration', 'Protect host-handled data at rest.'],
    ['Periodic update assessment', 'Enabled with patch owner and maintenance window', 'Make missing updates visible and actionable.'],
    ['Backup', 'Configured for stateful/recovery requirements; triage policy audit findings', 'Provide the approved recovery capability.'],
    ['Windows Defender real-time protection / signatures', 'Enabled / updated within one day', 'Maintain current endpoint malware protection.'],
    ['Defender for Servers / SQL on machines', 'Approved plan and guest prerequisites configured by their owner', 'Provide selected workload threat detection.'],
  ],
  'Virtual Networks and Subnets': [
    ['Default outbound access', 'Disabled; private subnets', 'Use explicit governed egress.'],
    ['Internet next-hop routes / direct NIC public IPs', 'Absent; use approved inspected paths and private origins', 'Keep traffic within reviewed ingress/egress controls.'],
    ['NSGs / DNS / peering / effective routes', 'Configured and verified as one approved connectivity design', 'Provide segmentation and functional private access.'],
    ['DDoS Protection plan', 'Selected through exposure, availability and budget assessment', 'Align additional protection with workload risk and cost.'],
  ],
  'VPN Gateway': [
    ['Point-to-site user authentication', 'Entra-only, using approved tenant/audience/issuer settings', 'Centralize remote-user identity governance.'],
    ['Conditional Access / MFA / device posture', 'Approved identity configuration, verified separately', 'Protect remote network access beyond the authentication-type policy.'],
    ['Reachable networks / diagnostics', 'Least-privilege routes and filtering; approved logging enabled', 'Limit remote reach and retain investigation evidence.'],
  ],
  'Web Application Firewall': [
    ['Application Gateway / Front Door WAF', 'Enabled and associated with approved public HTTP/S entry-points', 'Inspect web traffic at governed ingress.'],
    ['Origins', 'Private or restricted to the approved WAF path', 'Keep ingress inspection effective.'],
    ['WAF mode / rules / exclusions', 'Approved application-specific values; narrow reviewed exclusions', 'Balance protection and application behavior with accountable tuning.'],
    ['Diagnostics / response', 'Enabled with approved alert handling', 'Make WAF events actionable.'],
  ],
};

const positiveActions = new Map([
  ['Do not assume diagnostic logging is optional; it is governed through the shared diagnostic-settings baseline.', 'Keep diagnostic logging aligned with the shared diagnostic-settings baseline and confirm resource-specific coverage.'],
  ['Do not assume vulnerability scanning is optional; image scanning and remediation are part of container security operations.', 'Include image scanning and vulnerability remediation in container security operations.'],
  ['Do not disable Activity Log routing unless another approved landing-zone process owns the same routing outcome.', 'Keep Activity Log routing enabled and confirm the approved owner of that routing outcome.'],
  ['Do not store secrets in App Configuration; use Key Vault references for secret material.', 'Store secret material in Key Vault and use Key Vault references from App Configuration.'],
  ['Do not rely on subnet privacy alone; combine it with NSGs, routing, DNS, private endpoints, and firewall policy.', 'Combine private subnets with NSGs, routing, DNS, applicable private endpoints, and firewall policy.'],
  ['Do not route workload traffic directly to Internet next hops unless an approved exception documents the risk and compensating controls.', 'Route workload traffic through approved egress paths; obtain a scoped exception with risk acceptance and compensating controls for a different path.'],
  ['Do not place sensitive payloads in event metadata unless the full delivery chain is approved.', 'Include sensitive event metadata only within a fully approved delivery chain with appropriate data protection.'],
  ['Do not use WAF as a replacement for secure application design, authentication, authorization, and testing.', 'Combine WAF with secure application design, authentication, authorization, and testing.'],
  ['Do not use manual moves, portal deployments, or alternate subscriptions to bypass location policy.', 'Use the approved deployment process and location allow list, and request a scoped exception through governance when needed.'],
  ['Avoid local credentials, credential assets, and long-lived secrets unless an approved exception exists.', 'Use governed workload identities; obtain an approved exception for integrations requiring credential assets or long-lived secrets.'],
  ['Avoid storing connection strings or access keys in applications, scripts, and pipelines.', 'Use governed identity-based access for applications, scripts, and pipelines.'],
  ['Avoid broad management and any-any rules; the ABG deny guardrails block these high-risk patterns.', 'Scope management rules to approved private sources, destinations, protocols, and ports to satisfy the ABG guardrails.'],
  ['Avoid FTP, local SCM credentials, and basic authentication for deployments.', 'Use governed CI/CD identities with local FTP and SCM authentication disabled.'],
  ['Avoid local SCM credentials and use governed CI/CD identities for deployments.', 'Use governed CI/CD identities for deployments with local SCM authentication disabled.'],
  ['Avoid shared service keys in code, deployment pipelines, and support scripts.', 'Use supported Entra service identities with scoped permissions in code, deployment pipelines, and support scripts.'],
  ['Avoid access-key authentication where identity-based Redis authentication is available and required by the baseline.', 'Use identity-based Redis authentication where available and required by the baseline.'],
  ['Avoid public IPs directly on NICs; use approved ingress services and private origins.', 'Use private NIC configurations with approved ingress services and private origins.'],
  ['Avoid logging sensitive application payloads unless explicitly approved and protected.', 'Log approved operational metadata; include sensitive application payloads only with explicit approval and appropriate protection.'],
  ['Avoid privileged containers, CAP\\_SYS\\_ADMIN, and writable root filesystems unless formally risk accepted.', 'Run least-privilege containers with read-only root filesystems; obtain formal risk acceptance for elevated capabilities or writable roots.'],
  ['Protect backend APIs independently; do not rely on network placement alone.', 'Protect backend APIs with independent authentication and authorization as well as approved network placement.'],
  ['Treat policy denial as design feedback, not as an obstacle to bypass.', 'Use policy denial details to align the resource design with the approved target configuration.'],
]);

export const reviewGaps = {
  'Azure AI Search': 'The supplied attachment introduction described every listed policy as Deny, while the audit-log row specifies DeployIfNotExists. Follow row-level descriptions pending confirmation of the selected definition and effective assignment.',
  'Storage Accounts': 'The supplied attachment coverage introduction said no listed policy supports Modify, while the blob-versioning row specifies Modify. Follow the row-level effect pending confirmation of the selected definition, account-kind support and Terraform/policy ownership.',
  'App Configuration': 'The governance paragraph describes every listed policy as Audit/Deny/Disabled, while the diagnostic row specifies DeployIfNotExists. Confirm effects per definition.',
  'Azure Cache for Redis': 'The governance paragraph describes all rows as Audit/Deny/Disabled, while diagnostics use DeployIfNotExists and the non-TLS port control uses Modify. Confirm each definition and product lifecycle/support.',
  'Azure Container Registry': 'The statement that all listed policies support Deny conflicts with diagnostic DeployIfNotExists and vulnerability AuditIfNotExists rows. Verify definition capabilities and fixed effects individually.',
  'Container Apps': 'The statement that all listed policies support Deny includes a diagnostic DeployIfNotExists row. Verify app and environment controls separately.',
  'Azure Database for MySQL': 'Governance describes a public-exposure-only baseline with logging and Defender left to workload/platform choice, while coverage lists diagnostic and Defender DeployIfNotExists controls. Confirm selected membership and ownership.',
  'Azure Database for PostgreSQL': 'Five differently named server-parameter rows share policy ID a8f89ff4-3d6e-4d7b-8c5a-2e9b1f4c8d3a. Confirm the real definition and distinct initiative reference/parameter bindings for each setting before relying on these identifiers.',
  'Azure Kubernetes Service': 'Coverage includes a Defender for Containers plan control, while governance describes a specific Defender plan assignment as workload-specific. Confirm conditional inclusion and subscription versus cluster ownership.',
  'Azure SQL': 'Coverage lists several Defender and Advanced Data Security deployments, while governance describes Defender configuration as workload-specific. Confirm plan membership, scan-result storage ownership and SQL-variant applicability.',
  'Event Grid': 'The all-rows Audit/Deny/Disabled statement includes diagnostic DeployIfNotExists rows. Confirm subtype-specific member definitions and supported effects.',
  'Event Hubs': 'The all-rows Audit/Deny/Disabled statement includes diagnostic DeployIfNotExists. Confirm member definitions, infrastructure-encryption SKU support and creation-time constraints.',
  'IoT Hub': 'The all-rows Audit/Deny/Disabled statement includes diagnostic DeployIfNotExists. Confirm supported effects and the distinction between device and service-API authentication.',
  'Service Bus': 'The all-rows Audit/Deny/Disabled statement includes diagnostic DeployIfNotExists. Confirm member definitions, infrastructure-encryption SKU support and creation-time constraints.',
  'Network Security Groups': 'Confirm the currently supported flow-logging service and migration requirements before creating logging resources; the supplied NSG-flow-log audit row alone establishes neither current availability nor the approved replacement design.',
};

export function slug(title) {
  return title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

export function positiveGuidance(text) {
  return text.replace(/^(\d+\. )(.+)$/gm, (_, prefix, action) => {
    let result = positiveActions.get(action) ?? action;
    result = result
      .replace(' and avoid direct public exposure by default', '')
      .replace(' and avoid public exposure for disks and administrative access paths', ' for disks and administrative access paths')
      .replace(' and avoid shared administrator accounts', ' with individually attributable access')
      .replace(' and avoid shared administrative accounts', ' with individually attributable access')
      .replace(' and avoid embedding secrets in notebooks, environments, or pipelines', ' and use governed secret references from notebooks, environments, and pipelines')
      .replace('to avoid later migration effort', 'to plan creation-time settings and any required migration');
    if (/\bdo not\b|\bavoid\b|\bmust not\b/i.test(result)) {
      throw new Error(`Action-oriented rewrite required: ${action}`);
    }
    return prefix + result;
  });
}

export function buildReference(source, title, baseline) {
  assertSafe(source);
  if (!/^[a-f0-9]{40}$/.test(baseline)) throw new Error('Use a full authoring baseline SHA');
  const normalized = source.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n').trimEnd();
  if (!normalized.startsWith(`# ${title}\n`)) throw new Error(`Unexpected H1: ${title}`);
  if (/```|~~~|<script\b/i.test(normalized)) throw new Error(`Review unsupported source payload: ${title}`);
  const id = `secops-policies-${slug(title)}`;
  const file = `reference/${id}.md`;
  const metadata = {
    schema_version: 1, id, title: `SecOps policies: ${title}`,
    assistants: ['landing-zone'], topics: ['secops-policies', 'azure-policy', slug(title)],
    owner: 'almbrand/cloudfoundation', document_type: 'reference',
    source_repository: 'almbrand/cloudops-openai-hub-knowledge-source',
    source_path: file, source_commit: baseline,
    review_status: 'pending-review', verification_status: 'unverified',
  };
  // Split on H2 so every source section is accounted for, including the final one.
  const parts = normalized.split(/^## /m).slice(1);
  if (!parts.length || parts[0].split('\n')[0] !== 'Introduction') throw new Error(`Missing introduction: ${title}`);
  let body = `# ${metadata.title}\n\n## Purpose and scope\n\n`;
  body += '> Draft source interpretation; pending review and unverified. Confirm the applicable\n> reviewed implementation and assignment before using these controls as requirements.\n\n';
  body += `This resource reference belongs to [SecOps policies](../guides/secops-policies.md).\nUse its action-oriented answer format and evidence boundaries.\n\n`;
  body += '**Policy ownership: SecOps.** CloudFoundation maintains this knowledge source\nand its review/publication process; workload teams implement the applicable controls.\n\n';
  body += parts[0].slice(parts[0].indexOf('\n') + 1).trim();
  body += '\n\n## Common questions\n\n';
  body += '### Which settings should I enable, disable or configure, and why?\n\n';
  body += 'These are draft target outcomes from the supplied policy explanations and developer\nguidance. Baseline controls, operational responsibilities and workload-specific\nchoices are distinguished in the values below. Use the coverage table for source-stated\neffects and the review question for unresolved details.\n\n';
  body += '| Setting or control | Target value or action | Why |\n| --- | --- | --- |\n';
  for (const row of settings[title]) body += `| ${row.join(' | ')} |\n`;
  body += '\n';
  const [, terraformTypes, outcomes] = resources.find(([name]) => name === title);
  body += '### How should a Terraform agent implement these settings?\n\n';
  body += `**Resource lookup hints:** ${terraformTypes.split('; ').map(name => `\`${name}\``).join('; ')}.\n\n${outcomes}\n\n`;
  body += 'Use the [SecOps resource controls contract](../engineering-contract/secops-resource-controls.md)\nfor the generation sequence and validation evidence. Resolve each Azure setting to\nthe actual approved provider or module schema, including child-resource and creation-time\nrequirements. These lookup hints describe resource families, rather than guaranteed\ninterfaces for every provider version. Confirm Terraform and policy ownership of\neach setting before implementation.\n\n';
  for (const part of parts.slice(1)) {
    const heading = part.slice(0, part.indexOf('\n'));
    if (!questions[heading]) throw new Error(`Unmapped source heading: ${heading}`);
    let content = part.slice(part.indexOf('\n') + 1).trim().replace(/[ \t]+$/gm, '');
    if (heading === 'Developer guidance') content = positiveGuidance(content);
    content = content.replace(/^### /gm, '#### ')
      .replace('`Web Application Firewall.md`', '[Web Application Firewall](secops-policies-web-application-firewall.md)');
    body += `<a id="${slug(heading)}"></a>\n\n### ${questions[heading]}\n\n${content}\n\n`;
  }
  body += '### What should be confirmed before treating this as an approved requirement?\n\n';
  body += 'Confirm exact policy definitions, initiative reference IDs, parameters, effects,\nassignment scope, service/SKU support, remediation permissions and configuration ownership\nagainst the reviewed implementation and authorized Azure evidence. Treat the source\ncoverage table as documented intent while that confirmation is pending. Framework\nmappings and threat probabilities are source assessments, rather than compliance\ncertification or measured incident likelihood.\n\n';
  if (reviewGaps[title]) body += `**Specific source review gap:** ${reviewGaps[title]}\n\n`;
  body += '### What is the provenance of this reference?\n\n';
  body += `Imported from the supplied attachment \`${title}.md\`.\nOriginal file SHA-256: \`${crypto.createHash('sha256').update(source).digest('hex')}\`.\n\n`;
  body += `The metadata commit \`${baseline}\` identifies the knowledge repository's\npre-import authoring baseline, not a Git version of the attachment or its policy\nimplementation. The metadata path identifies this new reference at publication.\nThe attachment supplies policy intent; its original repository, implementation\ncommit and live assignment state remain to be confirmed. Preserve the attachment\nuntil source coverage and consumer migration have been independently verified.\n`;
  const text = `---\n${Object.entries(metadata).map(([key, value]) => `${key}: ${JSON.stringify(value)}`).join('\n')}\n---\n${body}`;
  validateDocument(text, file);
  return { file, text };
}

export function buildResourceContract() {
  let text = '# SecOps resource controls\n\n';
  text += '> Unpublished draft extension. The attached policy interpretations and this new\n> resource mapping require scoped owner review. Existing contract approvals cover\n> only their recorded revision and scope.\n\n';
  text += '## Ownership and sources\n\n';
  text += '**SecOps owns these security policies.** CloudFoundation maintains this knowledge\nrepository and its review/publication process. Workload teams implement the\napplicable configuration; platform owners manage shared assignments, remediation\nand central services through their existing approval process.\n\n';
  text += 'The [SecOps policies guide](../guides/secops-policies.md) indexes all 42 supplied\ndocuments. Each resource reference includes explicit enabled/disabled/configured\ntargets, reasons, source policy rows, threat analysis, developer actions, review\ngaps and the original attachment SHA-256. These uploads document intent; confirm\nthe reviewed policy implementation, effective assignment and service applicability\nbefore treating a draft target as a mandatory production requirement.\n\n';
  text += 'Load this contract explicitly as a separate source. Use approved/verified linked\nknowledge from the same reviewed publication snapshot. Keep pending attachments\navailable for owner review rather than loading them as authoritative agent rules.\n\n';
  text += '## Generation sequence\n\n';
  text += '1. Establish resource type and variant, subscription, environment, approved region/SKU, data classification and existing dependencies.\n';
  text += '2. Retrieve the baseline, the matching resource reference and shared monitoring/network/identity controls. Record document IDs, sections and the reviewed publication SHA.\n';
  text += '3. Build a setting matrix with the Azure setting, target value, reason, applicability, policy definition/reference ID and effect, Terraform or policy owner, provider/module field and validation evidence.\n';
  text += '4. Resolve field names, types, enum values and supported combinations from the actual approved provider/module version. Translate Azure Disabled into the field-specific boolean or enum; verify nested and child-resource settings explicitly.\n';
  text += '5. Configure required creation-time settings before resource creation. For an existing resource, obtain a reviewed migration plan for replacement-sensitive changes such as encryption, network mode or authentication.\n';
  text += '6. Preserve the existing tag ownership decision table, storage LRS default and policy-owned private DNS zone-group boundary. Establish diagnostics, Modify and DeployIfNotExists ownership per field/resource so Terraform and remediation converge on the same target.\n';
  text += '7. Run the consuming repository formatting, validation and approved checks. Have an authorized reviewer assess the plan and deployment gates; report live assignment, remediation and connectivity checks separately.\n\n';
  text += 'A missing mandatory value requires the exact input from the authorized owner.\nFor diagnostic-only sources, obtain architecture-specific requirements separately.\nFor an unresolved source conflict, preserve the disputed scope for review and use\nother established requirements within their own scopes. A successful static check\nestablishes syntax/schema validity; deployment and live compliance require their\nown evidence.\n\n';
  text += '## Resource-by-resource implementation map\n\n';
  text += "The resource names below are lookup hints, not a module catalogue, an approved\nprovider version matrix or a guarantee of field support. Use each reference's\nsetting/value/reason table with the actual consuming implementation. AKS pod\ncontrols belong in workload manifests; guest OS controls, identity configuration\nand shared platform remediation can require owners beyond the resource block.\n\n";
  text += '| SecOps resource/domain | Terraform lookup hints | Configuration outcomes to implement and verify |\n| --- | --- | --- |\n';
  for (const [title, types, outcomes] of resources) {
    text += `| [${title}](../reference/secops-policies-${slug(title)}.md) | ${types.split('; ').map(type => `\`${type}\``).join('; ')} | ${outcomes} |\n`;
  }
  text += '\n## Effects and shared ownership\n\n';
  text += '| Source-stated effect | Implementation action | Evidence to obtain |\n| --- | --- | --- |\n';
  text += '| Deny | Set the applicable resource target at creation/update. | Verified definition conditions, parameters, scope and supported resource variant. |\n';
  text += '| Modify | Confirm the owner and reconcile Terraform with the policy-modified field. | Selected aliases, request-time behavior, identity/role requirements and any existing-resource remediation. |\n';
  text += '| DeployIfNotExists | Establish ownership of the companion configuration and any dependency before generation. | Assignment identity/roles, destination IDs, deployment conditions and remediation result. |\n';
  text += '| Audit / AuditIfNotExists | Implement the applicable approved target and assign findings to an owner. | Explicit configuration evidence plus current audit/compliance findings. |\n\n';
  text += 'Use the supplied central monitoring destination and retain its named diagnostic\nsetting under its approved owner. Confirm service-specific diagnostic category\nsupport, actual logging coverage, retention and alert handling. A policy row for\none subtype establishes that subtype only. Workload-specific CMK, private-endpoint\ntopology, DDoS and Defender choices require their applicable classification,\napproval and operational ownership; preserve the distinction between included,\nconditional and excluded default controls.\n\n';
  text += '## Required implementation report\n\n';
  text += 'Use the [action-oriented answer structure](../guides/secops-policies.md#answer-template)\nwith concrete enabled/disabled values and reasons. Include the setting matrix,\nactual provider/module revision, state ownership, source IDs/sections, assumptions\nand required approvals. State each check as passed, failed, not validated or\nrequiring human approval. For this working copy report an unpublished draft;\nidentify a reviewed contract revision only after the actual publication has\nreceived its scoped review.\n';
  assertSafe(text);
  return { file: 'engineering-contract/secops-resource-controls.md', text };
}

export function importPolicies(sourceDirectory, root, baseline) {
  const expected = resources.map(([title]) => `${title}.md`).sort();
  const entries = fs.readdirSync(sourceDirectory, { withFileTypes: true });
  if (entries.some(entry => !entry.isFile())
    || JSON.stringify(entries.map(entry => entry.name).sort()) !== JSON.stringify(expected)) {
    throw new Error('Expected exactly the 42 reviewed Markdown attachments; review any changed inventory');
  }
  const documents = resources.map(([title]) => buildReference(
    fs.readFileSync(path.join(sourceDirectory, `${title}.md`), 'utf8'), title, baseline,
  ));
  documents.push(buildResourceContract());
  for (const { file, text } of documents) {
    const target = path.join(root, file);
    if (fs.existsSync(target) && fs.readFileSync(target, 'utf8') !== text) {
      throw new Error(`Existing content differs; resolve the update through review: ${file}`);
    }
  }
  for (const { file, text } of documents) {
    const target = path.join(root, file);
    if (!fs.existsSync(target)) fs.writeFileSync(target, text, { flag: 'wx' });
  }
  return documents;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [sourceDirectory, baseline] = process.argv.slice(2);
  if (!sourceDirectory || !baseline || process.argv.length !== 4) {
    throw new Error('Usage: node scripts/import-secops-policies.mjs <attachment-directory> <full-authoring-baseline-SHA>');
  }
  const root = fileURLToPath(new URL('../', import.meta.url));
  const documents = importPolicies(sourceDirectory, root, baseline);
  console.log(`Imported or confirmed ${documents.length - 1} pending-review SecOps references and the draft resource contract; no approval or publication performed.`);
}
