# Soun Al Hosn Assessment Runner

Windows-first, locally executed, operator-controlled cybersecurity assessment runner for authorized client environments.

The MVP is read-only. It does not include stealth, AV/firewall evasion, bypass behavior, persistence, credential dumping, exploit execution, lateral movement, auto-remediation, or unauthorized network expansion.

## Current MVP

Implemented:

- Rich terminal launcher with version reporting.
- Startup preflight and healthcheck validation.
- Minimal launch flow: interactive runs ask only for company name and package.
- Config-first/headless launch flow with automatic company-wide scope detection when config scopes are absent.
- Session creation with consent and scope enforcement.
- External runtime paths using `--config`, `--data-dir`, and `--log-dir`.
- Encrypted local workspace primitives for evidence, checkpoints, and sensitive session blobs.
- SQLite local structured storage for module status and normalized findings.
- Windows-aware environment profiling with clean non-Windows degradation.
- Basic, Standard, and Advanced package orchestration.
- Evidence-backed Windows identity, endpoint, local exposure, DNS/email, and approved-scope Nmap modules.
- Evidence-backed M365 / Entra Graph connector for read-only tenant posture where app permissions are provided.
- Read-only Active Directory evidence collection for domain inventory, privileged group exposure, stale account indicators, and directory policy review where approved access exists.
- Nessus `.nessus` and Greenbone/OpenVAS XML import parsing.
- Nessus API export foundation and Greenbone GMP API foundation.
- Asset role and criticality classification with operator overrides, AD-derived context, imported metadata, and naming/subnet heuristics.
- Firewall / VPN imported evidence foundation for vendor-neutral JSON and CSV exports.
- Backup platform imported evidence foundation for vendor-neutral JSON and CSV exports.
- Normalized findings schema and explicit risk scoring.
- Evidence quality fields: source type, collection time, raw evidence path, and finding basis.
- Audit trail, consent metadata, scope confirmation logging, evidence manifest, and bundle hashing.
- Multi-host asset inventory, per-host collection status tracking, and organization coverage summaries for Standard/Advanced.
- Company-wide discovery-to-collection orchestration with worker concurrency and per-host isolation.
- Remote Windows collection foundation over legitimate PowerShell remoting / WinRM patterns when operator credentials and scope allow it.
- Automatic module activation planning with explicit active/not-configured reasons.
- Finding correlation and deduplication for common estate issues such as RDP, SMB, backup, and privileged-access overlaps.
- PDF report, CSV action plan, JSON findings archive, and AES-encrypted ZIP result bundle.
- Optional sanitized SMTP summary plus queued callback retry for SMTP, HTTPS, S3-compatible storage, and SFTP.
- GitHub Actions Windows EXE build and ZIP packaging.
- Remote install/update PowerShell workflow with rollback.
- Unit tests for core modules.

Still partial:

- Greenbone API support depends on optional `python-gvm` and is a foundation, not a fully field-validated integration.
- Nessus API support currently targets export retrieval and reuse of the import parser. It is not a full scan-management client.
- M365 / Entra evidence depends on tenant permissions, licensing, and operator-provided app registration. Unsupported endpoints are marked partial instead of inferred.
- Firewall / VPN and backup platform foundations currently support documented vendor-neutral JSON/CSV import schemas. They do not claim generic vendor coverage beyond those schemas.
- AD evidence requires Windows execution context, approved domain access, and available AD PowerShell cmdlets.
- Auto-remediation remains deliberately out of scope.

## Security Boundaries

The tool fails closed:

- Written authorization confirmation is mandatory.
- Scope control is mandatory. Config-approved scopes are preferred; otherwise Standard/Advanced use directly connected private RFC1918 subnets only and record the scope source.
- Basic package does not perform subnet scanning.
- All collection is read-only.
- Standard and Advanced can assess multiple hosts only inside the approved scope model. Discovery-only assets remain labeled as discovery-only.
- PowerShell is used only for native Windows read-only collection and deployment launch/install.
- The runner does not suppress, evade, tamper with, or bypass defensive controls.
- Unsupported checks are marked skipped or partial rather than forced.

## Production Field Usage Flow

1. Run a health check before touching a client assessment.

```powershell
C:\SounRunner\run_assessment.ps1 -Healthcheck
```

2. Run a full preflight if you need dependency detail.

```powershell
C:\SounRunner\run_assessment.ps1 -Preflight
```

3. Run the authorized package. Interactive launches ask only for company name and package.

```powershell
C:\SounRunner\run_assessment.ps1
```

One-command Standard example:

```powershell
C:\SounRunner\app\SounAlHosnAssessmentRunner.exe --company-name "Client Name" --package standard
```

Installed PowerShell launcher equivalent:

```powershell
C:\SounRunner\run_assessment.ps1 -CompanyName "Client Name" -Package standard
```

That command auto-detects directly connected private subnets, domain context, available connectors/imports, Nmap availability, and estate planning inputs. If config provides approved scopes, config wins over auto-detection.

For company-wide Standard or Advanced runs, the lowest-friction headless path is config-first. If config or CLI defines company name, package, and consent, the runner does not ask again. Site, operator, AD domain, email domain, local scope, and connector availability are auto-detected or config-derived.

Headless Standard example:

```powershell
C:\SounRunner\app\SounAlHosnAssessmentRunner.exe `
  --config C:\SounRunner\config\config.yaml `
  --data-dir C:\SounRunner\data `
  --log-dir C:\SounRunner\logs `
  --package standard `
  --non-interactive `
  --consent-confirmed `
  --report-mode standard
```

If company name, package, or headless consent is missing in headless mode, the runner fails cleanly instead of falling back into fragile prompt chains.

4. If callbacks were enabled and any delivery failed, inspect and retry the queue.

```powershell
C:\SounRunner\run_assessment.ps1 -ShowQueue
C:\SounRunner\run_assessment.ps1 -RetryCallbacks
```

5. If a specific session needs manual resend, use the session ID from the report or output.

```powershell
C:\SounRunner\run_assessment.ps1 -ResendSession <session_id>
```

## Evidence-Backed Assessment Mode

Basic, Standard, and Advanced all rely on real evidence collection where automation exists. Questionnaire and advisory sections are labeled as such and are not reported as confirmed vulnerabilities.

What is real and implemented:

- Microsoft Defender status via `Get-MpComputerStatus`.
- Defender preferences via `Get-MpPreference`.
- Windows Firewall profile status via `Get-NetFirewallProfile`.
- Local Administrators membership via `Get-LocalGroupMember`.
- Local password/account policy via `net accounts`.
- RDP indicators from registry, service, firewall rule, and listener evidence.
- SMB indicators from `Get-SmbServerConfiguration`, service state, and listener evidence.
- BitLocker status via `Get-BitLockerVolume` where available.
- Patch posture indicators via `Get-HotFix`.
- Remote access software indicators from services and installed application registry keys.
- SPF, DMARC, and configured DKIM selector DNS TXT checks.
- Nmap XML parsing and approved-scope host/service discovery.
- Exposure findings for observed services such as RDP, SMB, WinRM, Telnet, and SSH.
- Enterprise network assessment for Standard/Advanced: service classification, management-plane exposure review, segmentation observations, network device identification, firewall/VPN import correlation, and network scoring.

What remains future/integration work:

- Broader Nessus scan/task management beyond export retrieval.
- Broader Greenbone/GMP operational support beyond report retrieval.
- Deeper M365 / Entra control coverage beyond the current read-only posture evidence set.
- Authenticated vulnerability scanner orchestration.

The runner does not invent CVEs. Nmap findings are exposure findings only. A discovered open service is not reported as a vulnerability unless direct evidence supports that conclusion.

Network assessment evidence labels:

- Observed network exposure: open services discovered inside approved scope.
- Inferred network posture: segmentation or topology observations inferred from service patterns, roles, subnet labels, and discovery evidence.
- Confirmed network configuration evidence: imported firewall/VPN configuration evidence only.

Do not treat inferred segmentation observations as confirmed firewall/router/switch configuration failures. Import firewall/VPN evidence when the client needs confirmed ACL or zone findings.

Finding basis values:

- `direct_system_evidence`: direct Windows or DNS control evidence collected from the assessed environment.
- `directory_evidence`: direct Active Directory evidence collected through read-only directory queries.
- `network_discovery_evidence`: approved-scope Nmap discovery evidence.
- `imported_scanner_evidence`: imported scanner export evidence such as Nessus `.nessus` or Greenbone XML.
- `imported_configuration_evidence`: imported non-scanner control evidence such as firewall/VPN or backup platform exports.
- `advisory_questionnaire`: reserved for questionnaire-driven findings.
- `inferred_partial`: partial evidence that requires operator validation.

## Company-Wide Assessment Mode

Basic remains a local, small-scope package. Standard and Advanced now support company-wide assessment orchestration.

How it works:

1. Approved scopes from config become the discovery boundary.
2. The runner builds a central asset inventory from every configured truth source it can use safely:
   - approved-scope Nmap discovery
   - Active Directory computer objects
   - imported scanner evidence
   - imported firewall/VPN evidence
   - imported backup platform evidence
   - configured cloud evidence
3. Asset records are enriched with hostname/FQDN, site, business unit, role, criticality, and evidence lineage.
4. The assessment planner decides which connectors and modules should run, records explicit active/not-configured reasons, and warns when coverage will be limited.
5. The orchestrator selects a remote Windows collection strategy and plans collection automatically for eligible in-scope hosts.
6. The network assessment module analyzes observed services, likely network devices, management exposure, insecure protocols, inferred segmentation, and imported firewall/VPN configuration evidence.
7. Discovery-only, imported-only, partial, unreachable, and fully assessed states are preserved honestly.
8. Estate-level coverage, repeated control issues, network score, and coverage gaps are generated automatically in Standard and Advanced.

Discovery-only vs fully assessed:

- `discovery_only`: host was found in approved scope, but no safe remote evidence path was available or WinRM was not observed.
- `partial`: some remote evidence was collected or access was limited.
- `assessed`: remote host evidence was collected successfully.
- `unreachable`: the host was discovered, but remote collection could not connect.

This matters because a discovered RDP or SMB service is not the same thing as a completed host posture assessment. The reports now separate those cases.

Advisory and partial items are not confirmed technical vulnerabilities. Reports separate them from direct system and network discovery findings.

## Minimal Launch And Headless Execution

Basic can still be launched interactively as a local validation mode. Standard and Advanced are designed to launch as company-wide assessment modes with minimal operator friction.

Interactive prompt contract:

- company name
- package: `basic`, `standard`, or `advanced`

Everything else is config-derived, environment-derived, connector-derived, or marked skipped/not configured. The runner no longer asks for subnet, site, operator, AD domain, business unit, email domain, connector availability, allowlist, or denylist during normal interactive launch.

Supported launch overrides:

- `--package basic|standard|advanced`
- `--non-interactive`
- `--company-name`
- `--client-name`
- `--site`
- `--operator`
- `--scope-from-config`
- `--approved-scope 10.0.180.0/24`
- `--consent-confirmed`
- `--report-mode`
- existing `--preflight`, `--healthcheck`, `--show-queue`, and `--retry-callbacks`

Behavior:

- If config already contains approved scopes, they are used as the assessment boundary.
- If `--approved-scope` is supplied, it overrides config and auto-detection for that run and records `scope_source=cli_scope`.
- If config scopes are absent, Standard/Advanced use auto-detected directly connected private subnets as the default company scope.
- If only loopback or non-private interfaces are detected, Basic can use `local-host-only`. Standard/Advanced block localhost fallback by default unless `assessment.allow_localhost_fallback_for_company_modes: true` is explicitly configured.
- Interactive prompting is reserved for company name and package.
- Optional fields do not force extra prompts during company-wide runs.
- If Standard or Advanced is explicitly allowed to run with `local-host-only`, the report warns that estate coverage is limited.

One-command Standard launch:

```powershell
C:\SounRunner\app\SounAlHosnAssessmentRunner.exe --company-name "Client Name" --package standard
```

Explicit approved-scope launch when auto-scope cannot read Windows adapter evidence:

```powershell
C:\SounRunner\app\SounAlHosnAssessmentRunner.exe --company-name "Client Name" --package standard --approved-scope 10.0.180.0/24
```

Config-approved scope launch:

```powershell
C:\SounRunner\app\SounAlHosnAssessmentRunner.exe `
  --config C:\SounRunner\config\config.yaml `
  --package standard `
  --non-interactive `
  --consent-confirmed
```

Example headless Advanced launch:

```powershell
C:\SounRunner\app\SounAlHosnAssessmentRunner.exe `
  --config C:\SounRunner\config\config.yaml `
  --data-dir C:\SounRunner\data `
  --log-dir C:\SounRunner\logs `
  --package advanced `
  --non-interactive `
  --consent-confirmed `
  --report-mode advanced
```

## Auto-Scope And Enterprise Context

Standard and Advanced determine scope in this order:

1. `--approved-scope` from CLI for the current authorized run.
2. `assessment.approved_scopes` or `assessment.approved_scope` from config.
3. The highest-confidence directly connected private RFC1918 IPv4 subnet from active local interfaces, with the default IPv4 route interface preferred.
4. `local-host-only` fallback for Basic only, unless company-mode localhost fallback is explicitly allowed in config.

The runner records the scope source as `cli_scope`, `config_scope`, `auto_detected_local_subnets`, or `localhost_only_fallback`. It does not scan arbitrary routed networks just because they are reachable. Broader routed networks must be explicitly approved by CLI or config.

Auto-scope ignores loopback, APIPA, CGNAT/Tailscale, Docker, WSL, Hyper-V internal, VMware, VirtualBox, Default Switch, host-only, NAT-only, ZeroTier, and VPN-style adapters by default. Use `assessment.auto_scope_allowed_adapter_keywords` only when a known lab adapter is explicitly approved for auto-scope.

Preflight includes an `auto_scope_detection` row showing detected adapters, ignored adapters with reasons, selected interface, selected IP/prefix, selected CIDR, confidence score, and scope source.

Detected enterprise context includes hostname, FQDN, domain join state, DNS suffixes, local site heuristic, inferred AD domain, inferred email domain, and directly connected private subnets.

Windows auto-scope uses merged read-only evidence from `Get-NetIPAddress`, `Get-NetAdapter`, `Get-NetRoute`, and `Get-DnsClient`. If that merged collector returns no rows, it falls back to `Get-NetIPAddress`, `route print -4`, and `ipconfig /all` parsing. It prefers the physical Ethernet/Wi-Fi adapter on the active default IPv4 route and ignores APIPA, loopback, CGNAT/Tailscale, Hyper-V/vEthernet, VMware, VirtualBox, Docker, WSL, VPN, host-only, and NAT-only adapters unless explicitly allowed.

Debug auto-scope decisions without starting an assessment:

```powershell
python .\main.py --debug-auto-scope
```

The debug output shows raw adapter rows, calculated CIDR, default-route status, ignored/selected decision, ignore reason, and final selected scope.

Use `--debug-auto-scope` when Standard/Advanced unexpectedly report `localhost_only_fallback`. The output includes platform, PowerShell path, each collector attempt, return code, stdout length, stderr preview, parsed row count, raw adapter summaries, ignored reasons, and the final selected scope. If the Windows collector is blocked by execution policy, endpoint controls, or missing PowerShell cmdlets, use the explicit approved scope mode for the authorized subnet.

## Automatic Module Activation

Standard and Advanced no longer behave like fixed prompt-driven scripts. They activate modules from config and evidence availability.

Examples:

- If `active_directory.enabled: true`, AD evidence is attempted and inventory is enriched from directory data.
- If explicit remote Windows credentials are configured, the orchestrator uses them for approved in-scope WinRM collection.
- If no credentials are configured but the runner is on a domain-joined Windows host, it can attempt current-user integrated WinRM using the active Windows security context.
- If neither path is available, hosts remain discovery-only and the report states why.
- If firewall/VPN or backup import paths exist, those imports are ingested automatically.
- If a client domain exists, DNS/email posture checks run.
- If M365 / Entra config is present, the cloud evidence connector runs.
- If Nessus or Greenbone imports/API are configured, scanner evidence is ingested.

Activation decisions are written into metadata and surfaced in the run output. Missing connectors are marked `not_configured`, `skipped`, or `partial`. They are not silently ignored.

## Assessment Brain

Standard and Advanced now use a central planning layer instead of scattered per-module assumptions.

What that plan does:

1. reads approved scope and connector state
2. records which discovery sources are active
3. marks which modules will run and which are not configured
4. drives estate discovery and remote collection planning
5. feeds assessment warnings and coverage gaps into the final report

This matters because the final report now explains why an asset was fully assessed, partially assessed, discovery-only, or import-only.

## Finding Correlation And Deduplication

Standard and Advanced now correlate common duplicate issues before final reporting.

Examples:

- direct host RDP evidence + Nmap RDP exposure
- direct host SMB evidence + Nmap SMB exposure
- local/admin governance findings on the same host
- backup platform evidence + backup readiness findings on the same asset

What changes:

- original evidence paths are preserved
- merged findings retain source-aware evidence lineage
- reports and JSON outputs use the consolidated finding instead of dumping obvious duplicates side by side
- estate-level repeated findings are generated from the correlated set, not the noisy raw set

## Automatic Remote Windows Collection Strategy

Standard and Advanced do not require an interactive credential prompt. The runner chooses one of three strategies:

- `configured_credentials`: used when `remote_windows.enabled: true`, a username is configured, and the password is referenced through an environment variable or external secret file.
- `current_user_integrated_auth`: used when no explicit credential is configured, the runner is executing on Windows with PowerShell available, and domain context is detected. This uses WinRM/PowerShell remoting with the current Windows security context. No password is requested or stored.
- `discovery_only_fallback`: used when there is no configured credential path and no safe current-user domain-auth path. Assets remain discovery-only unless imports or other evidence sources cover them.

By default, automatic current-user collection only attempts hosts where approved discovery observed WinRM on TCP 5985 or 5986. This is deliberate. The runner does not enable WinRM, change firewalls, try alternate admin channels, or guess credentials.

Reports and the terminal dashboard show:

- remote collection strategy
- Windows candidate count
- collection attempts
- successful, partial, and failed collection counts
- top remote failure reason
- discovery-only assets caused by missing or blocked remote collection paths

To improve coverage safely, use a client-approved domain assessment account and store the password outside the config:

```powershell
$env:SOUN_RUNNER_REMOTE_WINDOWS_PASSWORD = "use-the-client-approved-secret"
SounAlHosnAssessmentRunner.exe --company-name "Client Name" --package standard
```

```yaml
remote_windows:
  enabled: true
  username: "CORP\\assessment-operator"
  password_env: "SOUN_RUNNER_REMOTE_WINDOWS_PASSWORD"
  require_winrm_port_observed: true
```

## Enterprise Network Assessment

Standard and Advanced now run a dedicated network assessment layer after approved-scope discovery and import ingestion. It does not run exploits, brute force, stealth flags, intrusive Nmap scripts, packet flooding, or remediation. It only uses approved-scope discovery, inventory, imported configuration evidence, and connector evidence already available to the session.

The network layer produces:

- network scope summary and scan profile used
- services by category
- assets and services by subnet/site
- management-plane exposure review
- insecure protocol summary
- likely network device inventory
- segmentation observations
- firewall/VPN evidence summary
- network score with confidence and key drivers
- top network remediation actions

Service categories:

- `remote_admin`: RDP, SSH, WinRM, VNC
- `file_sharing`: SMB, NFS, FTP
- `directory_identity`: LDAP, Kerberos, DNS, DC-like SMB
- `web_admin`: HTTP/HTTPS admin panels or web consoles
- `database`: MSSQL, MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch
- `insecure_cleartext`: Telnet, FTP, HTTP, POP3, IMAP, observable SNMP exposure
- `network_infrastructure`: switches, routers, firewalls, AP controllers, printers
- `backup_storage`: NAS, backup consoles, and storage services
- `unknown_exposed`: open services not safely classified

Safe scan profiles:

- `discovery`: host discovery only.
- `exposure`: safe TCP connect scan over top ports, capped by `network_assessment.max_ports_per_host`.
- `service_inventory`: exposure profile with light service/version detection.
- `deep_safe`: optional approved safe scripts only. Intrusive, auth, brute-force, exploit, DoS, default, and vuln scripts are rejected.

Example network config:

```yaml
network_assessment:
  enabled: true
  profile: "exposure"
  include_service_version_detection: false
  include_deep_safe_scripts: false
  max_hosts: 4096
  max_ports_per_host: 200
  scan_timeout_seconds: 600
  classify_network_devices: true
  infer_segmentation: true
  require_config_evidence_for_confirmed_segmentation: true
```

Recommended network actions generated by the report are configuration recommendations, not auto-remediation:

1. restrict RDP/SSH/WinRM to admin subnet, jump host, or VPN source ranges
2. isolate servers from workstations
3. move infrastructure admin panels to a management VLAN
4. disable Telnet/FTP where detected
5. ingest firewall/VPN config to confirm ACL and zone posture

## Nmap On Windows

Install Nmap on the client machine only if approved for the assessment scope.

Recommended install path:

```powershell
winget install Insecure.Nmap
```

If `winget` is unavailable, install Nmap from the official Windows installer and confirm:

```powershell
nmap --version
```

If Nmap is not installed, the Nmap module is skipped cleanly. Local Windows posture and DNS checks still run.

## Assessment Config

Edit:

```text
C:\SounRunner\config\config.yaml
```

Approved scope example:

```yaml
assessment:
  approved_scopes:
    - "192.168.10.0/24"
    - "192.168.20.0/24"
  host_allowlist:
    - "192.168.10.15"
    - "fileserver01"
  host_denylist:
    - "192.168.20.250"
  ad_domain: "corp.example.local"
  business_unit: "Corporate IT"
  scope_labels:
    "192.168.10.0/24": "HQ"
    "192.168.20.0/24": "Branch-A"
  client_domain: "example.com"
  allow_localhost_fallback_for_company_modes: false
```

Remote Windows collection example:

```yaml
orchestration:
  enabled: true
  max_workers: 5
  per_host_timeout_seconds: 90
  retry_count: 1

remote_windows:
  enabled: true
  auto_current_user: true
  attempt_current_user_when_domain_joined: true
  require_winrm_port_observed: true
  max_auto_attempts: 50
  transport: "winrm"
  username: "CORP\\assessment-operator"
  password_env: "SOUN_RUNNER_REMOTE_WINDOWS_PASSWORD"
  auth: "default"
  use_ssl: false
  port: 5985
  connection_timeout_seconds: 30
  operation_timeout_seconds: 60
```

Active Directory, classification, and import foundations example:

```yaml
active_directory:
  enabled: true
  domain: "corp.example.local"
  computer_limit: 500
  user_limit: 500
  stale_account_days: 90
  include_ou_mapping: true

asset_classification:
  critical_assets:
    - "dc1.corp.example.local"
    - "erp-app-01"
  criticality_by_subnet:
    "192.168.20.0/24": "high"
  criticality_by_site:
    "HQ": "critical"
  role_overrides:
    "fw-hq-01": "network_device"

firewall_vpn_import:
  enabled: true
  import_paths:
    - "C:\\SounRunner\\config\\imports\\firewall-vpn.json"

backup_platform_import:
  enabled: true
  import_paths:
    - "C:\\SounRunner\\config\\imports\\backup-jobs.json"
  stale_success_days: 7
```

Neutral firewall/VPN JSON/YAML import example:

```json
{
  "policies": [
    {
      "device_name": "fw-hq",
      "rule_name": "Allow-Admin-RDP",
      "source": "vpn-admins",
      "destination": "server-vlan",
      "service": "rdp",
      "action": "allow",
      "enabled": true
    }
  ],
  "management_exposures": [
    {
      "device_name": "fw-hq",
      "service": "https",
      "internet_exposed": false,
      "admin_interface": true
    }
  ],
  "vpn_endpoints": [
    {
      "device_name": "vpn-hq",
      "internet_exposed": true,
      "remote_access_vpn_enabled": true
    }
  ]
}
```

Supported neutral fields include `device_name`, `vendor`, `zone`, `interface`, `rule_id`, `rule_name`, `source`, `source_zone`, `destination`, `destination_zone`, `service`, `port`, `action`, `enabled`, `internet_exposed`, `admin_interface`, and `remote_access_vpn_enabled`. Missing fields are treated as partial imported evidence, not as confirmed absence.

Field validation example:

```yaml
field_validation:
  enable_winrm_sample_checks: true
  winrm_sample_targets:
    - "server01.corp.example.local"
    - "10.0.10.25"
  max_samples: 2
```

Nmap example:

```yaml
nmap:
  enabled: true
  path: "nmap"
  profile: "top-ports"
  service_version_detection: false
  timeout_seconds: 180
  top_ports: 100

network_assessment:
  enabled: true
  profile: "exposure"
  include_service_version_detection: false
  include_deep_safe_scripts: false
  max_hosts: 4096
  max_ports_per_host: 200
  scan_timeout_seconds: 600
```

DKIM selector example:

```yaml
email_security:
  dns_timeout_seconds: 10
  dkim_selectors:
    - "selector1"
    - "selector2"
```

If DKIM selectors are unknown, leave the list empty. The report will state that DKIM was not assessed instead of pretending DKIM failed.

During normal interactive launch, the runner no longer asks for scope. Configured `approved_scopes` are the strongest boundary. If they are absent, Standard/Advanced use only directly connected private RFC1918 subnets detected on the assessment host. Empty or invalid configured scope values are rejected cleanly, and the runner does not scan outside approved or auto-detected local private scope.

Headless company-wide configs should populate launch defaults directly. Site and operator are optional because the runner can infer them, but explicit config values are better for audit quality.

```yaml
assessment:
  client_name: "Example Client"
  site: "HQ"
  operator_name: "Assessment Operator"
  package: "standard"
  consent_confirmed: true
  scope_notes: "Authorized estate assessment."
  approved_scopes:
    - "192.168.10.0/24"
    - "192.168.20.0/24"
```

## Active Directory Evidence

The AD module is read-only. It uses native PowerShell AD cmdlets when they are available and the operator has approved domain access.

Current AD evidence coverage:

- domain identity and directory mode
- domain controller inventory
- sampled computer objects
- sampled enabled/disabled user indicators
- stale enabled account indicators
- privileged group membership counts
- default domain password and lockout policy
- OU and site context where returned by directory evidence

If AD cmdlets are missing or access is not available, the module is marked `partial` or `skipped`. The runner does not pretend the domain was assessed.

## Role And Criticality Classification

Every asset can now carry both a role and a criticality rating.

Role sources:

- operator-provided override
- AD-derived evidence
- imported metadata
- naming/subnet heuristic

Criticality sources:

- operator-provided critical asset list
- explicit per-asset/subnet/site mapping
- AD-derived elevation for domain controllers
- role-based default when no stronger source exists

This classification feeds risk scoring, repeated finding summaries, and company-wide reporting. If the source is heuristic, that is what the record says. The tool does not overclaim certainty.

## Firewall / VPN Import Foundation

This is a read-only imported-evidence path. It is not an API collector and it does not claim generic vendor support.

Supported now:

- vendor-neutral JSON with `management_exposures`, `vpn_endpoints`, and `policies`
- flat CSV with fields such as `asset`, `exposure_type`, `service`, `port`, `internet_exposed`, `admin_interface`, and `policy_name`

Normalized outputs include:

- remote access exposure
- inbound management exposure
- broad management policy indicators
- VPN exposure indicators
- administrative interface exposure

These findings are tagged as `imported_configuration_evidence`.

## Backup Platform Import Foundation

This is also a read-only imported-evidence path.

Supported now:

- vendor-neutral JSON with a `jobs` array
- flat CSV with `asset`, `status`, `last_run`, `last_success`, `repository_type`, `immutable`, `offline`, and `restore_test`

Normalized outputs include:

- backup jobs present
- failed job indicators
- stale last successful backup indicators
- repository/target protection indicators
- restore-test status indicators

The runner does not claim restore readiness unless evidence or questionnaire input actually supports that conclusion.

## Safe Credential Handling

Do not put plaintext secrets in `config.yaml` unless there is no approved alternative. The preferred order is:

1. environment variable reference
2. secret file reference outside report/export paths
3. inline plaintext only as a last resort

Current secret-capable fields include:

- remote Windows credential reference
- SMTP password
- M365 client secret
- Nessus API keys
- Greenbone password
- S3/SFTP/HTTPS callback secrets

Preflight now warns when secret references are missing or when plaintext secrets are embedded in config. Reports, logs, session metadata, and callbacks are designed to avoid leaking secret values.

## WinRM Field Troubleshooting

Soun Runner does not widen scope or pivot to alternate admin channels when WinRM fails. It reports the blocker and moves on.

Common remoting failure categories:

- `winrm_unavailable`
- `auth_failed`
- `access_denied`
- `dns_resolution`
- `firewall_blocked`
- `timeout`
- `partial_remote_evidence`

Use:

```powershell
C:\SounRunner\run_assessment.ps1 -Preflight
```

Review the remote readiness section before a company-wide run. If sample checks fail, fix the approved management path first instead of retrying blindly.

## What Basic Actually Assesses

Basic assesses:

- Local Windows security posture.
- Local administrator and account policy posture.
- Defender, firewall, BitLocker, update, RDP, SMB, and remote access indicators.
- Email authentication DNS posture for the provided domain.
- Approved-scope Nmap host/service exposure when Nmap is installed and enabled.

Basic does not assess:

- Exploitability.
- Credential exposure.
- Lateral movement.
- Full vulnerability inventory.
- Cloud identity posture unless a future connector is implemented.
- Business continuity readiness, backup restore validation, or SOP maturity. Those are assessed only in Standard/Advanced as guided evidence, not as fully automated proof.
- Estate-wide remote host posture. That is a Standard/Advanced capability.

## Standard Package

Standard is now implemented as a real package path. It reuses Basic evidence-backed modules and adds hybrid readiness modules.

Standard runs:

- Basic local Windows posture, DNS/email posture, and approved-scope Nmap exposure checks.
- Multi-host discovery across configured approved CIDRs or auto-detected directly connected private subnets by default.
- Central asset inventory with discovery-only, partial, assessed, and unreachable host states.
- Automatic target planning from discovery, AD, and imported evidence sources.
- Remote Windows posture collection across eligible in-scope hosts using authorized WinRM/PowerShell remoting.
- Repeated-control aggregation such as the same control gap appearing across many endpoints.
- Backup readiness review.
- Ransomware readiness scoring.
- Shared and privileged access review.
- Incident response readiness review.
- Optional M365/Entra imported evidence foundation.
- Optional Nessus `.nessus` and Greenbone/OpenVAS XML import parsing.
- Prioritized remediation roadmap output.

Standard is honest about evidence quality:

- Direct Windows and DNS evidence is marked as `direct_system_evidence`.
- Nmap service exposure is marked as `network_discovery_evidence`.
- Nessus and Greenbone imported findings are marked as `imported_scanner_evidence`.
- Backup restore, offline backup, IR process, and privileged access governance prompts are marked as `advisory_questionnaire`.
- Ransomware readiness scoring is marked as `inferred_partial` because it aggregates assessment evidence and does not run malware tests.

Run Standard on Windows:

```powershell
C:\SounRunner\app\SounAlHosnAssessmentRunner.exe --company-name "Client Name" --package standard
```

Headless/config-driven Standard:

```powershell
C:\SounRunner\app\SounAlHosnAssessmentRunner.exe `
  --config C:\SounRunner\config\config.yaml `
  --data-dir C:\SounRunner\data `
  --log-dir C:\SounRunner\logs `
  --package standard `
  --non-interactive `
  --consent-confirmed
```

Standard outputs include:

- `assessment_report.pdf`
- `action_plan.csv`
- `findings.json`
- `prioritized_roadmap.csv`
- `results_bundle.zip`

Standard company-wide output now adds:

- organization coverage summary
- repeated finding summary
- host appendix with per-host status
- subnet/site grouping in the report

## Advanced Package

Advanced is implemented as a guided assessment foundation on top of Standard. It is intentionally hybrid. It does not pretend that business continuity, vendor access, policy maturity, or awareness readiness can be fully proven by local technical collection.

Advanced adds:

- Business continuity risk review prompts.
- Recovery priority mapping prompts.
- Backup restore process review prompts.
- Ransomware impact scenario prompts.
- Key department and vendor access review prompts.
- Policy/SOP gap review prompts.
- Awareness session output pack structure.
- 30/60/90-day action plan output.

Advanced reuses the same company-wide inventory and remote collection model as Standard, then layers guided business continuity and planning outputs on top.

Run Advanced on Windows:

```powershell
C:\SounRunner\app\SounAlHosnAssessmentRunner.exe --company-name "Client Name" --package advanced
```

Headless/config-driven Advanced:

```powershell
C:\SounRunner\app\SounAlHosnAssessmentRunner.exe `
  --config C:\SounRunner\config\config.yaml `
  --data-dir C:\SounRunner\data `
  --log-dir C:\SounRunner\logs `
  --package advanced `
  --non-interactive `
  --consent-confirmed
```

Advanced outputs include all Standard outputs plus:

- `30_60_90_day_plan.csv`

## Scanner Imports And API Foundations

The runner does not launch Nessus or Greenbone scans. It consumes legitimate scanner output or fetches completed results through read-only API foundations.

Configure import paths:

```yaml
scanner_integrations:
  nessus_import_path: "C:\\SounRunner\\config\\imports\\client-export.nessus"
  greenbone_import_path: "C:\\SounRunner\\config\\imports\\greenbone-report.xml"
```

Supported now:

- Nessus `.nessus` XML `ReportHost` and `ReportItem` parsing.
- Greenbone/OpenVAS XML `result` parsing.
- Severity mapping into Soun Runner severity.
- Raw import preservation as encrypted session evidence.
- Findings tagged as `imported_scanner_evidence`.
- Nessus API export retrieval from completed scans using X-ApiKeys authentication.
- Greenbone GMP report retrieval foundation using optional `python-gvm`.

Not supported yet:

- Full Nessus scan lifecycle management.
- Full Greenbone task lifecycle management.
- Scanner credential management.
- Any exploit validation.

## M365 / Entra Connector

The M365 / Entra connector is read-only and non-interactive. It uses Microsoft Graph app credentials when provided. Secrets stay in environment variables, not config files.

Configured Graph mode:

```yaml
m365_entra:
  enabled: true
  tenant_id: "tenant-id-guid-or-domain"
  client_id: "app-registration-client-id"
  client_secret_env: "SOUN_RUNNER_M365_CLIENT_SECRET"
  authority_host: "login.microsoftonline.com"
  graph_base_url: "https://graph.microsoft.com"
  timeout_seconds: 30
  user_registration_limit: 50
  legacy_sign_in_lookback_days: 14
```

Required application permissions for current Graph evidence collection:

- `AuditLog.Read.All`
- `Policy.Read.All`
- `Policy.Read.AuthenticationMethod`
- `RoleManagement.Read.Directory`

Current Graph evidence coverage:

- Security defaults state.
- Authentication methods policy.
- User registration details sample for MFA registration posture.
- Recent legacy-auth sign-in indicators when logs are accessible.
- High-value privileged role membership counts.

Current fallback mode if live Graph access is unavailable:

```yaml
m365_entra:
  enabled: true
  tenant_id: "tenant-id-guid-or-domain"
  client_id: ""
  evidence_json_path: "C:\\SounRunner\\config\\imports\\m365-evidence.json"
```

If Graph auth fails, permissions are missing, or licensing blocks a dataset, the module returns `partial` and writes the raw error context into encrypted evidence. It does not invent a tenant finding.

## Validated Vs Partial

Fully validated in code and test coverage:

- local/session storage, encrypted evidence, manifesting, callbacks, and report generation
- Basic local evidence-backed posture modules
- Standard/Advanced orchestration, inventory tracking, and aggregation
- AD normalization logic
- role/criticality classification logic
- firewall/VPN imported evidence normalization
- enterprise network service classification, management exposure review, inferred segmentation observations, network scoring, and report sectioning
- backup platform imported evidence normalization
- secret masking and preflight secret validation
- remoting failure categorization

Still partial or environment-dependent:

- live WinRM collection across real client endpoints
- live AD connectivity in each customer environment
- live M365 Graph permissions and licensing behavior
- live Nessus and Greenbone API connectivity
- vendor-specific firewall/VPN or backup export formats beyond the documented neutral schemas
- confirmed segmentation analysis without firewall/router/switch configuration import evidence

## Callback And Retry Flow

Callbacks are optional and failure-safe. The assessment completes even if every callback fails.

The runner always keeps the encrypted bundle locally. Upload is an additional return path, not a replacement.

Sanitized email summary includes only:

- Client/entity name.
- Site/branch.
- Assessment date/time.
- Package.
- Version.
- Severity counts.
- Top 5 findings.
- Bundle filename.
- Callback ID and status.

It never includes raw evidence or decrypted findings archives.

Enable callback:

```yaml
callback:
  enabled: true
  send_smtp_summary: true
  upload_bundle: true
  max_retry_attempts: 3
  base_retry_delay_seconds: 60
  max_retry_delay_seconds: 3600
  https:
    enabled: true
    url: "https://example.internal/soun-runner/upload"
    token_env: "SOUN_RUNNER_HTTPS_TOKEN"
```

SMTP uses the existing `smtp` section. S3 and SFTP are optional providers:

```yaml
callback:
  enabled: true
  upload_bundle: true
  s3:
    enabled: true
    endpoint_url: "https://s3.example.internal"
    bucket: "assessment-results"
    key_prefix: "soun-runner"
```

S3 upload requires optional `boto3` installed in the build environment. SFTP upload requires optional `paramiko`. If those dependencies or credentials are missing, callback items are queued instead of breaking the assessment.

Failed callback attempts are queued under the workspace callback queue by default:

```text
C:\SounRunner\data\callback_queue
```

Callback controls:

```powershell
C:\SounRunner\run_assessment.ps1 -ShowQueue
C:\SounRunner\run_assessment.ps1 -RetryCallbacks
C:\SounRunner\run_assessment.ps1 -ResendSession <session_id>
```

Each session also writes encrypted callback status under:

```text
C:\SounRunner\data\sessions\<session_id>\export\callback_status.json.enc
```

## Installed Windows Layout

The deployment scripts install to:

```text
C:\SounRunner
├── app
├── config
├── data
├── logs
├── rollback
├── install_or_update.ps1
└── run_assessment.ps1
```

Preserved across updates:

- `C:\SounRunner\config`
- `C:\SounRunner\data`
- `C:\SounRunner\logs`

Application files under `C:\SounRunner\app` are replaceable. If an update fails validation, the installer rolls back the previous app directory.

## GitHub Build

The workflow at `.github/workflows/windows-build.yml` runs on every push and on tags matching `v*`.

On every push:

- Installs dependencies on `windows-latest`.
- Runs `pytest`.
- Builds `SounAlHosnAssessmentRunner.exe` with PyInstaller.
- Packages a ZIP artifact named `soun-runner-windows`.

On version tags:

- Publishes `SounAlHosnAssessmentRunner-windows.zip` to the GitHub Release.

Release ZIPs are the approved client distribution path. Actions artifacts are useful for testing, but they can expire and usually require a token.

Create an approved release:

```powershell
git tag v0.1.0
git push origin v0.1.0
```

## First Install On Remote Windows Machine

Do this over AnyDesk in a normal PowerShell terminal. Do not manually copy repo files to the client machine.

Set your repository once:

```powershell
$Repo = "OWNER/REPO"
```

Download only the installer script from GitHub:

```powershell
$Installer = "$env:TEMP\install_or_update.ps1"
Invoke-WebRequest "https://raw.githubusercontent.com/$Repo/main/scripts/install_or_update.ps1" -OutFile $Installer
Unblock-File $Installer
powershell -NoProfile -File $Installer -Repository $Repo
```

For a private repository or private release, provide a GitHub token with read access:

```powershell
$env:GITHUB_TOKEN = "<token>"
powershell -NoProfile -File $Installer -Repository $Repo -GitHubToken $env:GITHUB_TOKEN
```

To install from a specific approved tag:

```powershell
powershell -NoProfile -File $Installer -Repository $Repo -Version v0.1.0
```

To test from the latest non-expired Actions artifact instead of a release:

```powershell
powershell -NoProfile -File $Installer -Repository $Repo -UseActionsArtifact -GitHubToken $env:GITHUB_TOKEN -Branch main
```

## Update Process

After first install, update from the client machine:

```powershell
C:\SounRunner\install_or_update.ps1 -Repository "OWNER/REPO"
```

Or pin to a release tag:

```powershell
C:\SounRunner\install_or_update.ps1 -Repository "OWNER/REPO" -Version v0.1.0
```

What happens during update:

- Downloads the approved release ZIP or selected Actions artifact.
- Supports local ZIP or local staged package install when GitHub access is not available.
- Extracts and stages the new app under `C:\SounRunner\tmp`.
- Validates `version.txt`, required package files, and `SounAlHosnAssessmentRunner.exe --version`.
- Moves the existing app to `C:\SounRunner\rollback\app-<timestamp>`.
- Installs the staged app to `C:\SounRunner\app`.
- Runs `--healthcheck` after install.
- Restores the previous app automatically if validation or install fails.
- Leaves `config`, `data`, and `logs` untouched.

Local-source update examples:

```powershell
C:\SounRunner\install_or_update.ps1 -LocalZipPath C:\Temp\SounAlHosnAssessmentRunner-windows.zip
C:\SounRunner\install_or_update.ps1 -LocalSourcePath C:\Temp\SounRunner
```

## Running Remotely Via AnyDesk

Launch the installed runner:

```powershell
C:\SounRunner\run_assessment.ps1
```

Smoke test:

```powershell
C:\SounRunner\run_assessment.ps1 -Sample
```

Operator cheatsheet:

```powershell
C:\SounRunner\run_assessment.ps1 -ShowCheatsheet
```

The launcher passes explicit external paths:

```powershell
C:\SounRunner\app\SounAlHosnAssessmentRunner.exe `
  --config C:\SounRunner\config\config.yaml `
  --data-dir C:\SounRunner\data `
  --log-dir C:\SounRunner\logs
```

Use an elevated terminal only when the authorized assessment explicitly requires reading admin-only local configuration. Do not use this tool as a background agent or persistence mechanism.

For company-wide runs over AnyDesk:

1. Confirm written authorization covers every approved subnet and remote admin path.
2. Run `-Preflight` first.
3. Verify scope was auto-detected or explicitly approved in `config.yaml`.
4. Check the reported remote collection strategy. If it is `current_user_integrated_auth`, confirm the current domain user has approved read access. If it is `discovery_only_fallback`, configure an approved credential reference or accept discovery-only coverage.
5. Launch Standard or Advanced.
6. Treat `discovery_only` and `unreachable` hosts as coverage gaps, not completed assessments.

## Output Paths

Each run writes session data under:

```text
C:\SounRunner\data\sessions\<session_id>\
```

Primary artifacts:

- `C:\SounRunner\logs\sessions\<session_id>\runner.log`
- `C:\SounRunner\data\sessions\<session_id>\runner.sqlite3`
- `C:\SounRunner\data\sessions\<session_id>\reports\assessment_report.pdf`
- `C:\SounRunner\data\sessions\<session_id>\reports\action_plan.csv`
- `C:\SounRunner\data\sessions\<session_id>\reports\findings.json`
- `C:\SounRunner\data\sessions\<session_id>\export\results_bundle.zip`
- `C:\SounRunner\data\sessions\<session_id>\export\callback_status.json.enc`
- `C:\SounRunner\data\sessions\<session_id>\export\bundle_hash.json.enc`
- `C:\SounRunner\data\sessions\<session_id>\audit\evidence_manifest.json.enc`
- `C:\SounRunner\data\sessions\<session_id>\audit\module_audit.jsonl.enc`
- `C:\SounRunner\data\sessions\<session_id>\audit\preflight.json.enc`
- encrypted evidence under `C:\SounRunner\data\sessions\<session_id>\evidence`
- per-host remote evidence under `C:\SounRunner\data\sessions\<session_id>\evidence\hosts\<asset_id>\`
- encrypted checkpoint at `C:\SounRunner\data\sessions\<session_id>\checkpoint.json.enc`

## Evidence Manifest And Audit Trail

Each session now captures:

- Consent and authorization confirmation in session metadata.
- Operator identity and scope details.
- Module execution audit events.
- Encrypted preflight results.
- Evidence manifest entries with filename, source module, timestamp, size, and SHA-256.
- SHA-256 hash for the final encrypted bundle.

The evidence manifest is included in the encrypted bundle. The bundle hash is stored alongside the bundle for local integrity verification.

## Fully Validated vs Partial

Fully validated in this repo:

- Basic, Standard, and Advanced package execution paths.
- Read-only Windows posture collection and graceful non-Windows degradation.
- DNS/email evidence checks.
- Approved-scope Nmap execution and parsing.
- Multi-CIDR scope parsing, inventory storage, estate aggregation, and organization coverage reporting.
- Automatic remote Windows strategy selection with configured credentials, current-user integrated auth, or honest discovery-only fallback.
- Scanner file imports.
- Callback queueing, retry, and manual resend flow.
- Audit trail, evidence manifest, encrypted bundle generation, and report generation.
- External config/data/log path handling.

Still partial or environment-dependent:

- M365 / Entra Graph evidence depends on tenant permissions, licensing, and app registration.
- Nessus API foundation depends on valid X-ApiKeys and completed export availability.
- Greenbone API foundation depends on optional `python-gvm`, reachable GMP access, and environment-specific TLS/SSH setup.
- Windows PowerShell collector behavior must still be validated on the actual client host and privilege context.
- Remote Windows collection depends on WinRM reachability, domain/current-user authorization or approved credentials, host policy, and local firewall state in the client environment.
- Company-wide field validation still depends on real client subnets and remote admin realities. Discovery-only coverage is expected when remote collection is blocked.

## Local Development

Use Python 3.11 or newer.

```powershell
cd soun-runner
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Interactive Basic assessment:

```powershell
python main.py --config config.example.yaml
```

Smoke test with external runtime paths:

```powershell
python main.py --sample --data-dir .\.local-data --log-dir .\.local-logs
```

Manual Windows EXE build:

```powershell
pip install pyinstaller
.\scripts\build_windows.ps1
```

Version check:

```powershell
.\dist\SounAlHosnAssessmentRunner.exe --version
```

## Optional Encryption Key

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
$env:SOUN_RUNNER_WORKSPACE_KEY = "<generated-key>"
```

If no key is supplied, the runner creates a local key file inside the session workspace. That protects evidence from casual disclosure, not from a local administrator or a compromised host.

## Tests

```powershell
pytest
```

## Keep/Kill Threshold

Keep this MVP if it reliably creates sessions, profiles Windows hosts, records skipped/partial checks honestly, generates reports, updates from GitHub without manual file copying, and never modifies target systems.

Kill the run immediately if authorization is unclear, scope is missing, the operator asks for stealth/evasion/exploitation/credential theft/persistence, or required evidence cannot be collected without unsafe behavior.
