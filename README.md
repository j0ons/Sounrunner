# Soun Al Hosn Assessment Runner

Windows-first, locally executed, operator-controlled cybersecurity assessment runner for authorized client environments.

The MVP is read-only. It does not include stealth, AV/firewall evasion, bypass behavior, persistence, credential dumping, exploit execution, lateral movement, auto-remediation, or unauthorized network expansion.

## Current MVP

Implemented:

- Rich terminal launcher with version reporting.
- Startup preflight and healthcheck validation.
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
- Authorized scope is mandatory.
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

3. Run the authorized package with approved scope and operator-confirmed consent.

```powershell
C:\SounRunner\run_assessment.ps1
```

For company-wide Standard or Advanced runs, define the approved CIDRs, optional allowlist/denylist, and remote collection settings in config before launch.

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

What remains future/integration work:

- Broader Nessus scan/task management beyond export retrieval.
- Broader Greenbone/GMP operational support beyond report retrieval.
- Deeper M365 / Entra control coverage beyond the current read-only posture evidence set.
- Authenticated vulnerability scanner orchestration.

The runner does not invent CVEs. Nmap findings are exposure findings only. A discovered open service is not reported as a vulnerability unless direct evidence supports that conclusion.

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

1. Nmap discovery runs only inside approved CIDRs.
2. The runner creates or updates a central asset inventory.
3. Discovery-only assets are recorded even if no remote collection is possible.
4. Remote Windows collection attempts authorized read-only evidence gathering per eligible host.
5. Host findings and repeated control gaps are aggregated into organization-level summaries.

Discovery-only vs fully assessed:

- `discovery_only`: host was found in approved scope, but no remote evidence was collected.
- `partial`: some remote evidence was collected or access was limited.
- `assessed`: remote host evidence was collected successfully.
- `unreachable`: the host was discovered, but remote collection could not connect.

This matters because a discovered RDP or SMB service is not the same thing as a completed host posture assessment. The reports now separate those cases.

Advisory and partial items are not confirmed technical vulnerabilities. Reports separate them from direct system and network discovery findings.

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

During intake, enter the exact authorized scope string or enter `config` to use `approved_scopes` from the config file. The tool rejects empty or invalid scope and does not scan outside approved CIDR ranges.

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
- Multi-host discovery across one or more approved CIDRs.
- Central asset inventory with discovery-only, partial, assessed, and unreachable host states.
- Remote Windows posture collection across eligible discovered hosts using authorized WinRM/PowerShell remoting.
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
C:\SounRunner\run_assessment.ps1
```

At the package prompt, enter:

```text
standard
```

Or launch the EXE directly:

```powershell
C:\SounRunner\app\SounAlHosnAssessmentRunner.exe `
  --config C:\SounRunner\config\config.yaml `
  --data-dir C:\SounRunner\data `
  --log-dir C:\SounRunner\logs
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
C:\SounRunner\run_assessment.ps1
```

At the package prompt, enter:

```text
advanced
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
- backup platform imported evidence normalization
- secret masking and preflight secret validation
- remoting failure categorization

Still partial or environment-dependent:

- live WinRM collection across real client endpoints
- live AD connectivity in each customer environment
- live M365 Graph permissions and licensing behavior
- live Nessus and Greenbone API connectivity
- vendor-specific firewall/VPN or backup export formats beyond the documented neutral schemas

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
3. Verify `config.yaml` contains approved CIDRs, labels, and remote Windows settings.
4. Launch Standard or Advanced.
5. Treat `discovery_only` and `unreachable` hosts as coverage gaps, not completed assessments.

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
- Scanner file imports.
- Callback queueing, retry, and manual resend flow.
- Audit trail, evidence manifest, encrypted bundle generation, and report generation.
- External config/data/log path handling.

Still partial or environment-dependent:

- M365 / Entra Graph evidence depends on tenant permissions, licensing, and app registration.
- Nessus API foundation depends on valid X-ApiKeys and completed export availability.
- Greenbone API foundation depends on optional `python-gvm`, reachable GMP access, and environment-specific TLS/SSH setup.
- Windows PowerShell collector behavior must still be validated on the actual client host and privilege context.
- Remote Windows collection depends on WinRM reachability, operator credentials, host policy, and local firewall state in the client environment.
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
