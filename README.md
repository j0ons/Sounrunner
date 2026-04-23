# Soun Al Hosn Assessment Runner

Windows-first, locally executed, operator-controlled cybersecurity assessment runner for authorized client environments.

The MVP is read-only. It does not include stealth, AV/firewall evasion, bypass behavior, persistence, credential dumping, exploit execution, lateral movement, auto-remediation, or unauthorized network expansion.

## Current MVP

Implemented:

- Rich terminal launcher with version reporting.
- Session creation with consent and scope enforcement.
- External runtime paths using `--config`, `--data-dir`, and `--log-dir`.
- Encrypted local workspace primitives for evidence, checkpoints, and sensitive session blobs.
- SQLite local structured storage for module status and normalized findings.
- Windows-aware environment profiling with clean non-Windows degradation.
- Basic package orchestration.
- Identity, endpoint, network exposure lite, and SPF/DKIM/DMARC modules.
- Normalized findings schema and explicit risk scoring.
- PDF report, CSV action plan, JSON findings archive, and AES-encrypted ZIP result bundle.
- Optional sanitized SMTP summary.
- GitHub Actions Windows EXE build and ZIP packaging.
- Remote install/update PowerShell workflow with rollback.
- Unit tests for core modules.

Not implemented:

- Standard and Advanced package execution. They are blocked in the launcher in this phase.
- Real M365/Entra authentication. The MVP only records connector availability.
- Auto-remediation. This is deliberately out of scope.

## Security Boundaries

The tool fails closed:

- Written authorization confirmation is mandatory.
- Authorized scope is mandatory.
- Basic package does not perform subnet scanning.
- All collection is read-only.
- PowerShell is used only for native Windows read-only collection and deployment launch/install.
- The runner does not suppress, evade, tamper with, or bypass defensive controls.
- Unsupported checks are marked skipped or partial rather than forced.

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
- Extracts and stages the new app under `C:\SounRunner\tmp`.
- Runs `SounAlHosnAssessmentRunner.exe --version` as a validation gate.
- Moves the existing app to `C:\SounRunner\rollback\app-<timestamp>`.
- Installs the staged app to `C:\SounRunner\app`.
- Restores the previous app automatically if validation or install fails.
- Leaves `config`, `data`, and `logs` untouched.

## Running Remotely Via AnyDesk

Launch the installed runner:

```powershell
C:\SounRunner\run_assessment.ps1
```

Smoke test:

```powershell
C:\SounRunner\run_assessment.ps1 -Sample
```

The launcher passes explicit external paths:

```powershell
C:\SounRunner\app\SounAlHosnAssessmentRunner.exe `
  --config C:\SounRunner\config\config.yaml `
  --data-dir C:\SounRunner\data `
  --log-dir C:\SounRunner\logs
```

Use an elevated terminal only when the authorized assessment explicitly requires reading admin-only local configuration. Do not use this tool as a background agent or persistence mechanism.

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
- encrypted evidence under `C:\SounRunner\data\sessions\<session_id>\evidence`
- encrypted checkpoint at `C:\SounRunner\data\sessions\<session_id>\checkpoint.json.enc`

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
