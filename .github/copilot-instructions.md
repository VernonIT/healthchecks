# Copilot Instructions for Cloud Health Checks Suite

## Project Overview
This is a bash and PowerShell health-check suite for validating the availability and correct construction of cloud resources across **Azure, AWS, and GCP**. Health checks must be idempotent, minimal-dependency, and platform-aware.

## Architecture Patterns

### Directory Structure (to establish)
```
.
├── checks/
│   ├── azure/       # Azure-specific health checks
│   ├── aws/         # AWS-specific health checks
│   ├── gcp/         # GCP-specific health checks
│   └── common/      # Cross-cloud utilities (logging, retry, validation)
├── scripts/
│   ├── run-all.sh   # Main bash orchestrator
│   ├── run-all.ps1  # Main PowerShell orchestrator
│   └── setup.sh/.ps1 # Environment and CLI validation
├── tests/           # Unit/integration tests
├── docs/            # Cloud-specific setup and troubleshooting
└── README.md        # Getting started, CLI tools required
```

### Dual-Language Design
- **Bash scripts**: Cross-platform (Linux, macOS, Windows WSL/GitBash)
- **PowerShell scripts**: Windows-native and PowerShell Core (cross-platform)
- Both must share identical logic and exit codes; use separate implementations, not wrapping one language in another.

### Health Check Anatomy
Each cloud-specific check should follow this pattern:
1. **Initialization**: Source common utilities, validate required CLI tools (aws, az, gcloud)
2. **Validation**: Assert resource exists and has expected properties (tags, permissions, config)
3. **Exit Code**: `0` = healthy, non-zero = failure (see common codes below)
4. **Output**: Simple status or JSON (machine-parseable) to stdout; errors to stderr

**Example exit codes** (define in `checks/common/`):
- `0`: Healthy
- `1`: Generic failure
- `2`: Missing CLI tool or credentials
- `3`: Resource not found
- `4`: Resource misconfigured

## Cloud Provider Patterns

### Azure (az CLI)
- Require `az account show` to validate credentials.
- Always include `--subscription` or `export AZURE_SUBSCRIPTION_ID`.
- Use `--query` for efficient property extraction.
- Example checks: Storage account access, Key Vault permissions, App Service health.

### AWS (aws CLI)
- Require `aws sts get-caller-identity` to validate credentials and permissions.
- Use `--region` consistently; respect `AWS_DEFAULT_REGION` and `AWS_PROFILE`.
- Leverage `--query` for JMESPath filtering.
- Example checks: S3 bucket existence/ACLs, EC2 instance state, RDS cluster status.

### GCP (gcloud CLI)
- Require `gcloud auth list` and `gcloud config get-value project`.
- Set project context: `gcloud config set project <PROJECT_ID>`.
- Use `--format=json` for structured output.
- Example checks: Compute instance status, Cloud SQL connectivity, Firestore permissions.

## Development Conventions

### Naming
- Check scripts: `<provider>-<resource>-check.sh` / `.ps1` (e.g., `aws-s3-check.sh`)
- Utilities: `<function>.sh` in `checks/common/`
- Test files: `test-<check-name>.sh` / `.ps1` in `tests/`

### Common Utilities (checks/common/)
- **logging.sh/.ps1**: Log levels (INFO, WARN, ERROR), consistent formatting
- **retry.sh/.ps1**: Retry logic with exponential backoff (AWS/GCP transient failures)
- **validate.sh/.ps1**: Schema/format validation (JSON, resource tags)
- **credentials.sh/.ps1**: Unified CLI tool detection and initialization

### Error Handling
- Always validate CLI availability before invoking commands.
- Gracefully handle credential errors (missing profiles, expired tokens).
- Return specific exit codes; avoid mixing stderr output with exit logic.
- Test offline scenarios: network failures, permission denied, resource not found.

### Testing
- Unit tests: Verify individual check logic in isolation (mock API responses).
- Integration tests: Full flow against test resources (non-production accounts).
- Use CI/CD to validate both bash and PowerShell implementations separately.

## Key Files to Understand
- **checks/common/**: Shared utilities are the backbone—understand logging, retry, and validation before writing cloud-specific checks.
- **README.md**: Document required CLI tools (versions), AWS/Azure/GCP account setup, and quick-start examples.
- **scripts/run-all.sh|ps1**: Orchestration—discover and execute all checks, aggregate results, and report.

## Coding Tips
1. **Avoid complex dependencies**: Use only built-in utilities + cloud CLI tools; no npm, pip, or gems.
2. **Portable paths**: Use `${BASH_SOURCE[0]}` (bash) or `$PSScriptRoot` (PowerShell) for relative imports.
3. **Idempotent checks**: Running a health check twice should return the same result without side effects.
4. **Fail fast**: Exit early on missing credentials or CLI tools; don't proceed into checks.
5. **Machine-readable output**: Support JSON output mode (`--json` or similar) for upstream tools to parse.
6. **Documentation**: Comment each check with cloud resource type, prerequisites (CLI, credentials, permissions), and example output.

## Common Gotchas
- **Multi-region/multi-subscription**: Always make region/subscription explicit; don't rely on defaults.
- **CLI version skew**: Document minimum CLI versions; consider version checks in setup scripts.
- **Transient failures**: Distinguish between permanent errors (misconfiguration) and transient ones (network, throttling)—use retry logic judiciously.
- **Credentials**: Never log credentials; sanitize error messages that might leak tokens or account IDs.
