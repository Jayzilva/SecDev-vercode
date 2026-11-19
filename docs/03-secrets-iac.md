# 03 — Secrets and IaC scanning

Workflow: [`.github/workflows/secrets-iac.yml`](../.github/workflows/secrets-iac.yml)

## Secrets: Gitleaks

- Regex + entropy rules for ~200 credential formats (cloud keys, tokens, private keys) plus a generic
  high-entropy rule.
- `gitleaks git` scans **every commit in history**. Deleting a secret in a later commit does not remove it:
  anyone who clones the repo has it. The only fix for a leaked secret is **rotate it**, then optionally
  rewrite history (`git filter-repo`).
- `gitleaks dir` scans the working tree (uncommitted files).
- [`.gitleaks.toml`](../.gitleaks.toml) extends the default rules with a connection-string password rule
  and shows an allowlist.
- Best place to run it: a **pre-commit hook**, so the secret never reaches git:
  ```yaml
  # .pre-commit-config.yaml
  repos:
    - repo: https://github.com/gitleaks/gitleaks
      rev: v8.30.1
      hooks: [{ id: gitleaks }]
  ```
- GitHub also has native secret scanning + push protection (free on public repos) for provider-issued
  token formats.

Planted: `src/VulnApp/Security/Secrets.cs` (random hex "API key", connection string with password) and
`infra/terraform/main.tf` (DB password). Values are random, not real credentials.

**Fix:** read secrets from configuration at runtime — `dotnet user-secrets` locally, environment variables
or Azure Key Vault / AWS Secrets Manager in deployed environments. Never in source.

## IaC: Checkov and Trivy config

Both parse infrastructure files and apply policy rules. Overlapping but not identical rule sets.

### Dockerfile findings and fixes

| Finding | Rule (Checkov / Trivy) | Fix |
|---|---|---|
| Runs as root | CKV_DOCKER_3 / DS-0002 | `USER $APP_UID` (the .NET images ship a non-root `app` user) |
| No HEALTHCHECK | CKV_DOCKER_2 / DS-0026 | `HEALTHCHECK CMD curl -f http://localhost:8080/ \|\| exit 1` |
| `ADD` instead of `COPY` | CKV_DOCKER_4 / DS-0005 | `COPY` (ADD can fetch URLs and auto-extract archives) |
| Floating tag | — | pin `FROM image:tag@sha256:...` |

### Terraform findings and fixes

| Finding | Fix |
|---|---|
| S3 bucket `public-read`, public-access block disabled | private ACL, all four public-access-block flags `true` |
| No bucket encryption / versioning / logging | `aws_s3_bucket_server_side_encryption_configuration`, versioning, access logs |
| SG allows 0.0.0.0/0 on port 22 | restrict to VPN/bastion CIDR, or use SSM Session Manager (no SSH) |
| RDS `publicly_accessible = true`, `storage_encrypted = false` | private subnet, encryption on |
| Hard-coded DB password | `manage_master_user_password = true` (Secrets Manager) |

The Terraform is **never applied**. There is no backend, no credentials, no `apply` step anywhere.

## Suppressions

- Checkov: `#checkov:skip=CKV_AWS_20:reason` inside the resource block.
- Trivy: `#trivy:ignore:AVD-AWS-0086` above the resource, or a `.trivyignore` file.
- Gitleaks: add the finding's fingerprint to `.gitleaksignore`.
