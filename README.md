# SecDev-vercode — automated security scanning POC

Learning proof-of-concept: how to wire **Veracode** and open-source security scanners into a CI/CD
pipeline, using a small, deliberately vulnerable ASP.NET Core app as the target.

> **WARNING — intentionally vulnerable code.** `src/VulnApp` contains SQL injection, command injection,
> XSS, insecure deserialization and more, on purpose. Run it only on `127.0.0.1` or inside a CI runner.
> Never deploy it, expose it to a network, or copy its code into a real project.
> The "secrets" in the repo are random values, not real credentials.

## What is here

| Path | Purpose |
|---|---|
| `src/VulnApp/` | .NET 10 minimal API + Razor page with 10 planted flaws, each tagged `POC-VULN: CWE-xxx` |
| `Dockerfile`, `infra/terraform/` | Intentionally misconfigured infrastructure for IaC scanners (Terraform is never applied) |
| `.github/workflows/sast.yml` | CodeQL, Semgrep, Roslyn analyzers |
| `.github/workflows/sca.yml` | `dotnet list package --vulnerable`, Trivy (repo + container image) |
| `.github/workflows/secrets-iac.yml` | Gitleaks, Checkov, Trivy config |
| `.github/workflows/dast.yml` | OWASP ZAP baseline + active API scan against the running container |
| `.github/workflows/veracode.yml` | Veracode Pipeline Scan, Policy Scan, SCA — **off** until `VERACODE_ENABLED=true` |
| `scripts/run-local-scans.ps1` | Run the same scanners locally with Docker |
| `docs/` | Learning guides, Veracode onboarding, findings matrix |

## Quick start

```powershell
# run the app (http://127.0.0.1:5099)
dotnet run --project src/VulnApp --urls http://127.0.0.1:5099

# run scanners locally (needs Docker Desktop running)
./scripts/run-local-scans.ps1                # SAST, SCA, secrets, IaC
./scripts/run-local-scans.ps1 -IncludeDast   # + ZAP against the container
```

Results land in `scan-results/` (git-ignored). Open `.sarif` files with the VS Code *SARIF Viewer* extension.

In GitHub: push, then see *Actions* for runs and *Security → Code scanning* for SARIF results
(code scanning needs a public repo, or GitHub Advanced Security on a private one).

## Enabling Veracode

See [docs/05-veracode-guide.md](docs/05-veracode-guide.md). Short version: add secrets
`VERACODE_API_ID`, `VERACODE_API_KEY`, `SRCCLR_API_TOKEN` and variable `VERACODE_ENABLED=true`.

## Learning path

1. [Overview](docs/00-overview.md) — SAST vs SCA vs DAST vs secrets/IaC
2. [SAST](docs/01-sast.md) · [SCA](docs/02-sca.md) · [Secrets + IaC](docs/03-secrets-iac.md) · [DAST](docs/04-dast.md)
3. [Veracode guide](docs/05-veracode-guide.md)
4. [Findings matrix](docs/findings-matrix.md) — which tool caught which planted flaw
