# 00 — Overview: automated security scanning

## The four scan families

| Family | Looks at | Finds | Runs when | Tools in this POC | Veracode product |
|---|---|---|---|---|---|
| **SAST** (static) | Your source / compiled code, without running it | Injection, XSS, weak crypto, insecure deserialization, path traversal | Every PR / commit | CodeQL, Semgrep, Roslyn analyzers | Static Analysis (Pipeline Scan, Policy Scan) |
| **SCA** (composition) | Third-party packages and container OS packages | Known CVEs, licence risk | Every PR **and** on a schedule (new CVEs appear without code changes) | `dotnet list package --vulnerable`, Trivy | Veracode SCA (agent-based) |
| **Secrets + IaC** | Git history, Dockerfiles, Terraform | Committed credentials, insecure cloud/container config | Every commit (pre-commit hook ideally) | Gitleaks, Checkov, Trivy config | Container Security / CLI `veracode scan` |
| **DAST** (dynamic) | The running app over HTTP | What is actually exploitable: XSS, SQLi, missing headers, redirects | After deploy to a test environment | OWASP ZAP | Dynamic Analysis |

No single family finds everything. SAST sees code paths DAST never reaches; DAST sees runtime config
(headers, cookies, server banners) that SAST cannot. `findings-matrix.md` shows this with real results.

## Where each scan sits in the pipeline

```
 developer          pull request                    main branch                    test env
 ─────────          ────────────                    ───────────                    ────────
 pre-commit:        SAST  (fast: Semgrep, Pipeline) SAST full (CodeQL, Policy)     DAST (ZAP / Veracode DA)
  gitleaks          SCA   (new deps only)           SCA full + container image
 IDE plugin         Secrets + IaC                   Secrets + IaC
                    → comment / block merge          → report to dashboard          → report
```

Rule of thumb: **fast + focused on the diff in PRs, full + tracked over time on main.**

## Key concepts

- **Source → sink (taint) analysis.** SAST marks user input (query string, body, headers) as *tainted*
  and reports when it reaches a *sink* (SQL command, `Process.Start`, `File.ReadAllText`) without passing
  a *sanitizer* (parameterisation, allow-list, encoding).
- **SARIF.** Standard JSON format for static-analysis results. Every tool here writes SARIF, and GitHub's
  Security tab ingests it, so results from five vendors appear in one place, de-duplicated per commit.
- **CWE vs CVE.** CWE = class of weakness in *your* code (CWE-89 SQL injection). CVE = specific known
  vulnerability in a *published* package version (CVE-2024-21907 in Newtonsoft.Json < 13.0.1).
- **False positive / false negative.** Scanners report things that are not exploitable (FP) and miss
  things that are (FN). Triage is part of the job; see each tool's doc for suppression syntax.
- **Baseline.** Snapshot of accepted existing findings so a gate fails only on *new* issues. Essential
  when adding scanning to a legacy codebase.
- **Gate.** Pipeline rule that fails the build, e.g. "no new High/Very High". This POC runs in *report-only*
  mode; each doc shows how to turn the gate on.

## GitHub specifics

- Code scanning (Security tab, SARIF upload) is free on **public** repos. On **private** repos it needs
  GitHub Advanced Security (GitHub Code Security). Without it, `upload-sarif` fails — the SARIF files are
  also uploaded as workflow artifacts so you can open them in VS Code (SARIF Viewer extension).
- Third-party actions are pinned to **commit SHAs**, not tags. Tags can be moved; an attacker who
  compromises an action repo can repoint `v1` to malicious code (this has happened to popular security
  actions). Scanner images are pinned to exact versions for the same reason.

## Read next

1. [01-sast.md](01-sast.md)
2. [02-sca.md](02-sca.md)
3. [03-secrets-iac.md](03-secrets-iac.md)
4. [04-dast.md](04-dast.md)
5. [05-veracode-guide.md](05-veracode-guide.md)
6. [findings-matrix.md](findings-matrix.md)
