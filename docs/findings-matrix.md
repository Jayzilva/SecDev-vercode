# Findings matrix

Which tool caught which planted flaw. **Local** column = verified with `scripts/run-local-scans.ps1`
on 2026-11-19. Columns marked *CI* are filled after the first GitHub Actions run; *Veracode* after
credentials are added.

Legend: ✅ found · ❌ missed · ⏳ not yet run · — not applicable to this tool type

## Application code (SAST / secrets)

| # | Planted flaw | CWE | Location | Roslyn | Semgrep | CodeQL *(CI)* | Gitleaks | ZAP *(CI)* | Veracode |
|---|---|---|---|---|---|---|---|---|---|
| 1 | SQL injection | 89 | `VulnEndpoints.cs` SearchUsers | ✅ CA2100 | ✅ csharp-sqli | ⏳ | — | ⏳ | ⏳ |
| 2 | Reflected XSS (`Html.Raw`) | 79 | `Pages/Search.cshtml` | ❌ | ❌ (no `.cshtml` parser) | ⏳ | — | ⏳ | ⏳ |
| 3 | OS command injection | 78 | `VulnEndpoints.cs` Ping | ❌ | ❌ | ⏳ | — | ⏳ | ⏳ |
| 4 | Path traversal | 22 | `VulnEndpoints.cs` ReadFile | ❌ | ❌ | ⏳ | — | ⏳ | ⏳ |
| 5 | Insecure deserialization | 502 | `VulnEndpoints.cs` ImportObject | ✅ CA2326, CA2327 | ❌ | ⏳ | — | — | ⏳ |
| 6 | MD5 password hash | 327 | `VulnEndpoints.cs` Register | ✅ CA5351 | ❌ | ⏳ | — | — | ⏳ |
| 7 | SSRF | 918 | `VulnEndpoints.cs` Fetch | ❌ | ❌ | ⏳ | — | ⏳ | ⏳ |
| 8 | Open redirect | 601 | `VulnEndpoints.cs` Login | ❌ | ❌ | ⏳ | — | ⏳ | ⏳ |
| 9a | Hard-coded API key | 798 | `Security/Secrets.cs:8` | ❌ | ❌ | ⏳ | ✅ generic-api-key | — | ⏳ |
| 9b | Connection string password | 798 | `Security/Secrets.cs:11` | ❌ | ❌ | ⏳ | ✅ custom rule | — | ⏳ |
| 10 | Missing security headers | 693 | `Program.cs` | — | — | — | — | ⏳ | — |

## Dependencies (SCA)

| Package | Advisory | `dotnet list --vulnerable` | Trivy fs | Trivy image *(CI)* | Veracode SCA |
|---|---|---|---|---|---|
| Newtonsoft.Json 12.0.1 | CVE-2024-21907 | ✅ High | ✅ High | ⏳ | ⏳ |
| System.Text.RegularExpressions 4.3.0 | CVE-2019-0820 | ✅ High | ✅ (after lock file added) | ⏳ | ⏳ |

## Infrastructure (IaC)

| Planted flaw | Checkov | Trivy config | Semgrep |
|---|---|---|---|
| Dockerfile runs as root | ✅ CKV_DOCKER_3 | ✅ DS-0002 (High) | ✅ missing-user-entrypoint |
| No HEALTHCHECK | ✅ CKV_DOCKER_2 | ✅ DS-0026 | ❌ |
| `ADD` instead of `COPY` | ✅ CKV_DOCKER_4 | ✅ DS-0005 | ❌ |
| S3 public ACL / public-access block off | ✅ CKV_AWS_20, 53–56 | ✅ AWS-0086/87/91/92/93 | ❌ |
| S3 no encryption / versioning / logging | ✅ CKV_AWS_18, 21, 145 | ✅ AWS-0089, 0090, 0132 | ❌ |
| SG 0.0.0.0/0 on port 22 | ✅ CKV_AWS_24, 382 | ✅ AWS-0107 (High), AWS-0104 egress (Critical) | ❌ |
| RDS public + unencrypted | ✅ CKV_AWS_16, 17 | ✅ AWS-0080, AWS-0180 | ✅ no-logging only |
| RDS hard-coded password | ❌ | ❌ | ✅ rds-insecure-password |

Totals: Checkov 30 failed checks (27 Terraform, 3 Dockerfile); Trivy config 20 unique rules (17 Terraform, 3 Dockerfile; 19 Terraform findings counting duplicates).

## What this teaches

1. **No single tool is enough.** Roslyn found 3 of 8 code flaws, Semgrep community rules found 1.
   Each found something the other missed. That gap is exactly what CodeQL and Veracode are evaluated on.
2. **Pattern rules ≠ taint analysis.** Roslyn's CA3xxx taint rules did not treat minimal-API parameters
   as user input, so they were silent on SQLi/command injection/path traversal. Taint-tracking engines
   (CodeQL, Veracode) are needed for injection-class flaws.
3. **File types matter.** Semgrep cannot parse Razor `.cshtml`, so the XSS is invisible to it.
   Veracode scans the compiled DLL, where Razor views are already C#, so it can see it.
4. **SCA depends on what the tool can read.** Trivy saw nothing reliable until a lock file existed.
5. **Gitleaks scans history.** `gitleaks git` reported 0 locally because the secrets were not committed
   yet; `gitleaks dir` caught both. After the first commit, the secrets live in history forever.
6. **Overlap is healthy for IaC.** Checkov and Trivy agree on most findings; pick one for gating,
   keep the other as a cross-check if you like.

## Fill in after the first CI run

- CodeQL column: Security tab → filter `tool:CodeQL`.
- ZAP column: `zap-reports` artifact → `api.json` / `baseline.json`. (Local DAST run was not completed;
  it was stopped while building the container image because the machine ran low on memory.)
- Trivy image: Security tab → category `trivy-image`.
