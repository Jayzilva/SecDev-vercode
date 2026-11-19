# 05 — Veracode onboarding guide

Workflow: [`.github/workflows/veracode.yml`](../.github/workflows/veracode.yml) — skipped until enabled.

## 1. What Veracode adds over the free tools

| | Free tools in this POC | Veracode |
|---|---|---|
| SAST engine | Source-level (CodeQL, Semgrep) | **Binary** analysis of compiled assemblies — also covers code you have no source for |
| Policy | Your own YAML / gates | Central org policy (e.g. "no Very High, fix High in 30 days"), compliance reports |
| Tracking | Per-repo Security tab | Application profiles, history, mitigation approvals, audit trail |
| SCA | CVE match | CVE match + vulnerable-method reachability, licence policy |
| Triage | Manual | Mitigation workflow (propose → approve), Veracode Fix (AI-generated patches) |
| Cost | Free | Commercial licence |

## 2. Get access

1. Request a Veracode trial or licence (veracode.com). Ask for **Static Analysis + SCA** for the POC.
2. Log in to the Veracode Platform (region: US `analysiscenter.veracode.com`, EU `analysiscenter.veracode.eu`).
3. Create **API credentials**: user menu → *API Credentials* → *Generate*. You get an ID and a secret key.
   Best practice: use a dedicated **API service account** with only the *Upload and Scan API* /
   *Results API* roles, not a personal login.
4. SCA: *Software Composition Analysis* → workspace → *Agents* → *Actions* → *Create* → choose
   **GitHub Actions** → copy the `SRCCLR_API_TOKEN`.

## 3. Wire it into GitHub

Repo → *Settings* → *Secrets and variables* → *Actions*:

| Type | Name | Value |
|---|---|---|
| Secret | `VERACODE_API_ID` | API ID |
| Secret | `VERACODE_API_KEY` | API key |
| Secret | `SRCCLR_API_TOKEN` | SCA agent token |
| Variable | `VERACODE_ENABLED` | `true` |

Push or run the workflow manually (*Actions* → *Veracode* → *Run workflow*).

## 4. Packaging .NET for Veracode

Veracode static analysis scans **compiled** assemblies, not `.cs` files. Requirements:

- Compile in **Debug** (unoptimised) so findings map to line numbers.
- Include **PDB** files next to each DLL (`<DebugType>portable</DebugType>`, the default).
- Upload the publish output as a **zip**. Exclude test projects and third-party DLLs you do not own
  (they cost scan time and are covered by SCA).
- .NET Core / .NET 5+: framework-dependent `dotnet publish -c Debug -o publish` output.

```bash
dotnet publish src/VulnApp/VulnApp.csproj -c Debug -o publish
cd publish && zip -r ../vulnapp-veracode.zip .
```

Alternative: the Veracode CLI auto-packager does this for you:
```bash
veracode package --source . --output veracode-artifacts --trust
```

Razor views (`.cshtml`) are compiled into the DLL in .NET 6+, so XSS in views is scanned too.

## 5. Three scan types in the workflow

| Job | When | Speed | Results go to | Use for |
|---|---|---|---|---|
| **Pipeline Scan** | Every PR + push | ~1–10 min | Build log, `filtered_results.json`, SARIF → Security tab | Fast developer feedback, PR gate |
| **Policy Scan** (Upload & Scan) | main only | 10 min – hours | Veracode Platform app profile | Official record, policy compliance, reports |
| **SCA agent** | Every PR + push | ~1 min | Veracode SCA workspace (+ GitHub issues if enabled) | Vulnerable/licence-risky packages |

`scantimeout: 0` on the policy scan means "submit and do not wait": main builds stay fast, results
appear in the Platform. Set e.g. `scantimeout: 30` + `failbuild: true` to block a release on policy failure.

A **sandbox** (`createsandbox: true`, `sandboxname: feature-x`) runs a policy-style scan without
affecting the app's official compliance status — useful for long-lived feature branches.

## 6. Baselines: adopting Veracode on existing code

On a legacy codebase the first scan returns hundreds of flaws. Failing every PR on that day is
not workable. Instead:

1. Run Pipeline Scan once on main and save the results as a baseline:
   `store_baseline_file: true`, `store_baseline_file_branch: main`, `create_baseline_from: standard`.
2. In PR builds set `baseline_file: <name>.json` + `fail_on_severity: "Very High, High"`.
3. PRs now fail only on **new** High+ flaws. Old ones are worked down from the Platform backlog.

## 7. Triage and mitigation

In the Platform, each flaw can be marked:
- **Mitigate by Design / Network Environment / OS Environment** — the flaw is real but not exploitable here (explain why).
- **Potential False Positive** — the tool is wrong.
- **Accept the Risk** — business decision.

A proposal must be **approved** by a security reviewer before it stops counting against policy. This
two-person rule is the main governance difference from suppressing a finding in code.

## 8. Expected Veracode results for VulnApp

Mapped to Veracode's CWE categories (verify after your first scan and record in `findings-matrix.md`):

| Planted flaw | CWE | Veracode category |
|---|---|---|
| SQL injection | 89 | SQL Injection |
| Reflected XSS | 79 | Cross-Site Scripting (XSS) |
| Command injection | 78 | OS Command Injection |
| Path traversal | 73 / 22 | Directory Traversal / External Control of File Name |
| Deserialization | 502 | Deserialization of Untrusted Data |
| MD5 | 327 | Cryptographic Issues |
| SSRF | 918 | Server-Side Request Forgery |
| Open redirect | 601 | Open Redirect |
| Hard-coded secret | 798 | Credentials Management |
| Newtonsoft.Json 12.0.1 | CVE-2024-21907 | SCA finding |

## 9. POC evaluation checklist

- [ ] Time from push to Pipeline Scan result
- [ ] Planted flaws found vs. CodeQL / Semgrep (fill `findings-matrix.md`)
- [ ] False positives count
- [ ] Quality of remediation guidance / Veracode Fix suggestions
- [ ] SARIF in GitHub Security tab works (developer stays in GitHub)
- [ ] Policy + mitigation workflow fits your security team's process
- [ ] Licence cost vs. free-tool coverage gap
