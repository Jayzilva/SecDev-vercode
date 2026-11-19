# 01 — SAST: static analysis

Workflow: [`.github/workflows/sast.yml`](../.github/workflows/sast.yml)

## Engines

### CodeQL
- Builds a database of the code (AST + data flow), then runs queries written in QL.
- `build-mode: manual` + `dotnet build` so CodeQL observes the real compilation.
  (`build-mode: none` also works for C# and is faster, at some precision cost.)
- `queries: security-extended` adds lower-precision security queries on top of the default suite.
- Strongest taint tracking of the free tools; slowest (minutes).

### Semgrep
- Pattern matching with some intra-file data flow. Rules are YAML, readable, easy to write your own.
- Rulesets used: `p/csharp`, `p/owasp-top-ten`, `p/secrets` (community registry, no account needed).
- Seconds to run, good for PRs and pre-commit.
- Learning point from this POC: the free community C# rules found only the SQL injection (plus some
  Dockerfile/Terraform issues). Semgrep's cross-file taint engine is in the paid tier. Free Semgrep is
  best as a fast, custom-rule layer, not your only SAST.
- Custom rule example — flag any `Html.Raw` in Razor:
  ```yaml
  rules:
    - id: razor-html-raw
      languages: [generic]
      paths: { include: ["*.cshtml"] }
      pattern: "@Html.Raw(...)"
      message: Html.Raw disables encoding; use @value instead
      severity: ERROR
  ```
  Run: `semgrep scan --config my-rules.yml`.

### Roslyn analyzers (built into the .NET SDK)
- Zero install; run on every `dotnet build` and in the IDE as you type.
- Security rules are mostly **off by default**. [`.editorconfig`](../.editorconfig) turns them on.
- `-p:ErrorLog=roslyn.sarif%2Cversion=2.1` writes SARIF (`%2C` is an escaped comma).
- Learning point seen in this POC: `CA2100` (SQL), `CA2326/CA2327` (TypeNameHandling) and
  `CA5351` (MD5) fire, but the CA3xxx **taint** rules do not recognise minimal-API parameters as
  user input, so SQLi/command-injection/path-traversal via taint go undetected. Pattern-based rules are
  not the same as data-flow rules.

## Reading a finding

Every SAST finding has: rule ID, CWE, severity, **source** (where input enters), **sink** (where it is
used), and often the **path** between. Example CodeQL path for `/api/users`:

```
string name (parameter)  →  "SELECT ... '" + name + "'"  →  cmd.CommandText  (sink: SQL)
```

Triage questions: Is the source really user-controlled? Is there a sanitizer the tool missed?
Is the sink reachable in production?

## Fixing the planted SAST flaws

| Flaw | Fix |
|---|---|
| SQLi | `cmd.CommandText = "... WHERE name = $name"; cmd.Parameters.AddWithValue("$name", name);` |
| XSS | `@Model.Query` (Razor encodes by default) instead of `@Html.Raw(...)` |
| Command injection | Never pass input to a shell. Validate `host` with `IPAddress.TryParse`, use `System.Net.NetworkInformation.Ping` |
| Path traversal | `Path.GetFileName(name)`, then check `Path.GetFullPath(p).StartsWith(root)` |
| Deserialization | `TypeNameHandling.None` (default), or a `SerializationBinder` allow-list |
| MD5 passwords | `Rfc2898DeriveBytes.Pbkdf2` (≥600k iterations SHA-256) or ASP.NET Core Identity `PasswordHasher` |
| SSRF | Allow-list hosts, block private/link-local ranges after DNS resolution |
| Open redirect | `Results.LocalRedirect(returnUrl)` or `Url.IsLocalUrl` check |

## Suppressing a false positive

- CodeQL: dismiss in Security tab with reason (tracked), or `// codeql[cs/sql-injection]` is **not**
  supported — use a query filter in a `codeql-config.yml`.
- Semgrep: `// nosemgrep: rule-id` on the line.
- Roslyn: `#pragma warning disable CA2100 // justified because ...` or `[SuppressMessage]`.
- Always record **why**. Unjustified suppressions are a review finding themselves.

## Turning on the gate

CodeQL/Semgrep results in the Security tab can block merges via a branch-protection rule
("Require code scanning results"). Semgrep: add `--error` to fail on findings. Roslyn: set
`<WarningsAsErrors>CA2100;CA5351;...</WarningsAsErrors>` in the csproj.
