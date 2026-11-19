# 04 — DAST: dynamic scanning with OWASP ZAP

Workflow: [`.github/workflows/dast.yml`](../.github/workflows/dast.yml)

DAST knows nothing about your code. It sends HTTP requests to a running app and judges the responses —
the same view an attacker has. It confirms *exploitability* and finds runtime/config issues SAST cannot see.

## How the workflow works

1. Build the Docker image and start it on `127.0.0.1:8080` inside the GitHub runner (never public).
2. **Baseline scan** (`zap-baseline.py`): spiders the site, then **passive** checks only — it looks at
   responses without attacking. Safe against any environment. Finds missing headers (CSP,
   X-Content-Type-Options, anti-clickjacking), cookie flags, information leaks.
3. **API scan** (`zap-api-scan.py`): imports `/openapi/v1.json` so ZAP knows every endpoint and parameter,
   then runs **active** attacks (SQL injection, XSS, path traversal, command injection payloads).
   Only run active scans against environments you own and that hold no real data.
4. HTML + JSON reports uploaded as the `zap-reports` artifact; alert list written to the job summary.

`-I` = do not fail the job on warnings (POC report-only mode).

## Why the OpenAPI spec matters

A spider only finds links it can see in HTML. JSON APIs have no links, so without the spec ZAP never
reaches `/api/users`. `Program.cs` calls `AddOpenApi()` / `MapOpenApi()` to publish the spec. For a real
app, publish it only in test environments.

## Tuning

- Generate a rules file: `zap-baseline.py -t URL -g gen.conf`, then edit `IGNORE`/`WARN`/`FAIL` per rule
  ID and pass `-c gen.conf`. This is how you gate ("fail on rule 40018 SQL Injection").
- Authenticated scans: ZAP needs a login script or a token header (`-z "-config replacer..."`), otherwise
  it only tests anonymous pages.
- Full scan (`zap-full-scan.py`) = spider + active scan on everything; slow, run nightly.

## Fixing the header findings

```csharp
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["Content-Security-Policy"] = "default-src 'self'";
    ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
    await next();
});
app.UseHsts();             // in production, behind HTTPS
app.UseHttpsRedirection();
```

## Veracode equivalent

Veracode Dynamic Analysis is configured in the Veracode Platform (target URL, login, schedule), not in
the pipeline. It can be triggered from CI via the REST API once a scan is defined.
