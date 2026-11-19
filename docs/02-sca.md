# 02 — SCA: vulnerable dependencies

Workflow: [`.github/workflows/sca.yml`](../.github/workflows/sca.yml)

Most code in a modern app is someone else's. SCA matches each package + version against advisory
databases (GitHub Advisory DB, NVD, OSV, vendor feeds).

## Tools

### `dotnet list package --vulnerable --include-transitive`
- Built into the SDK, uses the NuGet/GitHub advisory feed.
- `--include-transitive` matters: most vulnerable packages arrive indirectly.
- NuGet Audit also runs on every `restore` (warnings `NU1901`–`NU1904` by severity). The csproj sets
  `NuGetAuditMode=all` so transitive packages are audited too.

### Trivy
- `trivy fs` reads `packages.lock.json` (or `bin/**/*.deps.json` after a build). Learning point from
  this POC: before the lock file existed, Trivy found **only** Newtonsoft.Json, and only because a
  local `bin/` folder happened to exist — in a clean CI checkout it would have found nothing. The csproj
  now sets `RestorePackagesWithLockFile=true`, the lock file is committed, and Trivy finds both
  planted packages. Lock files also make restores reproducible (`dotnet restore --locked-mode` fails if
  someone changes a dependency without updating the lock) — a supply-chain control on its own.
- `trivy image` scans the built container: OS packages (Debian/Ubuntu libs in the base image)
  **and** the .NET assemblies inside. Base-image CVEs are often the largest count — fix by updating
  the base image, not your code.

## Planted dependencies

| Package | Version | Advisory | Fix |
|---|---|---|---|
| Newtonsoft.Json | 12.0.1 | GHSA-5crp-9r3c-p9vr / CVE-2024-21907 (DoS via deep nesting) | ≥ 13.0.1 |
| System.Text.RegularExpressions | 4.3.0 | GHSA-cmhx-cq75-c4mj / CVE-2019-0820 (ReDoS) | remove: it is part of the .NET runtime (the SDK even warns `NU1510`) |

Learning point found while building the POC: picking `Microsoft.AspNetCore.OpenApi` and
`Microsoft.Data.Sqlite` **10.0.0** pulled in vulnerable transitive packages (`Microsoft.OpenApi 2.0.0`,
`SQLitePCLRaw.lib.e_sqlite3 2.1.11`). Patch releases (10.0.15) fixed both. Staying on the latest
patch of each package is the cheapest SCA control there is.

## Reachability

A CVE in a package does not mean your app is exploitable — only if you call the vulnerable function.
Veracode SCA and some commercial tools do *vulnerable-method reachability*; the free tools here do not.
Prioritise: reachable + network-exposed + High/Critical first.

## Keeping it fixed

- **Dependabot**: add `.github/dependabot.yml` with `package-ecosystem: nuget` to get upgrade PRs.
- **Scheduled scan**: `sca.yml` runs weekly because new CVEs are published against code you did not change.
- **Gate**: commented-out `jq` step in `sca.yml` fails on High/Critical.
