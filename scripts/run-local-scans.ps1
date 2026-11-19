<#
.SYNOPSIS
  Run the same open-source scanners the CI pipelines use, locally via Docker.

.DESCRIPTION
  Results land in ./scan-results (git-ignored). Requires Docker Desktop and the .NET 10 SDK.
  Tool versions match .github/workflows/*.yml so local and CI results are comparable.

.EXAMPLE
  ./scripts/run-local-scans.ps1                 # everything except DAST
  ./scripts/run-local-scans.ps1 -Only sast,sca
  ./scripts/run-local-scans.ps1 -IncludeDast    # also builds the container and runs ZAP
#>
[CmdletBinding()]
param(
    [ValidateSet('sast', 'sca', 'secrets', 'iac')]
    [string[]] $Only = @('sast', 'sca', 'secrets', 'iac'),
    [switch] $IncludeDast
)

$ErrorActionPreference = 'Stop'
$Root = Resolve-Path (Join-Path $PSScriptRoot '..')
$Out  = Join-Path $Root 'scan-results'
New-Item -ItemType Directory -Force $Out | Out-Null

$Images = @{
    Semgrep  = 'semgrep/semgrep:1.186.0'
    Trivy    = 'aquasec/trivy:0.76.2'
    Gitleaks = 'zricethezav/gitleaks:v8.30.1'
    Checkov  = 'bridgecrew/checkov:3.4.5'
    Zap      = 'ghcr.io/zaproxy/zaproxy:2.17.0'
}
$Project = Join-Path $Root 'src/VulnApp/VulnApp.csproj'
$Mount   = "${Root}:/src"

function Write-Step($text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }

docker info --format '{{.ServerVersion}}' *> $null
if ($LASTEXITCODE -ne 0) { throw 'Docker engine is not running. Start Docker Desktop and retry.' }

if ($Only -contains 'sast') {
    Write-Step 'SAST: Roslyn analyzers'
    # --no-incremental: analyzers only run when the compiler runs.
    dotnet build $Project -c Release --no-incremental "-p:ErrorLog=$Out/roslyn.sarif%2Cversion=2.1" | Select-String 'warning CA' | ForEach-Object { $_.Line.Trim() } | Sort-Object -Unique

    Write-Step 'SAST: Semgrep'
    docker run --rm -v $Mount -w /src $Images.Semgrep semgrep scan --metrics=off `
        --config p/csharp --config p/owasp-top-ten --config p/secrets `
        --sarif --output scan-results/semgrep.sarif
}

if ($Only -contains 'sca') {
    Write-Step 'SCA: dotnet list package --vulnerable'
    dotnet restore $Project | Out-Null
    dotnet list $Project package --vulnerable --include-transitive

    Write-Step 'SCA: Trivy filesystem'
    docker run --rm -v $Mount -w /src $Images.Trivy fs --scanners vuln `
        --format sarif --output scan-results/trivy-fs.sarif .
    docker run --rm -v $Mount -w /src $Images.Trivy fs --scanners vuln --format table .
}

if ($Only -contains 'secrets') {
    Write-Step 'Secrets: Gitleaks (git history + working tree)'
    docker run --rm -v "${Root}:/repo" -w /repo $Images.Gitleaks git /repo --config /repo/.gitleaks.toml `
        --redact --report-format sarif --report-path /repo/scan-results/gitleaks.sarif --exit-code 0
    docker run --rm -v "${Root}:/repo" -w /repo $Images.Gitleaks dir /repo --config /repo/.gitleaks.toml `
        --redact --report-format json --report-path /repo/scan-results/gitleaks-dir.json --exit-code 0
}

if ($Only -contains 'iac') {
    Write-Step 'IaC: Checkov'
    docker run --rm -v $Mount -w /src $Images.Checkov -d /src --framework dockerfile terraform `
        --soft-fail --compact -o cli -o sarif --output-file-path console,/src/scan-results/checkov.sarif

    Write-Step 'IaC: Trivy config'
    docker run --rm -v $Mount -w /src $Images.Trivy config --format table .
}

if ($IncludeDast) {
    Write-Step 'DAST: build + run container, ZAP baseline + API scan'
    docker build -t vulnapp:local $Root
    docker rm -f vulnapp-local 2>$null | Out-Null
    docker run -d --name vulnapp-local -p 127.0.0.1:8080:8080 vulnapp:local | Out-Null
    try {
        for ($i = 0; $i -lt 30; $i++) {
            try { Invoke-WebRequest http://127.0.0.1:8080/ -UseBasicParsing -TimeoutSec 2 | Out-Null; break } catch { Start-Sleep 2 }
        }
        $zapDir = Join-Path $Out 'zap'
        New-Item -ItemType Directory -Force $zapDir | Out-Null
        # On Docker Desktop, host.docker.internal reaches the published port from inside the ZAP container.
        docker run --rm -v "${zapDir}:/zap/wrk:rw" $Images.Zap zap-baseline.py `
            -t http://host.docker.internal:8080/ -I -r baseline.html -J baseline.json
        docker run --rm -v "${zapDir}:/zap/wrk:rw" $Images.Zap zap-api-scan.py `
            -t http://host.docker.internal:8080/openapi/v1.json -f openapi -I -r api.html -J api.json
    }
    finally {
        docker rm -f vulnapp-local | Out-Null
    }
}

Write-Host "`nResults in $Out" -ForegroundColor Green
