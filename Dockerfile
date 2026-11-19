# WARNING: intentionally weak Dockerfile so IaC scanners (Checkov, Trivy) have findings.
# Fixed version of each line is described in docs/03-secrets-iac.md.

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/VulnApp/ ./VulnApp/
RUN dotnet publish VulnApp/VulnApp.csproj -c Release -o /app

# POC-VULN: floating tag, not pinned to a digest
FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
# POC-VULN: ADD instead of COPY (CKV_DOCKER_4)
ADD --chown=root:root . /tmp/context-not-needed
COPY --from=build /app .
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
# POC-VULN: no USER instruction -> container runs as root (CKV_DOCKER_3 / DS002)
# POC-VULN: no HEALTHCHECK (CKV_DOCKER_2 / DS026)
ENTRYPOINT ["dotnet", "VulnApp.dll"]
