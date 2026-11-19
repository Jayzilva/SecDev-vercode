// =============================================================================
//  VulnApp — INTENTIONALLY VULNERABLE application for security-scanner training.
//  Every flaw is tagged "POC-VULN: CWE-xxx" so findings can be traced in
//  docs/findings-matrix.md. NEVER deploy this anywhere reachable by others.
// =============================================================================
using Microsoft.Data.Sqlite;
using VulnApp.Endpoints;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages();
builder.Services.AddOpenApi();          // exposes /openapi/v1.json for the ZAP API scan
builder.Services.AddHttpClient();

var app = builder.Build();

// Seed a throwaway SQLite database.
var dbPath = Path.Combine(app.Environment.ContentRootPath, "vulnapp.db");
var connectionString = $"Data Source={dbPath}";
SeedDatabase(connectionString);
app.Services.GetRequiredService<IConfiguration>()["ConnectionStrings:Default"] = connectionString;

// POC-VULN: CWE-693 — no security headers (CSP, X-Frame-Options, HSTS ...), no HTTPS redirect.
app.UseStaticFiles();
app.MapOpenApi();
app.MapRazorPages();
app.MapVulnEndpoints();

app.Run();

static void SeedDatabase(string cs)
{
    using var conn = new SqliteConnection(cs);
    conn.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = """
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password_hash TEXT);
        DELETE FROM users;
        INSERT INTO users (name, email, password_hash) VALUES
          ('alice', 'alice@example.test', 'x'),
          ('bob',   'bob@example.test',   'x'),
          ('admin', 'admin@example.test', 'x');
        """;
    cmd.ExecuteNonQuery();
}
