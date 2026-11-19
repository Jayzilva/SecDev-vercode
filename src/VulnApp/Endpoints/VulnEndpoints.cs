using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;

namespace VulnApp.Endpoints;

// WARNING: every endpoint below is deliberately insecure. See docs/findings-matrix.md
// for the secure version of each pattern.
public static class VulnEndpoints
{
    public static void MapVulnEndpoints(this WebApplication app)
    {
        var api = app.MapGroup("/api");

        api.MapGet("/users", SearchUsers);
        api.MapGet("/ping", Ping);
        api.MapGet("/files", ReadFile);
        api.MapPost("/import", ImportObject);
        api.MapPost("/register", Register);
        api.MapGet("/fetch", Fetch);
        app.MapGet("/login", Login);
    }

    // POC-VULN: CWE-89 — SQL injection via string concatenation.
    // Try: /api/users?name=' OR '1'='1
    static IResult SearchUsers(string name, IConfiguration config)
    {
        using var conn = new SqliteConnection(config["ConnectionStrings:Default"]);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id, name, email FROM users WHERE name = '" + name + "'";
        using var reader = cmd.ExecuteReader();

        var rows = new List<object>();
        while (reader.Read())
            rows.Add(new { id = reader.GetInt64(0), name = reader.GetString(1), email = reader.GetString(2) });
        return Results.Ok(rows);
    }

    // POC-VULN: CWE-78 — OS command injection.
    // Try: /api/ping?host=127.0.0.1;id   (Linux)  or  host=127.0.0.1%26whoami (Windows)
    static IResult Ping(string host)
    {
        var psi = OperatingSystem.IsWindows()
            ? new ProcessStartInfo("cmd.exe", "/c ping -n 1 " + host)
            : new ProcessStartInfo("/bin/sh", "-c \"ping -c 1 " + host + "\"");
        psi.RedirectStandardOutput = true;
        using var proc = Process.Start(psi)!;
        var output = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit(5000);
        return Results.Text(output);
    }

    // POC-VULN: CWE-22 — path traversal, user input joined to a path without validation.
    // Try: /api/files?name=../../appsettings.json
    static IResult ReadFile(string name, IWebHostEnvironment env)
    {
        var path = Path.Combine(env.WebRootPath, "files", name);
        return Results.Text(File.ReadAllText(path));
    }

    // POC-VULN: CWE-502 — insecure deserialization (TypeNameHandling.All lets the
    // caller choose which .NET type gets instantiated).
    static async Task<IResult> ImportObject(HttpRequest request)
    {
        using var reader = new StreamReader(request.Body);
        var body = await reader.ReadToEndAsync();
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
        var obj = JsonConvert.DeserializeObject(body, settings);
        return Results.Ok(new { imported = obj?.GetType().FullName });
    }

    // POC-VULN: CWE-327/CWE-328 — MD5 used for password hashing (fast, unsalted, broken).
    static IResult Register(RegisterRequest req, IConfiguration config)
    {
        using var md5 = MD5.Create();
        var hash = Convert.ToHexString(md5.ComputeHash(Encoding.UTF8.GetBytes(req.Password)));

        using var conn = new SqliteConnection(config["ConnectionStrings:Default"]);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO users (name, email, password_hash) VALUES ($n, $e, $h)";
        cmd.Parameters.AddWithValue("$n", req.Name);
        cmd.Parameters.AddWithValue("$e", req.Email);
        cmd.Parameters.AddWithValue("$h", hash);
        cmd.ExecuteNonQuery();
        return Results.Ok(new { stored = hash });
    }

    // POC-VULN: CWE-918 — server-side request forgery; server fetches any URL the caller gives.
    // Try: /api/fetch?url=http://169.254.169.254/latest/meta-data/
    static async Task<IResult> Fetch(string url, IHttpClientFactory factory)
    {
        var client = factory.CreateClient();
        var body = await client.GetStringAsync(url);
        return Results.Text(body);
    }

    // POC-VULN: CWE-601 — open redirect.
    // Try: /login?returnUrl=https://evil.example
    static IResult Login(string? returnUrl)
    {
        return Results.Redirect(returnUrl ?? "/");
    }

    public record RegisterRequest(string Name, string Email, string Password);
}
