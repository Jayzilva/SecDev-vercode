namespace VulnApp.Security;

// POC-VULN: CWE-798 — hard-coded credentials committed to source control.
// The values below are random, NOT real credentials. They exist only so that
// secret scanners (Gitleaks, Veracode, GitHub secret scanning) have something to find.
public static class Secrets
{
    public const string PaymentApiKey = "4814c08419b6bbb8625cf4ad2cbffe3151f1d681";

    public const string AdminConnectionString =
        "Server=db.internal.test;Database=prod;User Id=sa;Password=Pr0d-Adm1n-2026!;";
}
