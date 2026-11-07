using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Zertwacht.Core;

public enum Severity
{
    Info,
    Warning,
    Critical,
}

public sealed record Issue(string Code, Severity Severity, string Message);

/// <summary>One certificate as found on an endpoint or in a file, with what Zertwacht thinks of it.</summary>
public sealed record CertReport
{
    public required string Target { get; init; }
    public required string Subject { get; init; }
    public required string Issuer { get; init; }
    public required DateTimeOffset NotBefore { get; init; }
    public required DateTimeOffset NotAfter { get; init; }
    public required int DaysLeft { get; init; }
    public required string KeyAlgorithm { get; init; }
    public required int KeySize { get; init; }
    public required string SignatureAlgorithm { get; init; }
    public required IReadOnlyList<string> DnsNames { get; init; }
    public required string Thumbprint { get; init; }
    public string? Protocol { get; init; }
    public required IReadOnlyList<Issue> Issues { get; init; }

    public Severity? Worst => Issues.Count == 0 ? null : Issues.Max(i => i.Severity);
}

public sealed record Policy
{
    /// <summary>Warn this many days before expiry.</summary>
    public int WarnDays { get; init; } = 30;

    /// <summary>Critical this many days before expiry: time to renew is now.</summary>
    public int CriticalDays { get; init; } = 7;

    /// <summary>Public TLS certificates may be valid for at most 398 days (CA/Browser Forum baseline requirements).</summary>
    public int MaxLifetimeDays { get; init; } = 398;

    /// <summary>Check the chain against the system trust store (off for internal CAs, or use <see cref="ExtraTrust"/>).</summary>
    public bool CheckTrust { get; init; } = true;

    /// <summary>Internal root CAs to trust in addition to the system store.</summary>
    public IReadOnlyList<X509Certificate2> ExtraTrust { get; init; } = [];
}

/// <summary>The checks. Everything here works on certificates in memory, so it is the same for files and live endpoints.</summary>
public sealed class Analyzer(Policy policy, TimeProvider? clock = null)
{
    private readonly TimeProvider clock = clock ?? TimeProvider.System;

    /// <param name="chain">The other certificates: what the server sent, or the rest of the PEM file.</param>
    /// <param name="fromServer">True for live endpoints: then the chain must be complete without help from local caches.</param>
    public CertReport Analyze(string target, X509Certificate2 cert, IReadOnlyList<X509Certificate2> chain, string? expectedHost = null, string? protocol = null, bool fromServer = false)
    {
        var now = clock.GetUtcNow();
        var issues = new List<Issue>();
        var notAfter = new DateTimeOffset(cert.NotAfter.ToUniversalTime());
        var notBefore = new DateTimeOffset(cert.NotBefore.ToUniversalTime());
        var daysLeft = (int)Math.Floor((notAfter - now).TotalDays);

        // Validity
        if (notAfter <= now)
            issues.Add(new("expired", Severity.Critical, $"expired on {notAfter:yyyy-MM-dd} ({-daysLeft} day(s) ago)"));
        else if (daysLeft < policy.CriticalDays)
            issues.Add(new("expires-soon", Severity.Critical, $"expires in {daysLeft} day(s), on {notAfter:yyyy-MM-dd}: renew now"));
        else if (daysLeft < policy.WarnDays)
            issues.Add(new("expires-soon", Severity.Warning, $"expires in {daysLeft} day(s), on {notAfter:yyyy-MM-dd}"));
        if (notBefore > now)
            issues.Add(new("not-yet-valid", Severity.Critical, $"not valid before {notBefore:yyyy-MM-dd} (clock or deployment problem)"));

        // Key and signature
        var (keyAlg, keySize) = KeyInfo(cert);
        if (keyAlg == "RSA" && keySize < 2048)
            issues.Add(new("weak-key", Severity.Critical, $"RSA key of {keySize} bits (at least 2048, BSI TR-02102 recommends 3000 from 2023)"));
        else if (keyAlg == "ECDSA" && keySize < 256)
            issues.Add(new("weak-key", Severity.Critical, $"EC key of {keySize} bits (at least 256)"));
        var sig = cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "?";
        if (sig.Contains("sha1", StringComparison.OrdinalIgnoreCase) || sig.Contains("md5", StringComparison.OrdinalIgnoreCase))
            issues.Add(new("weak-signature", Severity.Critical, $"signed with {sig}: collisions are practical, browsers reject it"));

        // Names
        var dns = DnsNames(cert);
        if (dns.Count == 0)
            issues.Add(new("no-san", Severity.Warning, "no Subject Alternative Name: browsers ignore the CN and reject the certificate"));
        if (expectedHost is not null && dns.Count > 0 && !dns.Any(n => Matches(n, expectedHost)))
            issues.Add(new("name-mismatch", Severity.Critical, $"not valid for {expectedHost} (covers {string.Join(", ", dns.Take(5))})"));

        // Lifetime: only for leaf certificates from public CAs; a self-signed or internal certificate may run longer
        var lifetime = (int)(notAfter - notBefore).TotalDays;
        var selfSigned = cert.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData);
        if (lifetime > policy.MaxLifetimeDays && !selfSigned && !IsCa(cert))
            issues.Add(new("long-lifetime", Severity.Info, $"valid for {lifetime} days; public CAs issue at most {policy.MaxLifetimeDays} (and less from 2026), automate renewal (ACME)"));

        // Trust
        if (selfSigned && !IsCa(cert))
            issues.Add(new("self-signed", Severity.Warning, "self-signed: clients cannot verify who they talk to"));
        else if (policy.CheckTrust)
        {
            var problem = ChainProblem(cert, chain, fromServer);
            if (problem is not null)
                issues.Add(new("untrusted-chain", Severity.Critical, problem));
        }

        return new CertReport
        {
            Target = target,
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            NotBefore = notBefore,
            NotAfter = notAfter,
            DaysLeft = daysLeft,
            KeyAlgorithm = keyAlg,
            KeySize = keySize,
            SignatureAlgorithm = sig,
            DnsNames = dns,
            Thumbprint = cert.GetCertHashString(HashAlgorithmName.SHA256),
            Protocol = protocol,
            Issues = issues.OrderByDescending(i => i.Severity).ToList(),
        };
    }

    private string? ChainProblem(X509Certificate2 cert, IReadOnlyList<X509Certificate2> chain, bool fromServer)
    {
        using var builder = new X509Chain();
        builder.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // offline-friendly; revocation is a separate concern
        builder.ChainPolicy.VerificationTime = clock.GetUtcNow().UtcDateTime;
        builder.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid; // expiry is reported on its own
        // Do not fetch missing intermediates (AIA) like Windows and browsers do: many API clients and apps cannot,
        // so a server must send the full chain itself
        builder.ChainPolicy.DisableCertificateDownloads = true;
        foreach (var c in chain) builder.ChainPolicy.ExtraStore.Add(c);
        if (policy.ExtraTrust.Count > 0)
        {
            builder.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            foreach (var root in policy.ExtraTrust) builder.ChainPolicy.CustomTrustStore.Add(root);
        }
        if (builder.Build(cert))
        {
            // Valid here, but only because this machine already knew the intermediate? Then other clients fail.
            if (fromServer && builder.ChainElements.Count > 2)
            {
                var issuing = builder.ChainElements[1].Certificate.Thumbprint;
                if (!chain.Any(c => c.Thumbprint == issuing))
                    return "incomplete chain: the server does not send the intermediate (browsers cope, many API clients fail)";
            }
            return null;
        }
        var statuses = builder.ChainStatus.Where(s => s.Status != X509ChainStatusFlags.NotTimeValid).Select(s => s.Status.ToString()).Distinct().ToList();
        if (statuses.Count == 0) return null;
        return statuses.Contains(nameof(X509ChainStatusFlags.PartialChain))
            ? "incomplete chain: the intermediate certificate is missing (works in some browsers, fails in apps and APIs)"
            : $"chain does not validate ({string.Join(", ", statuses)})";
    }

    internal static (string Algorithm, int Size) KeyInfo(X509Certificate2 cert)
    {
        using var rsa = cert.GetRSAPublicKey();
        if (rsa is not null) return ("RSA", rsa.KeySize);
        using var ec = cert.GetECDsaPublicKey();
        if (ec is not null) return ("ECDSA", ec.KeySize);
        return (cert.PublicKey.Oid.FriendlyName ?? "unknown", 0);
    }

    internal static bool IsCa(X509Certificate2 cert) =>
        cert.Extensions.OfType<X509BasicConstraintsExtension>().Any(b => b.CertificateAuthority);

    internal static List<string> DnsNames(X509Certificate2 cert)
    {
        var san = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        return san is null ? [] : san.EnumerateDnsNames().ToList();
    }

    /// <summary>RFC 6125: a wildcard covers exactly one label (*.example.com matches a.example.com, not example.com or a.b.example.com).</summary>
    internal static bool Matches(string pattern, string host)
    {
        host = host.TrimEnd('.').ToLowerInvariant();
        pattern = pattern.TrimEnd('.').ToLowerInvariant();
        if (!pattern.StartsWith("*.", StringComparison.Ordinal)) return pattern == host;
        var dot = host.IndexOf('.');
        return dot > 0 && host[(dot + 1)..] == pattern[2..];
    }
}
