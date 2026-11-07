using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Zertwacht.Core;

namespace Zertwacht.Tests;

internal sealed class FixedClock(DateTimeOffset now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now;
}

/// <summary>Builds real X.509 certificates in memory: a root CA, an intermediate and leaves signed by it.</summary>
internal static class Pki
{
    public static readonly DateTimeOffset Now = new(2026, 11, 7, 12, 0, 0, TimeSpan.Zero);

    public static readonly X509Certificate2 Root = CreateCa("CN=Zertwacht Test Root", null, Now.AddYears(-6), Now.AddYears(10));
    public static readonly X509Certificate2 Intermediate = CreateCa("CN=Zertwacht Test Intermediate", Root, Now.AddYears(-5), Now.AddYears(5));

    private static X509Certificate2 CreateCa(string subject, X509Certificate2? issuer, DateTimeOffset from, DateTimeOffset to)
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        if (issuer is null) return req.CreateSelfSigned(from, to);
        using var signed = req.Create(issuer, from, to, Serial());
        return signed.CopyWithPrivateKey(key);
    }

    public static X509Certificate2 Leaf(
        string[]? dns = null, int daysLeft = 90, int lifetime = 180, int rsaBits = 2048, bool ecdsa = false,
        HashAlgorithmName? hash = null, bool selfSigned = false, DateTimeOffset? notBefore = null)
    {
        var from = notBefore ?? Now.AddDays(daysLeft - lifetime);
        var to = Now.AddDays(daysLeft);
        CertificateRequest req;
        IDisposable key;
        if (ecdsa)
        {
            var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            req = new CertificateRequest("CN=app.example.test", ec, HashAlgorithmName.SHA256);
            key = ec;
        }
        else
        {
            var rsa = RSA.Create(rsaBits);
            req = new CertificateRequest("CN=app.example.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            key = rsa;
        }
        using (key)
        {
            if (dns is not { Length: 0 })
            {
                var san = new SubjectAlternativeNameBuilder();
                foreach (var n in dns ?? ["app.example.test"]) san.AddDnsName(n);
                req.CertificateExtensions.Add(san.Build());
            }
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            if (selfSigned) return req.CreateSelfSigned(from, to);
            // Sign with the intermediate's RSA key explicitly: works for ECDSA leaves and for the SHA-1 test case
            var issuerKey = Intermediate.GetRSAPrivateKey()!;
            X509SignatureGenerator signer = hash == HashAlgorithmName.SHA1
                ? new Sha1RsaSigner(issuerKey)
                : X509SignatureGenerator.CreateForRSA(issuerKey, RSASignaturePadding.Pkcs1);
            return req.Create(Intermediate.SubjectName, signer, from, to, Serial());
        }
    }

    /// <summary>.NET refuses to create SHA-1 signatures; real servers still present them, so the test builds one by hand.</summary>
    private sealed class Sha1RsaSigner(RSA key) : X509SignatureGenerator
    {
        private readonly X509SignatureGenerator inner = CreateForRSA(key, RSASignaturePadding.Pkcs1);

        // AlgorithmIdentifier: sha1WithRSAEncryption (1.2.840.113549.1.1.5), NULL parameters
        public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm) =>
            [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05, 0x05, 0x00];

        public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm) => key.SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

        protected override PublicKey BuildPublicKey() => inner.PublicKey;
    }

    private static byte[] Serial() => RandomNumberGenerator.GetBytes(12);

    public static Analyzer Analyzer(Policy? policy = null) =>
        new(policy ?? new Policy { ExtraTrust = [Root] }, new FixedClock(Now));

    public static CertReport Check(X509Certificate2 leaf, string? host = null, IReadOnlyList<X509Certificate2>? chain = null, Policy? policy = null, bool fromServer = false) =>
        Analyzer(policy).Analyze("test", leaf, chain ?? [Intermediate], host, fromServer: fromServer);

    public static List<string> Codes(CertReport r) => r.Issues.Select(i => i.Code).ToList();
}

public class ValidityTests
{
    [Fact]
    public void HealthyCertificateHasNoIssues()
    {
        var r = Pki.Check(Pki.Leaf(), "app.example.test");
        Assert.Empty(r.Issues);
        Assert.Null(r.Worst);
        Assert.Equal(90, r.DaysLeft);
        Assert.Equal(64, r.Thumbprint.Length); // SHA-256, not the SHA-1 thumbprint Windows shows by default
    }

    [Theory]
    [InlineData(-3, "expired", Severity.Critical)]
    [InlineData(3, "expires-soon", Severity.Critical)]
    [InlineData(20, "expires-soon", Severity.Warning)]
    public void Expiry(int daysLeft, string code, Severity severity)
    {
        var issue = Assert.Single(Pki.Check(Pki.Leaf(daysLeft: daysLeft)).Issues);
        Assert.Equal(code, issue.Code);
        Assert.Equal(severity, issue.Severity);
    }

    [Fact]
    public void ThresholdsArePolicy()
    {
        var r = Pki.Check(Pki.Leaf(daysLeft: 20), policy: new Policy { WarnDays = 14, ExtraTrust = [Pki.Root] });
        Assert.Empty(r.Issues);
    }

    [Fact]
    public void NotYetValid() =>
        Assert.Contains("not-yet-valid", Pki.Codes(Pki.Check(Pki.Leaf(notBefore: Pki.Now.AddDays(2)))));

    [Fact]
    public void LongLifetimeIsInfo()
    {
        var issue = Assert.Single(Pki.Check(Pki.Leaf(daysLeft: 300, lifetime: 800)).Issues);
        Assert.Equal("long-lifetime", issue.Code);
        Assert.Equal(Severity.Info, issue.Severity);
    }
}

public class CryptoTests
{
    [Fact]
    public void WeakRsaKey() => Assert.Contains("weak-key", Pki.Codes(Pki.Check(Pki.Leaf(rsaBits: 1024))));

    [Fact]
    public void EcdsaP256IsFine()
    {
        var r = Pki.Check(Pki.Leaf(ecdsa: true));
        Assert.Empty(r.Issues);
        Assert.Equal(("ECDSA", 256), (r.KeyAlgorithm, r.KeySize));
    }

    [Fact]
    public void Sha1SignatureIsCritical()
    {
        var r = Pki.Check(Pki.Leaf(hash: HashAlgorithmName.SHA1));
        var issue = r.Issues.Single(i => i.Code == "weak-signature");
        Assert.Equal(Severity.Critical, issue.Severity);
    }
}

public class NameTests
{
    [Theory]
    [InlineData("app.example.test", "app.example.test", true)]
    [InlineData("APP.example.test", "app.example.TEST.", true)]
    [InlineData("*.example.test", "app.example.test", true)]
    [InlineData("*.example.test", "example.test", false)]          // the wildcard needs a label
    [InlineData("*.example.test", "a.b.example.test", false)]      // and covers only one
    [InlineData("app.example.test", "api.example.test", false)]
    public void Matching(string pattern, string host, bool matches) => Assert.Equal(matches, Analyzer.Matches(pattern, host));

    [Fact]
    public void MismatchIsCritical()
    {
        var issue = Pki.Check(Pki.Leaf(), "portal.example.test").Issues.Single();
        Assert.Equal("name-mismatch", issue.Code);
        Assert.Contains("covers app.example.test", issue.Message);
    }

    [Fact]
    public void NoSan() => Assert.Contains("no-san", Pki.Codes(Pki.Check(Pki.Leaf(dns: []))));

    [Fact]
    public void FilesAreNotCheckedForAHost() => Assert.Empty(Pki.Check(Pki.Leaf(dns: ["other.example.test"])).Issues);
}

public class TrustTests
{
    [Fact]
    public void SelfSigned() => Assert.Contains("self-signed", Pki.Codes(Pki.Check(Pki.Leaf(selfSigned: true), chain: [])));

    [Fact]
    public void MissingIntermediateIsAnIncompleteChain()
    {
        var issue = Pki.Check(Pki.Leaf(), chain: [], fromServer: true).Issues.Single();
        Assert.Equal("untrusted-chain", issue.Code);
        Assert.Contains("incomplete chain", issue.Message);
    }

    [Fact]
    public void UnknownRootIsUntrusted()
    {
        // Without the test root in the trust list, the chain ends at an unknown root
        var r = Pki.Check(Pki.Leaf(), policy: new Policy { ExtraTrust = [Pki.Leaf(selfSigned: true)] });
        Assert.Contains("untrusted-chain", Pki.Codes(r));
    }

    [Fact]
    public void TrustCheckCanBeTurnedOff() =>
        Assert.Empty(Pki.Check(Pki.Leaf(), chain: [], policy: new Policy { CheckTrust = false }).Issues);

    [Fact]
    public void CaCertificatesAreNotSelfSignedWarnings() =>
        Assert.DoesNotContain("self-signed", Pki.Codes(Pki.Analyzer().Analyze("root", Pki.Root, [])));
}

public class FileTests
{
    private static string Temp(string name, byte[] content)
    {
        var dir = Path.Combine(Path.GetTempPath(), "zertwacht-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, name);
        File.WriteAllBytes(path, content);
        return path;
    }

    [Fact]
    public void PemWithChainLeafFirst()
    {
        var leaf = Pki.Leaf();
        var pem = leaf.ExportCertificatePem() + "\n" + Pki.Intermediate.ExportCertificatePem() + "\n";
        var (loaded, chain) = CertFiles.Load(Temp("site.pem", System.Text.Encoding.ASCII.GetBytes(pem)));
        Assert.Equal(leaf.Thumbprint, loaded.Thumbprint);
        Assert.Equal(Pki.Intermediate.Thumbprint, Assert.Single(chain).Thumbprint);
    }

    [Fact]
    public void Der() => Assert.Empty(CertFiles.Load(Temp("site.cer", Pki.Leaf().Export(X509ContentType.Cert))).Chain);

    [Fact]
    public void NotACertificate() => Assert.Throws<InvalidDataException>(() => CertFiles.Load(Temp("x.crt", [1, 2, 3])));

    [Fact]
    public void FolderFindsOnlyCertificateFiles()
    {
        var file = Temp("a.pem", System.Text.Encoding.ASCII.GetBytes(Pki.Leaf().ExportCertificatePem()));
        var dir = Path.GetDirectoryName(file)!;
        File.WriteAllText(Path.Combine(dir, "notes.txt"), "x");
        File.WriteAllBytes(Path.Combine(dir, "b.der"), Pki.Leaf().Export(X509ContentType.Cert));
        Assert.Equal(["a.pem", "b.der"], CertFiles.Find(dir).Select(Path.GetFileName));
    }
}

public class TargetTests
{
    [Theory]
    [InlineData("example.com", "example.com", 443)]
    [InlineData("example.com:8443", "example.com", 8443)]
    [InlineData("https://example.com/login", "example.com", 443)]
    [InlineData("https://example.com:9443/", "example.com", 9443)]
    [InlineData("[::1]:8443", "::1", 8443)]
    [InlineData("[2001:db8::1]", "2001:db8::1", 443)]
    public void Parse(string target, string host, int port) => Assert.Equal((host, port), TlsEndpoint.Parse(target));
}

public class ReportTests
{
    [Fact]
    public void MarkdownSortsBySoonestExpiry()
    {
        var reports = new[] { Pki.Check(Pki.Leaf(daysLeft: 200, lifetime: 300)), Pki.Check(Pki.Leaf(daysLeft: 3)), Pki.Check(Pki.Leaf(daysLeft: 20)) };
        var md = Reports.ToMarkdown(reports, [new Failure("down.example.test:443", "timeout")], DateOnly.FromDateTime(Pki.Now.UtcDateTime));
        Assert.Contains("3 certificate(s): **1 critical**, 1 warning(s), 1 unreachable.", md);
        var rows = md.Split('\n').Where(l => l.StartsWith("| 🔴") || l.StartsWith("| 🟠") || l.StartsWith("| 🟢")).ToList();
        Assert.Equal(["| 🔴", "| 🟠", "| 🟢"], rows.Select(r => r[..4]));
        Assert.Contains("| ⚪ | `down.example.test:443` |", md);
    }

    [Fact]
    public void Json()
    {
        using var doc = System.Text.Json.JsonDocument.Parse(Reports.ToJson([Pki.Check(Pki.Leaf(daysLeft: 3))], []));
        var c = doc.RootElement.GetProperty("certificates")[0];
        Assert.Equal(3, c.GetProperty("daysLeft").GetInt32());
        Assert.Equal("critical", c.GetProperty("issues")[0].GetProperty("severity").GetString());
    }
}
