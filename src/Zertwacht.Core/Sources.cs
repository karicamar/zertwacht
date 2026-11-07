using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Zertwacht.Core;

/// <summary>Certificates from files: PEM (one or several, leaf first), DER (.cer/.der/.crt).</summary>
public static class CertFiles
{
    private static readonly string[] Extensions = [".pem", ".crt", ".cer", ".der"];

    public static IEnumerable<string> Find(string path) =>
        File.Exists(path) ? [path]
        : Directory.Exists(path) ? Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories).Where(f => Extensions.Contains(Path.GetExtension(f).ToLowerInvariant())).Order(StringComparer.Ordinal)
        : throw new FileNotFoundException($"Not found: {path}");

    /// <summary>The first certificate is the one checked, the others are its chain. Private keys in the file are ignored.</summary>
    public static (X509Certificate2 Leaf, List<X509Certificate2> Chain) Load(string file)
    {
        var bytes = File.ReadAllBytes(file);
        var text = System.Text.Encoding.ASCII.GetString(bytes);
        if (text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
        {
            var all = new X509Certificate2Collection();
            all.ImportFromPem(text);
            if (all.Count == 0) throw new InvalidDataException($"{file}: no certificate in the PEM file");
            return (all[0], all.Skip(1).ToList());
        }
        try
        {
            return (X509CertificateLoader.LoadCertificate(bytes), []);
        }
        catch (System.Security.Cryptography.CryptographicException ex)
        {
            throw new InvalidDataException($"{file}: not a certificate ({ex.Message})", ex);
        }
    }
}

/// <summary>
/// Fetches the certificate an endpoint presents, with SNI, without trusting it: the handshake accepts any certificate so that
/// expired or broken ones can be reported instead of failing. Nothing is sent after the handshake.
/// </summary>
public static class TlsEndpoint
{
    public static async Task<(X509Certificate2 Leaf, List<X509Certificate2> Chain, string Protocol)> FetchAsync(string host, int port, TimeSpan timeout, CancellationToken ct = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);

        X509Certificate2? leaf = null;
        var chain = new List<X509Certificate2>();
        await using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false, (_, cert, presented, _) =>
        {
            if (cert is not null) leaf = new X509Certificate2(cert);
            // ExtraStore holds what the server actually sent; ChainElements may include intermediates the OS filled in from its cache
            if (presented is not null)
                foreach (var c in presented.ChainPolicy.ExtraStore)
                    if (leaf is null || c.Thumbprint != leaf.Thumbprint) chain.Add(new X509Certificate2(c));
            return true; // inspect, do not trust: the Analyzer decides
        });
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = host,
            EnabledSslProtocols = SslProtocols.None, // let the OS pick the best it supports
        }, cts.Token).ConfigureAwait(false);

        return (leaf ?? throw new InvalidDataException($"{host}:{port} sent no certificate"), chain, ssl.SslProtocol.ToString());
    }

    /// <summary>"example.com", "example.com:8443", "[::1]:443"</summary>
    public static (string Host, int Port) Parse(string target)
    {
        target = target.Trim();
        if (target.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) target = new Uri(target).Authority;
        if (target.StartsWith('['))
        {
            var close = target.IndexOf(']');
            var host = target[1..close];
            return (host, close + 2 < target.Length && target[close + 1] == ':' ? int.Parse(target[(close + 2)..]) : 443);
        }
        var colon = target.LastIndexOf(':');
        return colon > 0 && target.IndexOf(':') == colon && int.TryParse(target[(colon + 1)..], out var p) ? (target[..colon], p) : (target, 443);
    }
}
