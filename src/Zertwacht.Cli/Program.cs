using System.Text;
using Zertwacht.Core;

Console.OutputEncoding = Encoding.UTF8;

if (args.Length == 0 || args[0] is "-h" or "--help")
{
    Console.WriteLine("""
        Zertwacht: TLS certificate monitor for your own servers and certificate files

        Usage: zertwacht <target> [<target> ...] [options]
          target   host, host:port, https://url, a .pem/.crt/.cer/.der file, or a folder of them

          --list <file>          targets, one per line (# for comments)
          --warn <days>          warning before expiry (default 30)
          --critical <days>      critical before expiry (default 7)
          --ca <file>            trust this internal root CA (repeatable)
          --no-trust             do not check the chain (internal certificates without their CA)
          -f, --format <console|markdown|json>
          -o, --output <file>
          --fail-on <critical|warning|none>   exit code 1 at this level (default: critical)

        Exit codes: 0 = OK, 1 = problems at or above --fail-on, 2 = error.
        """);
    return args.Length == 0 ? 2 : 0;
}

var targets = new List<string>();
var extraTrust = new List<System.Security.Cryptography.X509Certificates.X509Certificate2>();
int warn = 30, critical = 7;
var checkTrust = true;
var format = "console";
string? output = null;
Severity? failOn = Severity.Critical;
try
{
    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--list":
                targets.AddRange(File.ReadAllLines(args[++i]).Select(l => l.Split('#')[0].Trim()).Where(l => l.Length > 0));
                break;
            case "--warn": warn = int.Parse(args[++i]); break;
            case "--critical": critical = int.Parse(args[++i]); break;
            case "--ca": extraTrust.Add(CertFiles.Load(args[++i]).Leaf); break;
            case "--no-trust": checkTrust = false; break;
            case "--format" or "-f": format = args[++i].ToLowerInvariant(); break;
            case "--output" or "-o": output = args[++i]; break;
            case "--fail-on": failOn = args[++i].ToLowerInvariant() == "none" ? null : Enum.Parse<Severity>(args[i], ignoreCase: true); break;
            default:
                if (args[i].StartsWith('-')) { Console.Error.WriteLine($"Unknown option {args[i]}"); return 2; }
                targets.Add(args[i]);
                break;
        }
    }
}
catch (Exception ex) when (ex is IndexOutOfRangeException or FormatException or ArgumentException or IOException or InvalidDataException)
{
    Console.Error.WriteLine("Invalid arguments: " + ex.Message);
    return 2;
}

var analyzer = new Analyzer(new Policy { WarnDays = warn, CriticalDays = critical, CheckTrust = checkTrust, ExtraTrust = extraTrust });
var reports = new List<CertReport>();
var failures = new List<Failure>();
var endpoints = new List<string>();

foreach (var t in targets)
{
    if (File.Exists(t) || Directory.Exists(t))
    {
        foreach (var file in CertFiles.Find(t))
        {
            try
            {
                var (leaf, chain) = CertFiles.Load(file);
                reports.Add(analyzer.Analyze(Path.GetRelativePath(".", file).Replace('\\', '/'), leaf, chain));
            }
            catch (InvalidDataException ex) { failures.Add(new Failure(file, ex.Message)); }
        }
    }
    else endpoints.Add(t);
}

// Endpoints in parallel, a few at a time (polite to the servers, fast for long lists)
var gate = new SemaphoreSlim(8);
var results = await Task.WhenAll(endpoints.Select(async t =>
{
    await gate.WaitAsync();
    try
    {
        var (host, port) = TlsEndpoint.Parse(t);
        var (leaf, chain, protocol) = await TlsEndpoint.FetchAsync(host, port, TimeSpan.FromSeconds(10));
        return (Report: analyzer.Analyze($"{host}:{port}", leaf, chain, host, protocol, fromServer: true), Failure: (Failure?)null);
    }
    catch (Exception ex) when (ex is System.Net.Sockets.SocketException or IOException or OperationCanceledException or System.Security.Authentication.AuthenticationException or InvalidDataException or FormatException)
    {
        return (Report: (CertReport?)null, Failure: new Failure(t, ex is OperationCanceledException ? "timeout" : ex.Message));
    }
    finally { gate.Release(); }
}));
reports.AddRange(results.Where(r => r.Report is not null).Select(r => r.Report!));
failures.AddRange(results.Where(r => r.Failure is not null).Select(r => r.Failure!));

var today = DateOnly.FromDateTime(DateTime.UtcNow);
var text = format switch
{
    "markdown" or "md" => Reports.ToMarkdown(reports, failures, today),
    "json" => Reports.ToJson(reports, failures),
    _ => null,
};
if (text is null) Print(reports, failures);
else if (output is not null) { File.WriteAllText(output, text); Console.Error.WriteLine($"Report written to {output}"); }
else Console.WriteLine(text);

if (Environment.GetEnvironmentVariable("GITHUB_STEP_SUMMARY") is { Length: > 0 } summary)
    File.AppendAllText(summary, Reports.ToMarkdown(reports, failures, today));

if (reports.Count == 0 && failures.Count > 0) return 2;
return failOn is { } level && (reports.Any(r => r.Worst >= level) || (level <= Severity.Critical && failures.Count > 0)) ? 1 : 0;

static void Print(IReadOnlyList<CertReport> reports, IReadOnlyList<Failure> failures)
{
    Console.WriteLine();
    foreach (var r in reports.OrderBy(r => r.DaysLeft))
    {
        var (label, color) = r.Worst switch
        {
            Severity.Critical => ("CRITICAL", ConsoleColor.Red),
            Severity.Warning => ("WARNING ", ConsoleColor.DarkYellow),
            Severity.Info => ("INFO    ", ConsoleColor.Cyan),
            _ => ("OK      ", ConsoleColor.Green),
        };
        Write($"  {label} ", color);
        Write(r.Target, ConsoleColor.White);
        Write($"  {r.DaysLeft,4} days  {r.NotAfter:yyyy-MM-dd}  {r.KeyAlgorithm} {r.KeySize}{(r.Protocol is null ? "" : "  " + r.Protocol)}\n", ConsoleColor.Gray);
        foreach (var i in r.Issues)
            Write($"           {i.Message}\n", i.Severity == Severity.Critical ? ConsoleColor.Red : ConsoleColor.DarkGray);
    }
    foreach (var f in failures)
    {
        Write("  FAILED   ", ConsoleColor.Red);
        Console.WriteLine($"{f.Target}: {f.Error}");
    }
    Console.WriteLine();
}

static void Write(string text, ConsoleColor color)
{
    var old = Console.ForegroundColor;
    Console.ForegroundColor = color;
    Console.Write(text);
    Console.ForegroundColor = old;
}
