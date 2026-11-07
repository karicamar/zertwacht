using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Zertwacht.Core;

public sealed record Failure(string Target, string Error);

public static class Reports
{
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string ToJson(IReadOnlyList<CertReport> certs, IReadOnlyList<Failure> failures) =>
        JsonSerializer.Serialize(new { tool = "Zertwacht", certificates = certs.OrderBy(c => c.DaysLeft), failures }, Json);

    /// <summary>Soonest expiry first: the table someone looks at on Monday morning.</summary>
    public static string ToMarkdown(IReadOnlyList<CertReport> certs, IReadOnlyList<Failure> failures, DateOnly today)
    {
        var sb = new StringBuilder($"## Zertwacht: certificates ({today:yyyy-MM-dd})\n\n");
        var critical = certs.Count(c => c.Worst == Severity.Critical);
        var warning = certs.Count(c => c.Worst == Severity.Warning);
        sb.AppendLine($"{certs.Count} certificate(s): **{critical} critical**, {warning} warning(s){(failures.Count > 0 ? $", {failures.Count} unreachable" : "")}.").AppendLine();
        sb.AppendLine("| | Target | Expires | Days | Key | Problems |").AppendLine("|---|---|---|---:|---|---|");
        foreach (var c in certs.OrderBy(c => c.DaysLeft))
        {
            var icon = c.Worst switch { Severity.Critical => "🔴", Severity.Warning => "🟠", Severity.Info => "🔵", _ => "🟢" };
            sb.AppendLine($"| {icon} | `{Esc(c.Target)}` | {c.NotAfter:yyyy-MM-dd} | {c.DaysLeft} | {c.KeyAlgorithm} {c.KeySize} | {Esc(string.Join("; ", c.Issues.Select(i => i.Message)))} |");
        }
        foreach (var f in failures)
            sb.AppendLine($"| ⚪ | `{Esc(f.Target)}` | – | – | – | {Esc(f.Error)} |");
        return sb.ToString();
    }

    private static string Esc(string s) => s.Replace("|", "\\|");
}
