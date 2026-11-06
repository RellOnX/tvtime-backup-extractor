using System.Globalization;
using System.Text.Json;

namespace TVTimeRecovery.Windows;

internal sealed record RecoveryProgress(string Message, long? Current = null, long? Total = null)
{
    public bool HasExtractionCounts => Current is long current && Total is long total && current >= 0 && total >= 0 && current <= total;
    public bool IsDeterminate => HasExtractionCounts && Total > 0;
    public double PhasePercent => IsDeterminate ? 100.0 * (double)Current!.Value / Total!.Value : 0;
    public string DisplayText => HasExtractionCounts
        ? string.Create(CultureInfo.InvariantCulture, $"Extraction phase: {Current} of {Total} selected files. Other phases are not included.")
        : Message;

    public static RecoveryProgress FromPayload(JsonElement payload)
    {
        var stage = payload.GetProperty("stage").GetString();
        if (stage == "extraction" &&
            payload.TryGetProperty("current", out var currentValue) && currentValue.ValueKind == JsonValueKind.Number && currentValue.TryGetInt64(out var current) &&
            payload.TryGetProperty("total", out var totalValue) && totalValue.ValueKind == JsonValueKind.Number && totalValue.TryGetInt64(out var total) &&
            current >= 0 && total >= 0 && current <= total)
            return new("Copying selected TV Time files.", current, total);
        return new(stage switch
        {
            "preflight" => "Validating the completed encrypted backup.",
            "extraction" => "Copying selected TV Time files.",
            "analysis" => "Recovering readable history tables.",
            "report" => "Building private offline reports.",
            _ => "Validating private recovery state.",
        });
    }
}
