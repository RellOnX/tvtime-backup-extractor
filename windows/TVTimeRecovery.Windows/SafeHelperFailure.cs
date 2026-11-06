using System.Text.Json;

namespace TVTimeRecovery.Windows;

internal enum HelperRecoveryPhase { BackupValidation, Unlocking, Acquisition, Extraction, Analysis, Report }

internal static class SafeHelperFailure
{
    internal static HelperRecoveryPhase Advance(HelperRecoveryPhase previous, JsonElement payload) =>
        payload.TryGetProperty("stage", out var stage) && stage.ValueKind == JsonValueKind.String
            ? stage.GetString() switch
            {
                "preflight" => HelperRecoveryPhase.BackupValidation,
                "extraction" => HelperRecoveryPhase.Extraction,
                "analysis" => HelperRecoveryPhase.Analysis,
                "report" => HelperRecoveryPhase.Report,
                _ => previous,
            } : previous;

    internal static RecoveryUserException FromPayload(JsonElement payload, HelperRecoveryPhase phase)
    {
        var code = payload.TryGetProperty("code", out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() : null;
        // Never display payload.message, raw code, exception text, paths or helper stderr.
        var explanation = code switch
        {
            "invalid_input" => "The selected source, destination or options failed a safety check.",
            "insufficient_space" => "The destination ran out of usable space. Incomplete output was not accepted.",
            "output_exists" => "The destination is no longer fresh. Existing output was not overwritten.",
            "unsafe_path" => "A source or destination path failed a safety check. Use regular local folders without overlap, links or cloud sync.",
            "backup_unencrypted" => "The selected Apple backup is not confirmed as encrypted.",
            "backup_unfinished" => "The selected Apple backup is not marked finished.",
            "app_data_missing" => "The backup does not contain the required TV Time app data.",
            "source_changed" => "The source backup changed during recovery. Incomplete output was not accepted.",
            "unsupported_schema" => "This release cannot safely interpret the TV Time data format. Preserve any incomplete output.",
            "backup_password_rejected" => "The encrypted backup could not be unlocked with the supplied password.",
            "partial_extraction" => "Some selected TV Time files could not be copied safely. The incomplete extraction was not analyzed.",
            "cancelled" => "Recovery was cancelled. Incomplete output was preserved.",
            _ => "The helper reported a failure without a more specific supported explanation. No completed report was accepted.",
        };
        var phaseLabel = phase switch
        {
            HelperRecoveryPhase.BackupValidation => "backup validation",
            HelperRecoveryPhase.Unlocking => "encrypted backup recovery",
            HelperRecoveryPhase.Acquisition => "source validation and acquisition",
            HelperRecoveryPhase.Extraction => "selected-file extraction",
            HelperRecoveryPhase.Analysis => "data analysis",
            HelperRecoveryPhase.Report => "report creation",
            _ => "private recovery",
        };
        var diagnostic = code switch
        {
            "backup_unencrypted" or "backup_unfinished" or "backup_password_rejected" or "app_data_missing" => RecoveryDiagnostic.BackupRejected,
            "cancelled" => RecoveryDiagnostic.RecoveryCancelled,
            _ => RecoveryDiagnostic.LocalHelperError,
        };
        return new RecoveryUserException($"{explanation} Last phase: {phaseLabel}.", diagnostic);
    }
}
