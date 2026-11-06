using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Windowing;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.System;
using WinRT.Interop;

namespace TVTimeRecovery.Windows;

public sealed partial class MainWindow : Window
{
    private string? _backupPath;
    private string _sourceKind = "ios_encrypted_backup";
    private CancellationTokenSource? _cancellation;
    private Task? _activeRecovery;
    private ValidatedRecoveryOutput? _completedOutput;
    private bool _closePending;
    private bool _allowClose;
    private readonly RecoveryProgressEpoch _progressEpoch = new();

    public MainWindow()
    {
        InitializeComponent();
        SourceKind.SelectedIndex = 0;
        AppWindow.Closing += Window_Closing;
    }

    private async void Window_Closing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        var activeRecovery = _activeRecovery;
        if (_allowClose || activeRecovery is null)
        {
            ClearCompletedOutput();
            return;
        }

        args.Cancel = true;
        if (_closePending) return;
        _closePending = true;
        _progressEpoch.CancelCurrent();
        _cancellation?.Cancel();
        try
        {
            await activeRecovery;
        }
        finally
        {
            ClearCompletedOutput();
            _allowClose = true;
            Close();
        }
    }

    private async void SelectBackup_Click(object sender, RoutedEventArgs e)
    {
        IStorageItem? selectedItem;
        if (_sourceKind is "ios_encrypted_backup" or "android_preserved_snapshot")
        {
            var picker = new FolderPicker();
            picker.FileTypeFilter.Add("*");
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(this));
            selectedItem = await picker.PickSingleFolderAsync();
        }
        else
        {
            var picker = new FileOpenPicker();
            picker.FileTypeFilter.Add("*");
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(this));
            selectedItem = await picker.PickSingleFileAsync();
        }
        if (selectedItem is null) return;
        _backupPath = selectedItem.Path;
        SelectionStatus.Text = "Private local source selected";
        RecoverButton.IsEnabled = true;
        StatusBar.Title = "Source selected";
        StatusBar.Message = "The app will validate the selected source before accepting any completed report.";
    }

    private void SourceKind_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (SourceKind.SelectedItem is not ComboBoxItem item || item.Tag is not string kind) return;
        _sourceKind = kind;
        _backupPath = null;
        ClearCompletedOutput();
        ResultActions.Visibility = Visibility.Collapsed;
        SelectionStatus.Text = "No source selected";
        RecoverButton.IsEnabled = false;
        SelectBackupButton.Content = kind switch
        {
            "ios_encrypted_backup" => "Select encrypted iOS backup folder",
            "android_preserved_snapshot" => "Select preserved Android database folder",
            "android_legacy_backup" => "Select Android backup file",
            _ => "Select official TV Time export",
        };
        BackupPassword.Header = kind == "ios_encrypted_backup"
            ? "Encrypted local-backup password"
            : "Export password (only if the ZIP is encrypted)";
        BackupPassword.IsEnabled = kind is "ios_encrypted_backup" or "tvtime_official_export";
        BackupPassword.Password = string.Empty;
    }

    private async void Recover_Click(object sender, RoutedEventArgs e)
    {
        var backupPath = _backupPath;
        if (backupPath is null ||
            SensitiveConfirmation.IsChecked != true ||
            (_sourceKind == "ios_encrypted_backup" && BackupPassword.Password.Length == 0))
        {
            StatusBar.Severity = InfoBarSeverity.Warning;
            StatusBar.Title = "Confirmation required";
            StatusBar.Message = "Complete the required source password and sensitive-output confirmation.";
            return;
        }

        if (_activeRecovery is not null) return;
        var sourceKind = _sourceKind;
        var password = BackupPassword.Password;
        BackupPassword.Password = string.Empty;
        var activeRecovery = RunRecoveryAsync(sourceKind, backupPath, password);
        _activeRecovery = activeRecovery;
        try
        {
            await activeRecovery;
        }
        finally
        {
            if (ReferenceEquals(_activeRecovery, activeRecovery)) _activeRecovery = null;
        }
    }

    private async Task RunRecoveryAsync(string sourceKind, string backupPath, string password)
    {
        RecoverButton.IsEnabled = false;
        SelectBackupButton.IsEnabled = false;
        SourceKind.IsEnabled = false;
        BackupPassword.IsEnabled = false;
        SensitiveConfirmation.IsEnabled = false;
        CancelButton.IsEnabled = true;
        ClearCompletedOutput();
        ResultActions.Visibility = Visibility.Collapsed;
        _cancellation = new CancellationTokenSource();
        var helperMayHaveStarted = false;
        var operation = _progressEpoch.Begin();
        try
        {
            var protectionConsent = new ContentDialog
            {
                XamlRoot = Content.XamlRoot,
                Title = "Check Windows drive protection?",
                Content = "Windows will ask permission to check drive protection. Only this read-only status check uses administrator access. The recovery app and backup helper stay at ordinary user access.",
                PrimaryButtonText = "Check protection",
                CloseButtonText = "Cancel",
                DefaultButton = ContentDialogButton.Close,
            };
            ContentDialogResult consent;
            using (var registration = _cancellation.Token.Register(() =>
                DispatcherQueue.TryEnqueue(() => protectionConsent.Hide())))
            {
                consent = await protectionConsent.ShowAsync();
            }
            _cancellation.Token.ThrowIfCancellationRequested();
            if (consent != ContentDialogResult.Primary)
                throw new OperationCanceledException();
            StatusBar.Title = "Checking drive protection";
            StatusBar.Message = "Verifying protection before creating private recovery output.";
            var outputParent = await PrivateRecoveryStore.RequireEncryptedParentAsync(_cancellation.Token);
            _cancellation.Token.ThrowIfCancellationRequested();
            var output = PrivateRecoveryStore.FreshOutput(outputParent);
            var recovery = new RecoveryCoordinator();
            helperMayHaveStarted = true;
            _completedOutput = await recovery.RecoverAsync(
                sourceKind,
                backupPath,
                output,
                password,
                progress => DispatcherQueue.TryEnqueue(() =>
                {
                    if (!_progressEpoch.IsCurrent(operation)) return;
                    StatusBar.Severity = InfoBarSeverity.Informational;
                    StatusBar.Title = "Recovery in progress";
                    StatusBar.Message = progress;
                }),
                _cancellation.Token);
            _progressEpoch.End(operation);
            ResultActions.Visibility = Visibility.Visible;
            StatusBar.Severity = InfoBarSeverity.Success;
            StatusBar.Title = "Recovery complete";
            StatusBar.Message = "The private Markdown and offline HTML reports are ready in app-managed storage.";
            RecoveryDiagnostics.Record(RecoveryDiagnostic.RecoveryCompleted);
        }
        catch (OperationCanceledException)
        {
            _progressEpoch.End(operation);
            StatusBar.Severity = InfoBarSeverity.Warning;
            StatusBar.Title = "Recovery cancelled";
            StatusBar.Message = helperMayHaveStarted
                ? "Incomplete output was preserved. Start again with a fresh private folder."
                : "No recovery was started.";
            RecoveryDiagnostics.Record(RecoveryDiagnostic.RecoveryCancelled);
        }
        catch (RecoveryUserException error)
        {
            _progressEpoch.End(operation);
            StatusBar.Severity = InfoBarSeverity.Error;
            StatusBar.Title = "Recovery stopped safely";
            StatusBar.Message = error.SafeMessage;
            RecoveryDiagnostics.Record(error.Diagnostic);
        }
        catch
        {
            _progressEpoch.End(operation);
            StatusBar.Severity = InfoBarSeverity.Error;
            StatusBar.Title = "Recovery stopped safely";
            StatusBar.Message = "No completed report was accepted. The source backup was not intentionally modified.";
            RecoveryDiagnostics.Record(RecoveryDiagnostic.UnrecognizedFailure);
        }
        finally
        {
            _progressEpoch.End(operation);
            _cancellation?.Dispose();
            _cancellation = null;
            CancelButton.IsEnabled = false;
            SelectBackupButton.IsEnabled = true;
            SourceKind.IsEnabled = true;
            BackupPassword.IsEnabled = _sourceKind is "ios_encrypted_backup" or "tvtime_official_export";
            SensitiveConfirmation.IsEnabled = true;
            RecoverButton.IsEnabled = _backupPath is not null;
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        _progressEpoch.CancelCurrent();
        _cancellation?.Cancel();
    }

    private void ClearCompletedOutput()
    {
        _completedOutput?.Dispose();
        _completedOutput = null;
    }

    private async void OpenMarkdown_Click(object sender, RoutedEventArgs e)
    {
        if (_completedOutput is null) return;
        await LaunchValidatedOutputAsync(output => output.MarkdownReport);
    }

    private async void OpenHtml_Click(object sender, RoutedEventArgs e)
    {
        if (_completedOutput is null) return;
        await LaunchValidatedOutputAsync(output => output.HtmlReport);
    }

    private async void RevealOutput_Click(object sender, RoutedEventArgs e)
    {
        if (_completedOutput is null) return;
        try
        {
            using var validated = RecoveryOutputValidator.ValidateCompletedOutput(
                _completedOutput.OutputRoot);
            var folder = await StorageFolder.GetFolderFromPathAsync(validated.OutputRoot);
            if (!await Launcher.LaunchFolderAsync(folder)) throw new InvalidOperationException();
        }
        catch
        {
            ShowOpenFailure();
        }
    }

    private async Task LaunchValidatedOutputAsync(Func<ValidatedRecoveryOutput, string> selectedPath)
    {
        if (_completedOutput is null) return;
        try
        {
            using var validated = RecoveryOutputValidator.ValidateCompletedOutput(
                _completedOutput.OutputRoot);
            await LaunchPrivateFileAsync(selectedPath(validated));
        }
        catch
        {
            ShowOpenFailure();
        }
    }

    private async Task LaunchPrivateFileAsync(string path)
    {
        try
        {
            var file = await StorageFile.GetFileFromPathAsync(path);
            if (!await Launcher.LaunchFileAsync(file)) throw new InvalidOperationException();
        }
        catch
        {
            throw new InvalidOperationException();
        }
    }

    private void ShowOpenFailure()
    {
        StatusBar.Severity = InfoBarSeverity.Warning;
        StatusBar.Title = "Private report retained";
        StatusBar.Message = "Windows could not open the validated private result. The recovery was not deleted.";
    }
}
