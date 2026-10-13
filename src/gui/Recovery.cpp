// Selected-file recovery and worker completion.

#include "gui/RecoveryApplication.h"
#include "recovery/RecoveryEngine.h"

namespace KVC {

// Recover highlighted rows, consistently with the context menu and keyboard.
void RecoveryApplication::OnRecoverSelected() {
    RecoverHighlightedFiles();
}

// Recover multiple files to a user-selected destination.
void RecoveryApplication::RecoverMultipleFiles(const std::vector<DeletedFileEntry>& files) {
    if (m_isScanning || m_isRecovering || m_isSorting || files.empty()) return;
    const std::wstring destFolder = SelectFolder(L"Select destination folder for recovered files",
        L"[WinRE Mode] Select any file inside the destination folder", true);

    if (!destFolder.empty()) {
        if (!RecoveryEngine::ValidateDestination(m_lastScannedVolume, destFolder)) {
            MessageBoxW(m_hwnd,
                L"Cannot recover to the source drive!\n\n"
                L"Please select a folder on a different physical disk or a network share.\n\n"
                L"Recovering to the same drive may overwrite deleted data.",
                L"Invalid Destination",
                MB_OK | MB_ICONERROR);
            return;
        }

        // Disable UI during recovery.
        EnableWindow(m_hwndScanButton, FALSE);
        EnableWindow(m_hwndStopButton, FALSE);
        EnableWindow(m_hwndListView, FALSE);
        EnableWindow(m_hwndDriveCombo, FALSE);
        EnableWindow(m_hwndOpenImageButton, FALSE);

        UpdateStatusBar(L"Recovering files... Please wait.");

        m_isRecovering = true;
        EnableWindow(m_hwndRecoverButton, FALSE);
        m_recoveryThread = std::make_unique<std::thread>([this, files, destFolder]() {
            PostProgress(L"Recovering files...", 0.0f);

            RecoveryEngine::Outcome outcome;
            try {
                outcome = m_recoveryEngine->RecoverMultipleFiles(
                files,
                m_lastScannedVolume,
                destFolder,
                [this](const std::wstring& msg, float progress) {
                    PostProgress(msg, progress);
                }
            );
            } catch (const std::exception&) {
                outcome.failed = static_cast<int>(files.size());
            }
            const bool success = outcome.recovered + outcome.damaged > 0;

            if (success) {
                wchar_t msg[768];
                swprintf_s(msg, L"Recovery finished: %d recovered, %d with unreadable parts, %d failed, %d without data.\n\nCheck folder:\n%s",
                           outcome.recovered, outcome.damaged, outcome.failed, outcome.skipped, destFolder.c_str());
                m_recoveryMessage = msg;
            } else {
                m_recoveryMessage = L"Recovery failed. Check the status bar for details.";
            }
            PostMessage(m_hwnd, WM_RECOVERY_COMPLETE, success ? 1 : 0, 0);
        });
    }
}

// Recover files selected via standard selection (not checkboxes).
void RecoveryApplication::RecoverHighlightedFiles() {
    std::vector<DeletedFileEntry> filesToRecover;

    int iPos = ListView_GetNextItem(m_hwndListView, -1, LVNI_SELECTED);
    while (iPos != -1) {
        std::lock_guard<std::mutex> lock(m_filesMutex);
        if (iPos < static_cast<int>(m_filteredFiles.size())) {
            filesToRecover.push_back(m_filteredFiles[iPos]);
        }
        iPos = ListView_GetNextItem(m_hwndListView, iPos, LVNI_SELECTED);
    }

    if (filesToRecover.empty()) {
        MessageBoxW(m_hwnd, L"No files selected", L"Info", MB_OK | MB_ICONINFORMATION);
        return;
    }

    RecoverMultipleFiles(filesToRecover);
}

void RecoveryApplication::OnRecoveryComplete(bool success) {
    if (m_recoveryThread && m_recoveryThread->joinable()) m_recoveryThread->join();
    m_isRecovering = false;
    EnableWindow(m_hwndRecoverButton, TRUE);
    // Re-enable UI after recovery operation.
    EnableWindow(m_hwndScanButton, TRUE);
    EnableWindow(m_hwndListView, TRUE);
    EnableWindow(m_hwndDriveCombo, TRUE);
    EnableWindow(m_hwndCheckMft, TRUE);
    EnableWindow(m_hwndCheckUsn, TRUE);
    EnableWindow(m_hwndCheckCarving, TRUE);
    EnableWindow(m_hwndCheckRaw, TRUE);
    EnableWindow(m_hwndOpenImageButton, TRUE);
    UpdateStatusBar(success ? L"Recovery Completed" : L"Recovery Failed");
    MessageBoxW(m_hwnd, m_recoveryMessage.c_str(), L"Recovery complete", MB_OK | (success ? MB_ICONINFORMATION : MB_ICONERROR));
}

} // namespace KVC
