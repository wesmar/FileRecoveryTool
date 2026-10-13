// Scan worker, cancellation and progress delivery.

#include "gui/RecoveryApplication.h"
#include <algorithm>

namespace KVC {

// Initiate a new scan operation.
void RecoveryApplication::OnStartScan() {
    if (m_isScanning || m_isRecovering || m_isSorting) return;

    int idx = static_cast<int>(SendMessage(m_hwndDriveCombo, CB_GETCURSEL, 0, 0));
    if (idx == CB_ERR) {
        MessageBoxW(m_hwnd, L"Please select a drive to scan", L"No Drive Selected", MB_OK | MB_ICONWARNING);
        return;
    }

    if (idx < 0 || static_cast<size_t>(idx) >= m_volumePaths.size()) return;
    m_lastScannedVolume = m_volumePaths[static_cast<size_t>(idx)];

    wchar_t buffer[MAX_PATH];
    GetWindowTextW(m_hwndFolderEdit, buffer, MAX_PATH);
    std::wstring folderFilter = buffer;          // Folder filter input

    GetWindowTextW(m_hwndFilenameEdit, buffer, MAX_PATH);
    std::wstring filenameFilter = buffer;        // Filename filter input

    bool enableMft = (SendMessage(m_hwndCheckMft, BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool enableUsn = (SendMessage(m_hwndCheckUsn, BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool enableCarving = (SendMessage(m_hwndCheckCarving, BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool rawMode = (SendMessage(m_hwndCheckRaw, BM_GETCHECK, 0, 0) == BST_CHECKED);
    if (!enableMft && !enableUsn && !enableCarving && !rawMode) {
        MessageBoxW(m_hwnd, L"Please select at least one scan mode", L"No Scan Mode Selected", MB_OK | MB_ICONWARNING);
        return;
    }

    m_deletedFiles.clear();                      // Clear previous results
    m_filteredFiles.clear();                     // Clear filtered view
    m_displayedResultCount = 0;
    m_sortColumn = -1;
    ListView_SetItemCountEx(m_hwndListView, 0, 0);

    // Update UI for scanning state.
    ShowWindow(m_hwndScanButton, SW_HIDE);
    ShowWindow(m_hwndStopButton, SW_SHOW);
    EnableWindow(m_hwndDriveCombo, FALSE);
    EnableWindow(m_hwndCheckMft, FALSE);
    EnableWindow(m_hwndCheckUsn, FALSE);
    EnableWindow(m_hwndCheckCarving, FALSE);
    EnableWindow(m_hwndCheckRaw, FALSE);
    EnableWindow(m_hwndOpenImageButton, FALSE);
    EnableWindow(m_hwndRecoverButton, FALSE);

    m_isScanning = true;
    m_shouldStopScan = false;

    // Launch background scan thread.
    m_scanThread = std::make_unique<std::thread>([this, volume = m_lastScannedVolume, folderFilter, filenameFilter, enableMft, enableUsn, enableCarving, rawMode]() {
        StartBackgroundScan(volume, folderFilter, filenameFilter, enableMft, enableUsn, enableCarving, rawMode);
    });
}

// Signal the scan thread to stop.
void RecoveryApplication::OnStopScan() {
    m_shouldStopScan = true;                     // Cooperative cancellation flag
    UpdateStatusBar(L"Stopping scan...");
}

// Perform scan in a worker thread.
void RecoveryApplication::StartBackgroundScan(std::wstring volume, std::wstring folderFilter,
                                               std::wstring filenameFilter, bool enableMft,
                                               bool enableUsn, bool enableCarving, bool rawMode) {
    auto onProgress = [this](const std::wstring& status, float progress) {
        PostProgress(status, progress);
    };

    auto onFile = [this](const DeletedFileEntry& file) {
        {
            std::lock_guard<std::mutex> lock(m_filesMutex); // Protect shared results
            m_deletedFiles.push_back(file);   // Append discovered file
        }
        if (!m_resultsPosted.exchange(true)) PostMessage(m_hwnd, WM_SCAN_FILE_FOUND, 0, 0);
    };

    bool success = false;
    try { success = m_forensicsCore->StartScan(
        volume,
        folderFilter,
        filenameFilter,
        onFile,
        onProgress,
        m_shouldStopScan,                           // Cancellation flag
        enableMft,
        enableUsn,
        enableCarving,
        rawMode
    ); } catch (const std::exception&) { PostProgress(L"Scan failed while reading the volume", -1.0f); }

    // Notify UI that scan has completed.
    PostMessage(m_hwnd, WM_SCAN_COMPLETE, success ? 1 : 0, 0);
}

// Update text displayed in the status bar.
void RecoveryApplication::UpdateStatusBar(const std::wstring& text) {
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)text.c_str());
}

void RecoveryApplication::PostProgress(const std::wstring& text, float progress) {
    std::lock_guard<std::mutex> lock(m_progressMutex);
    m_pendingStatus = text;
    m_pendingProgress = progress >= 0.0f ? std::clamp(static_cast<int>(progress * 100), 0, 100) : -1;
    if (!m_progressPosted.exchange(true)) PostMessage(m_hwnd, WM_SCAN_PROGRESS, 0, 0);
}

void RecoveryApplication::OnScanComplete(bool success) {
    // Restore UI state after scan completes.
    ShowWindow(m_hwndScanButton, SW_SHOW);
    ShowWindow(m_hwndStopButton, SW_HIDE);
    EnableWindow(m_hwndDriveCombo, TRUE);
    EnableWindow(m_hwndCheckMft, TRUE);
    EnableWindow(m_hwndCheckUsn, TRUE);
    EnableWindow(m_hwndCheckCarving, TRUE);
    EnableWindow(m_hwndCheckRaw, TRUE);
    EnableWindow(m_hwndOpenImageButton, TRUE);
    m_isScanning = false;
    EnableWindow(m_hwndRecoverButton, TRUE);

    if (m_scanThread && m_scanThread->joinable()) {
        m_scanThread->join();
    }
    {
        std::wstring finalMsg = success ? L"Scan Completed Successfully" : L"Scan Stopped or Failed";
        finalMsg += L"          |          💡 TIP: Use Shift/Ctrl+Arrows to select, Ctrl+A for All";
        UpdateStatusBar(finalMsg);
    }

    PopulateResultsList();
}

} // namespace KVC
