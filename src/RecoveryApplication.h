// ============================================================================
// RecoveryApplication.h - Main GUI Application
// ============================================================================
// Manages the Windows GUI interface, user interactions, and coordinates
// the scanning and recovery operations.
// Implements multi-threaded scanning
// with responsive UI and progress reporting.
// ============================================================================

#pragma once

#define NOMINMAX
#include <Windows.h>
#include <CommCtrl.h>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <chrono>
#include "DiskForensicsCore.h"

namespace KVC {
    class RecoveryEngine;
}

namespace KVC {

class RecoveryApplication {
public:
    explicit RecoveryApplication(HINSTANCE hInstance);
    ~RecoveryApplication();

    bool Initialize();
    int Run(int nShowCmd);

private:
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam);

    void CreateMainWindow();
    void CreateControls();
    void SetupListView();
    
    void OnMenuCommand(WORD menuId);
    void OnStartScan();
    void OnStopScan();
    void OnBrowseFolderInput();
    void OnRecoverSelected();
    void OnExportCSV();
    void OnAbout();
    void OnExit();
    void OnSize(WORD width, WORD height);
    void OnColumnClick(LPNMLISTVIEW pnmv);
    void OnListViewRightClick(LPNMITEMACTIVATE pnmitem);

    void StartBackgroundScan(wchar_t driveLetter, std::wstring folderFilter, 
                            std::wstring filenameFilter, bool enableMft, 
                            bool enableUsn, bool enableCarving);
    void UpdateScanStatus(const std::wstring& status);
    void PopulateResultsList();
    void FilterResults();
    bool IsFileOfType(const std::wstring& name, int typeIndex);
    void RecoverFile(const DeletedFileEntry& file);
    void RecoverMultipleFiles(const std::vector<DeletedFileEntry>& files);
    void RecoverHighlightedFiles();
    std::wstring FormatFileSize(uint64_t bytes);
    void UpdateStatusBar(const std::wstring& text);
    void ShowError(const std::wstring& message);

    HINSTANCE m_hInstance;
    HWND m_hwnd;
    HWND m_hwndDriveCombo;
    HWND m_hwndFolderEdit;
    HWND m_hwndFilenameEdit;
    HWND m_hwndListView;
    HWND m_hwndBrowseFolderButton;
    HWND m_hwndStatusBar;
    HWND m_hwndProgress;
    HWND m_hwndScanButton;
    HWND m_hwndStopButton;
    HWND m_hwndCheckMft;
    HWND m_hwndCheckUsn;
    HWND m_hwndCheckCarving;

    std::unique_ptr<std::thread> m_scanThread;
    std::atomic<bool> m_isScanning;
    std::atomic<bool> m_shouldStopScan;
    std::mutex m_filesMutex;
    
    // Data storage
    std::vector<DeletedFileEntry> m_deletedFiles;  // Raw scan results
    std::vector<DeletedFileEntry> m_filteredFiles; // Currently displayed results
    
    std::wstring m_scanStatus;
    std::wstring m_filterText;
    std::wstring m_filterType;

    std::unique_ptr<DiskForensicsCore> m_forensicsCore;
    std::unique_ptr<RecoveryEngine> m_recoveryEngine;
    ScanConfiguration m_config;
    
    wchar_t m_lastScannedDrive; // Remember which drive was scanned

    // Sorting state
    int m_sortColumn = -1;
    // -1 means no sorting
    bool m_sortAscending = true;

    static constexpr int LISTVIEW_ID = 1001;
    static constexpr int SCAN_BUTTON_ID = 1002;
    static constexpr int STOP_BUTTON_ID = 1003;
    static constexpr int DRIVE_COMBO_ID = 1004;
    static constexpr int FOLDER_EDIT_ID = 1005;
    static constexpr int FILENAME_EDIT_ID = 1006;
    static constexpr int PROGRESS_ID = 1007;
    static constexpr int FILTER_EDIT_ID = 1008;
    static constexpr int TYPE_COMBO_ID = 1009;
    static constexpr int GROUP_SCAN_ID = 1010;
    static constexpr int GROUP_FILTER_ID = 1011;
    static constexpr int CHECK_MFT_ID = 1012;
    static constexpr int CHECK_USN_ID = 1013;
    static constexpr int CHECK_CARVING_ID = 1014;
    static constexpr int BROWSE_FOLDER_BTN_ID = 1015;
    static constexpr int ID_CONTEXT_SAVE_AS = 40020;
	static constexpr int ID_EDIT_SELECTALL = 40021;

    static constexpr UINT WM_SCAN_PROGRESS = WM_APP + 1;
    static constexpr UINT WM_SCAN_FILE_FOUND = WM_APP + 2;
    static constexpr UINT WM_SCAN_COMPLETE = WM_APP + 3;
    static constexpr UINT WM_RECOVERY_COMPLETE = WM_APP + 4;
    static constexpr UINT WM_SORT_COMPLETE = WM_APP + 5;
};
} // namespace KVC
