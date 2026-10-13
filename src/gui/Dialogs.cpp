// File pickers, CSV export and application information.

#include "gui/RecoveryApplication.h"
#include "recovery/CsvExport.h"
#include "recovery/RecoveryEngine.h"
#include "resources/resource.h"
#include <commdlg.h>
#include <shlobj.h>

namespace KVC {

namespace {

// About dialog message procedure.
INT_PTR CALLBACK AboutDialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    UNREFERENCED_PARAMETER(lParam);             // lParam not used in this dialog
    switch (msg) {
    case WM_INITDIALOG:
        return TRUE;                            // Dialog initialized successfully
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));    // Close dialog on OK or Cancel
            return TRUE;
        }
        break;
    case WM_CLOSE:
        EndDialog(hDlg, IDCANCEL);              // Close dialog when window is closed
        return TRUE;
    }
    return FALSE;                               // Message not handled
}

} // namespace

void RecoveryApplication::OnOpenImage() {
    if (m_isScanning || m_isRecovering || m_isSorting) return;
    wchar_t path[32768]{};
    OPENFILENAMEW dialog{sizeof(dialog)};
    dialog.hwndOwner = m_hwnd;
    dialog.lpstrFilter = L"Flat disk images (*.img;*.dd;*.raw;*.bin)\0*.img;*.dd;*.raw;*.bin\0All files\0*.*\0";
    dialog.lpstrFile = path;
    dialog.nMaxFile = static_cast<DWORD>(std::size(path));
    dialog.lpstrTitle = L"Open a flat image (VHD/VHDX containers must be mounted first)";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&dialog)) return;
    const auto index = SendMessageW(m_hwndDriveCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(path));
    if (index == CB_ERR || index == CB_ERRSPACE) return;
    m_volumePaths.emplace_back(path);
    SendMessageW(m_hwndDriveCombo, CB_SETCURSEL, index, 0);
    SendMessageW(m_hwndCheckRaw, BM_SETCHECK, BST_CHECKED, 0);
    OnCommand(MAKEWPARAM(CHECK_RAW_ID, BN_CLICKED), reinterpret_cast<LPARAM>(m_hwndCheckRaw));
    UpdateStatusBar(L"Flat image selected. RAW scans all bytes; original names and deletion state are unavailable.");
}

// Export filtered results to a CSV file.
void RecoveryApplication::OnExportCSV() {
    OPENFILENAME ofn = {};
    wchar_t fileName[MAX_PATH] = L"recovered_files.csv";
    ofn.lStructSize = sizeof(OPENFILENAME);
    ofn.hwndOwner = m_hwnd;
    ofn.lpstrFilter = L"CSV Files (*.csv)\0*.csv\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = L"csv";

    if (GetSaveFileName(&ofn)) {
        if (!RecoveryEngine::ValidateDestination(m_lastScannedVolume, fileName)) {
            MessageBoxW(m_hwnd, L"Save the report outside the source disk. The input image must not be overwritten.", L"Invalid destination", MB_OK | MB_ICONERROR);
            return;
        }
        std::vector<DeletedFileEntry> snapshot;
        {
            std::lock_guard<std::mutex> lock(m_filesMutex);
            snapshot = m_filteredFiles;
        }
        if (ExportCandidatesToCsv(fileName, snapshot)) {
            MessageBoxW(m_hwnd, L"CSV export completed successfully", L"Export Complete", MB_OK | MB_ICONINFORMATION);
        } else {
            MessageBoxW(m_hwnd, L"The CSV file could not be written", L"Export Failed", MB_OK | MB_ICONERROR);
        }
    }
}
// Display the About dialog.
void RecoveryApplication::OnAbout() {
    DialogBox(m_hInstance, MAKEINTRESOURCE(IDD_ABOUTBOX), m_hwnd, AboutDialogProc);
}

// Both folder operations share the WinRE-compatible picker.
std::wstring RecoveryApplication::SelectFolder(const wchar_t* title, const wchar_t* recoveryEnvironmentTitle, bool allowCreate) {
    wchar_t path[MAX_PATH]{};
    if (IsWinRE()) {
        OPENFILENAMEW dialog{sizeof(dialog)};
        dialog.hwndOwner = m_hwnd;
        dialog.lpstrFilter = L"All files\0*.*\0";
        dialog.lpstrFile = path;
        dialog.nMaxFile = MAX_PATH;
        dialog.lpstrTitle = recoveryEnvironmentTitle;
        dialog.Flags = OFN_NOCHANGEDIR | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_DONTADDTORECENT;
        if (!GetOpenFileNameW(&dialog)) return {};
        const std::wstring file(path);
        const auto slash = file.find_last_of(L'\\');
        return slash == std::wstring::npos ? std::wstring{} : file.substr(0, slash + 1);
    }
    BROWSEINFOW browse{};
    browse.hwndOwner = m_hwnd;
    browse.lpszTitle = title;
    browse.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | (allowCreate ? 0 : BIF_NONEWFOLDERBUTTON);
    LPITEMIDLIST id = SHBrowseForFolderW(&browse);
    if (!id) return {};
    const bool selected = SHGetPathFromIDListW(id, path) != FALSE;
    CoTaskMemFree(id);
    return selected ? std::wstring(path) : std::wstring{};
}

void RecoveryApplication::OnBrowseFolderInput() {
    const auto folder = SelectFolder(L"Select folder to filter by", L"[WinRE Mode] Select any file in the target folder", false);
    if (!folder.empty()) SetWindowTextW(m_hwndFolderEdit, folder.c_str());
}

// Detect if running in Windows Recovery Environment.
bool RecoveryApplication::IsWinRE() {
    wchar_t winDir[MAX_PATH];
    GetWindowsDirectoryW(winDir, MAX_PATH);
    std::wstring checkPath = std::wstring(winDir) + L"\\System32\\winpeshl.exe";
    return (GetFileAttributesW(checkPath.c_str()) != INVALID_FILE_ATTRIBUTES);
}

} // namespace KVC
