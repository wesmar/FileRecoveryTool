// Control and menu command dispatch.

#include "gui/RecoveryApplication.h"
#include "resources/resource.h"

namespace KVC {

void RecoveryApplication::OnCommand(WPARAM wParam, LPARAM lParam) {
    // Handle button clicks.
    if (lParam != 0 && HIWORD(wParam) == BN_CLICKED) {
        const WORD id = LOWORD(wParam);
        if (id == CHECK_RAW_ID && SendMessage(m_hwndCheckRaw, BM_GETCHECK, 0, 0) == BST_CHECKED) {
            for (HWND method : {m_hwndCheckMft, m_hwndCheckUsn, m_hwndCheckCarving}) SendMessage(method, BM_SETCHECK, BST_UNCHECKED, 0);
        } else if (id == CHECK_MFT_ID || id == CHECK_USN_ID || id == CHECK_CARVING_ID) {
            SendMessage(m_hwndCheckRaw, BM_SETCHECK, BST_UNCHECKED, 0);
        }
        switch (LOWORD(wParam)) {
        case OPEN_IMAGE_ID:
            OnOpenImage();
            break;
        case SCAN_BUTTON_ID:
            OnStartScan();                  // Start new scan
            break;
        case STOP_BUTTON_ID:
            OnStopScan();                   // Stop running scan
            break;
        case RECOVER_BUTTON_ID:
            OnRecoverSelected();
            break;
        case CHECK_USN_ID:
            // Ensure MFT is enabled when USN is selected.
            if (SendMessage(m_hwndCheckUsn, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                if (SendMessage(m_hwndCheckMft, BM_GETCHECK, 0, 0) == BST_UNCHECKED) {
                    SendMessage(m_hwndCheckMft, BM_SETCHECK, BST_CHECKED, 0);
                }
            }
            break;
        case CHECK_MFT_ID:
            // Disable USN if MFT is unchecked.
            if (SendMessage(m_hwndCheckMft, BM_GETCHECK, 0, 0) == BST_UNCHECKED) {
                if (SendMessage(m_hwndCheckUsn, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                    SendMessage(m_hwndCheckUsn, BM_SETCHECK, BST_UNCHECKED, 0);
                }
            }
            break;
        case BROWSE_FOLDER_BTN_ID:
            OnBrowseFolderInput();          // Browse for folder filter
            break;
        }
    }
    else if (lParam != 0 && LOWORD(wParam) == DRIVE_COMBO_ID && HIWORD(wParam) == CBN_SELCHANGE) {
        const auto index = SendMessageW(m_hwndDriveCombo, CB_GETCURSEL, 0, 0);
        if (index >= 0 && static_cast<size_t>(index) < m_volumePaths.size() &&
            m_volumePaths[static_cast<size_t>(index)].rfind(L"\\\\.\\PhysicalDrive", 0) == 0) {
            SendMessageW(m_hwndCheckRaw, BM_SETCHECK, BST_CHECKED, 0);
            OnCommand(MAKEWPARAM(CHECK_RAW_ID, BN_CLICKED), reinterpret_cast<LPARAM>(m_hwndCheckRaw));
            UpdateStatusBar(L"Whole disk selected. RAW scans all bytes, including live files and partition metadata.");
        }
    }
    // Handle filter type changes.
    else if (lParam != 0 && LOWORD(wParam) == TYPE_COMBO_ID) {
        if (HIWORD(wParam) == CBN_SELCHANGE) {
            FilterResults();                // Re-apply result filtering
        }
    }
    // Handle search text changes.
    else if (lParam != 0 && LOWORD(wParam) == FILTER_EDIT_ID) {
        if (HIWORD(wParam) == EN_CHANGE) {
            FilterResults();                // Re-apply result filtering
        }
    }
    // Handle menu commands.
    else if (lParam == 0 && (HIWORD(wParam) == 0 || HIWORD(wParam) == 1)) {
        OnMenuCommand(LOWORD(wParam));
    }
}

// Handle menu commands.
void RecoveryApplication::OnMenuCommand(WORD menuId) {
    switch (menuId) {
    case ID_FILE_EXIT:
        OnExit();                                // Exit application
        break;
    case ID_SCAN_START:
        OnStartScan();                           // Start scan from menu
        break;
    case ID_SCAN_STOP:
        OnStopScan();                            // Stop scan from menu
        break;
    case ID_RECOVERY_RECOVERSELECTED:
        OnRecoverSelected();                     // Recover selected files
        break;
    case ID_RECOVERY_RECOVERALL:
        {
            std::vector<DeletedFileEntry> files;
            { std::lock_guard<std::mutex> lock(m_filesMutex); files = m_filteredFiles; }
            RecoverMultipleFiles(files);
        }
        break;
    case ID_FILE_EXPORTCSV:
        OnExportCSV();                           // Export results to CSV
        break;
    case ID_HELP_ABOUT:
        OnAbout();                               // Show About dialog
        break;
    case ID_CONTEXT_SAVE_AS:
        RecoverHighlightedFiles();               // Recover files via context menu
        break;
    case ID_EDIT_SELECTALL:
        ListView_SetItemState(m_hwndListView, -1, LVIS_SELECTED, LVIS_SELECTED); // Select all items
        SetFocus(m_hwndListView);
        break;
    }
}

} // namespace KVC
