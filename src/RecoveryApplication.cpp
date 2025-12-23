// RecoveryApplication.cpp
// Main GUI application implementation for the recovery tool.

#include "RecoveryApplication.h"
#include "RecoveryEngine.h"
#include "StringUtils.h"
#include "resource.h"

#include <climits>
#include <CommCtrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <cwctype>

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

namespace KVC {

// Construct application instance and initialize core components.
RecoveryApplication::RecoveryApplication(HINSTANCE hInstance)
    : m_hInstance(hInstance)
    , m_hwnd(nullptr)
    , m_hwndDriveCombo(nullptr)
    , m_hwndFolderEdit(nullptr)
    , m_hwndFilenameEdit(nullptr)
    , m_hwndListView(nullptr)
    , m_hwndStatusBar(nullptr)
    , m_hwndProgress(nullptr)
    , m_hwndScanButton(nullptr)
    , m_hwndStopButton(nullptr)
    , m_hwndCheckMft(nullptr)
    , m_hwndCheckUsn(nullptr)
    , m_hwndCheckCarving(nullptr)
    , m_hwndBrowseFolderButton(nullptr)
    , m_isScanning(false)
    , m_shouldStopScan(false)
    , m_lastScannedDrive(L'C')                  // Default drive selection
{
    m_forensicsCore = std::make_unique<DiskForensicsCore>();   // Low-level disk scanner
    m_recoveryEngine = std::make_unique<RecoveryEngine>();    // File recovery engine
    m_config = ScanConfiguration::Load();       // Load persisted scan configuration
}

// Ensure background scan thread is stopped on destruction.
RecoveryApplication::~RecoveryApplication() {
    if (m_scanThread && m_scanThread->joinable()) {
        m_shouldStopScan = true;                 // Signal scan thread to stop
        m_scanThread->join();                    // Wait for thread termination
    }
}

// Register window class and create main application window.
bool RecoveryApplication::Initialize() {
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_HREDRAW | CS_VREDRAW;          // Redraw on horizontal/vertical resize
    wc.lpfnWndProc = WindowProc;                 // Static window procedure
    wc.hInstance = m_hInstance;
    wc.hIcon = LoadIcon(m_hInstance, MAKEINTRESOURCE(IDI_MAINICON));
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszMenuName = MAKEINTRESOURCE(IDR_MAINMENU);
    wc.lpszClassName = L"KVCRecoveryWindowClass";
    wc.hIconSm = LoadIcon(m_hInstance, MAKEINTRESOURCE(IDI_MAINICON));

    if (!RegisterClassExW(&wc)) {
        return false;                           // Window class registration failed
    }

    CreateMainWindow();                          // Create main window instance
    return m_hwnd != nullptr;                   // Return success if window exists
}

// Create the main top-level window.
void RecoveryApplication::CreateMainWindow() {
    m_hwnd = CreateWindowExW(
        0,
        L"KVCRecoveryWindowClass",
        L"KVC File Recovery - Professional Data Salvage Tool (CLI: use --help)",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        1200, 600,
        nullptr,
        nullptr,
        m_hInstance,
        this                                   // Pass application pointer to WM_NCCREATE
    );

    if (!m_hwnd) {
        return;                                // Abort if window creation failed
    }

    CreateControls();                           // Initialize child controls
}

// Create and layout all child controls.
void RecoveryApplication::CreateControls() {
    HFONT hFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI"); // UI font

    // Scan configuration group box.
    HWND hGroupBox = CreateWindowExW(0, L"BUTTON", L"Scan Configuration",
        WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
        20, 20, 1140, 150, m_hwnd, 
        reinterpret_cast<HMENU>(static_cast<UINT_PTR>(GROUP_SCAN_ID)), 
        m_hInstance, nullptr);
    SendMessage(hGroupBox, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Drive letter label.
    CreateWindowExW(0, L"STATIC", L"Drive Letter:",
        WS_VISIBLE | WS_CHILD,
        40, 50, 100, 20, m_hwnd, nullptr, m_hInstance, nullptr);

    // Drive selection combo box.
    m_hwndDriveCombo = CreateWindowExW(0, L"COMBOBOX", nullptr,
        WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL,
        150, 48, 100, 200, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(DRIVE_COMBO_ID)), m_hInstance, nullptr);
    SendMessage(m_hwndDriveCombo, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Populate available logical drives.
    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (drives & (1 << i)) {
            wchar_t drive[3] = { static_cast<wchar_t>(L'A' + i), L':', L'\0' };
            SendMessage(m_hwndDriveCombo, CB_ADDSTRING, 0, (LPARAM)drive);
        }
    }
    SendMessage(m_hwndDriveCombo, CB_SELECTSTRING, static_cast<WPARAM>(-1), (LPARAM)L"C:"); // Default to C:

    // Folder filter label.
    CreateWindowExW(0, L"STATIC", L"Folder Filter:",
        WS_VISIBLE | WS_CHILD,
        280, 50, 100, 20, m_hwnd, nullptr, m_hInstance, nullptr);

    // Folder filter edit box.
    m_hwndFolderEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr,
        WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL,
        390, 48, 265, 24, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(FOLDER_EDIT_ID)), m_hInstance, nullptr);
    SendMessage(m_hwndFolderEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Browse folder button.
    m_hwndBrowseFolderButton = CreateWindowExW(0, L"BUTTON", L"...",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        660, 47, 30, 26, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(BROWSE_FOLDER_BTN_ID)), m_hInstance, nullptr);
    SendMessage(m_hwndBrowseFolderButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Filename filter label.
    CreateWindowExW(0, L"STATIC", L"Filename:",
        WS_VISIBLE | WS_CHILD,
        40, 85, 100, 20, m_hwnd, nullptr, m_hInstance, nullptr);

    // Filename filter edit box.
    m_hwndFilenameEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr,
        WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL,
        150, 83, 200, 24, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(FILENAME_EDIT_ID)), m_hInstance, nullptr);
    SendMessage(m_hwndFilenameEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Scan mode label.
    CreateWindowExW(0, L"STATIC", L"Scan Mode:",
        WS_VISIBLE | WS_CHILD,
        40, 120, 100, 20, m_hwnd, nullptr, m_hInstance, nullptr);

    // MFT scan checkbox.
    m_hwndCheckMft = CreateWindowExW(0, L"BUTTON", L"MFT (Ultra Fast)",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        150, 120, 140, 20, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(CHECK_MFT_ID)), m_hInstance, nullptr);
    SendMessage(m_hwndCheckMft, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hwndCheckMft, BM_SETCHECK, BST_CHECKED, 0); // Enabled by default

    // USN journal scan checkbox.
    m_hwndCheckUsn = CreateWindowExW(0, L"BUTTON", L"+ USN Journal (Fast)",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        300, 120, 180, 20, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(CHECK_USN_ID)), m_hInstance, nullptr);
    SendMessage(m_hwndCheckUsn, WM_SETFONT, (WPARAM)hFont, TRUE);

    // File carving scan checkbox.
    m_hwndCheckCarving = CreateWindowExW(0, L"BUTTON", L"+ File Carving (Slow)",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        490, 120, 170, 20, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(CHECK_CARVING_ID)), m_hInstance, nullptr);
    SendMessage(m_hwndCheckCarving, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Start scan button.
    m_hwndScanButton = CreateWindowExW(0, L"BUTTON", L"Start Scan",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        700, 115, 150, 30, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(SCAN_BUTTON_ID)), m_hInstance, nullptr);
    SendMessage(m_hwndScanButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Stop scan button (hidden initially).
    m_hwndStopButton = CreateWindowExW(0, L"BUTTON", L"Stop Scan",
        WS_CHILD | BS_PUSHBUTTON,
        870, 115, 120, 30, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(STOP_BUTTON_ID)), m_hInstance, nullptr);
    SendMessage(m_hwndStopButton, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Progress bar control.
    m_hwndProgress = CreateWindowExW(0, PROGRESS_CLASS, nullptr,
        WS_VISIBLE | WS_CHILD,
        1010, 120, 130, 20, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(PROGRESS_ID)), m_hInstance, nullptr);

    // Results filter group box.
    HWND hFilterGroup = CreateWindowExW(0, L"BUTTON", L"Results Filter",
        WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
        20, 185, 1140, 60, m_hwnd, 
        reinterpret_cast<HMENU>(static_cast<UINT_PTR>(GROUP_FILTER_ID)), 
        m_hInstance, nullptr);
    SendMessage(hFilterGroup, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Search label.
    CreateWindowExW(0, L"STATIC", L"Search:",
        WS_VISIBLE | WS_CHILD,
        40, 215, 60, 20, m_hwnd, nullptr, m_hInstance, nullptr);

    // Search filter edit box.
    HWND hFilterEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr,
        WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL,
        110, 213, 300, 24, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(FILTER_EDIT_ID)), m_hInstance, nullptr);
    SendMessage(hFilterEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

    // File type filter label.
    CreateWindowExW(0, L"STATIC", L"Type:",
        WS_VISIBLE | WS_CHILD,
        430, 215, 50, 20, m_hwnd, nullptr, m_hInstance, nullptr);

    // File type filter combo box.
    HWND hTypeCombo = CreateWindowExW(0, L"COMBOBOX", nullptr,
        WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST,
        490, 213, 200, 200, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(TYPE_COMBO_ID)), m_hInstance, nullptr);
    SendMessage(hTypeCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hTypeCombo, CB_ADDSTRING, 0, (LPARAM)L"All Files");
    SendMessage(hTypeCombo, CB_ADDSTRING, 0, (LPARAM)L"Documents");
    SendMessage(hTypeCombo, CB_ADDSTRING, 0, (LPARAM)L"Images");
    SendMessage(hTypeCombo, CB_ADDSTRING, 0, (LPARAM)L"Videos");
    SendMessage(hTypeCombo, CB_ADDSTRING, 0, (LPARAM)L"Archives");
    SendMessage(hTypeCombo, CB_SETCURSEL, 0, 0); // Default to All Files

    // Results ListView in virtual mode.
    m_hwndListView = CreateWindowExW(0, WC_LISTVIEW, nullptr,
        WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_OWNERDATA | WS_BORDER,
        20, 260, 1140, 450, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(LISTVIEW_ID)), m_hInstance, nullptr);
    SendMessage(m_hwndListView, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    // Enable extended ListView styles.
    ListView_SetExtendedListViewStyle(m_hwndListView, 
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_CHECKBOXES);

    SetupListView();                             // Initialize ListView columns

    // Status bar at the bottom of the window.
    m_hwndStatusBar = CreateWindowExW(0, STATUSCLASSNAME, nullptr,
        WS_VISIBLE | WS_CHILD | SBARS_SIZEGRIP,
        0, 0, 0, 0, m_hwnd, nullptr, m_hInstance, nullptr);

    UpdateStatusBar(L"Ready");                  // Initial status text
}

// Configure ListView columns.
void RecoveryApplication::SetupListView() {
    LVCOLUMNW col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    col.fmt = LVCFMT_LEFT;

    col.pszText = const_cast<LPWSTR>(L"Name");
    col.cx = 250;
    ListView_InsertColumn(m_hwndListView, 0, &col);

    col.pszText = const_cast<LPWSTR>(L"Path");
    col.cx = 350;
    ListView_InsertColumn(m_hwndListView, 1, &col);

    col.pszText = const_cast<LPWSTR>(L"Size");
    col.cx = 100;
    ListView_InsertColumn(m_hwndListView, 2, &col);

    col.pszText = const_cast<LPWSTR>(L"Type");
    col.cx = 150;
    ListView_InsertColumn(m_hwndListView, 3, &col);

    col.pszText = const_cast<LPWSTR>(L"Recoverable");
    col.cx = 100;
    ListView_InsertColumn(m_hwndListView, 4, &col);
}

// Enter the main message loop.
int RecoveryApplication::Run(int nShowCmd) {
    ShowWindow(m_hwnd, nShowCmd);                // Show main window
    UpdateWindow(m_hwnd);                       // Force initial paint

    HACCEL hAccelTable = LoadAccelerators(m_hInstance, MAKEINTRESOURCE(IDC_MAINACCEL));
    MSG msg = {};

    while (GetMessage(&msg, nullptr, 0, 0)) {   // Standard message loop
        if (!TranslateAccelerator(m_hwnd, hAccelTable, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    return static_cast<int>(msg.wParam);        // Return application exit code
}

// Static window procedure that forwards messages to the instance.
LRESULT CALLBACK RecoveryApplication::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    RecoveryApplication* pApp = nullptr;

    if (uMsg == WM_NCCREATE) {
        CREATESTRUCT* pCreate = reinterpret_cast<CREATESTRUCT*>(lParam);
        pApp = reinterpret_cast<RecoveryApplication*>(pCreate->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pApp));
        pApp->m_hwnd = hwnd;                    // Store window handle
    } else {
        pApp = reinterpret_cast<RecoveryApplication*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }

    if (pApp) {
        return pApp->HandleMessage(uMsg, wParam, lParam); // Dispatch to instance handler
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);     // Default handling
}

// Instance-level message handler.
LRESULT RecoveryApplication::HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_COMMAND:
        // Handle button clicks.
        if (lParam != 0 && HIWORD(wParam) == BN_CLICKED) {
            switch (LOWORD(wParam)) {
            case SCAN_BUTTON_ID:
                OnStartScan();                  // Start new scan
                break;
            case STOP_BUTTON_ID:
                OnStopScan();                   // Stop running scan
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
        break;

    case WM_NOTIFY:
        {
            LPNMHDR pnmh = (LPNMHDR)lParam;
            if (pnmh->hwndFrom == m_hwndListView) {
                if (pnmh->code == LVN_COLUMNCLICK) {
                    OnColumnClick((LPNMLISTVIEW)lParam); // Sort by column
                }
                else if (pnmh->code == LVN_GETDISPINFO) {
                    NMLVDISPINFOW* pDispInfo = (NMLVDISPINFOW*)lParam;
                    int itemIndex = pDispInfo->item.iItem;
                    
                    std::lock_guard<std::mutex> lock(m_filesMutex); // Protect shared data
                    
                    // Provide data for virtual ListView items.
                    if (itemIndex >= 0 && itemIndex < static_cast<int>(m_filteredFiles.size())) {
                        const auto& file = m_filteredFiles[itemIndex];

                        if (pDispInfo->item.mask & LVIF_TEXT) {
                            switch (pDispInfo->item.iSubItem) {
                            case 0: // Name
                                wcsncpy_s(pDispInfo->item.pszText, pDispInfo->item.cchTextMax, 
                                         file.name.c_str(), _TRUNCATE);
                                break;
                            case 1: // Path
                                wcsncpy_s(pDispInfo->item.pszText, pDispInfo->item.cchTextMax, 
                                         file.path.c_str(), _TRUNCATE);
                                break;
                            case 2: // Size
                                wcsncpy_s(pDispInfo->item.pszText, pDispInfo->item.cchTextMax, 
                                         file.sizeFormatted.c_str(), _TRUNCATE);
                                break;
                            case 3: // Type
                                wcsncpy_s(pDispInfo->item.pszText, pDispInfo->item.cchTextMax, 
                                         file.filesystemType.c_str(), _TRUNCATE);
                                break;
                            case 4: // Recoverable
                                wcsncpy_s(pDispInfo->item.pszText, pDispInfo->item.cchTextMax, 
                                         file.isRecoverable ? L"Yes" : L"No", _TRUNCATE);
                                break;
                            }
                        }
                    }
                }
                else if (pnmh->code == NM_RCLICK) {
                    OnListViewRightClick((LPNMITEMACTIVATE)lParam); // Show context menu
                }
            }
        }
        break;

    case WM_SCAN_PROGRESS:
        SendMessage(m_hwndProgress, PBM_SETPOS, wParam, 0); // Update progress bar
        break;

    case WM_SCAN_FILE_FOUND:
        PopulateResultsList();                   // Refresh results when file is found
        break;

    case WM_SCAN_COMPLETE:
        // Restore UI state after scan completes.
        ShowWindow(m_hwndScanButton, SW_SHOW);
        ShowWindow(m_hwndStopButton, SW_HIDE);
        EnableWindow(m_hwndDriveCombo, TRUE);
        EnableWindow(m_hwndCheckMft, TRUE);
        EnableWindow(m_hwndCheckUsn, TRUE);
        EnableWindow(m_hwndCheckCarving, TRUE);
        m_isScanning = false;
        
        if (m_scanThread && m_scanThread->joinable()) {
            m_scanThread->detach();              // Detach completed scan thread
        }
		{
            std::wstring finalMsg = wParam ? L"Scan Completed Successfully" : L"Scan Stopped or Failed";
            finalMsg += L"          |          💡 TIP: Use Shift/Ctrl+Arrows to select, Ctrl+A for All";
            UpdateStatusBar(finalMsg);
        }

        MessageBoxW(m_hwnd, L"Scan finished!", L"Done", MB_OK | MB_ICONINFORMATION);
        break;

    case WM_RECOVERY_COMPLETE:
        // Re-enable UI after recovery operation.
        EnableWindow(m_hwndScanButton, TRUE);
        EnableWindow(m_hwndListView, TRUE);
        EnableWindow(m_hwndDriveCombo, TRUE);
        EnableWindow(m_hwndCheckMft, TRUE);
        EnableWindow(m_hwndCheckUsn, TRUE);
        EnableWindow(m_hwndCheckCarving, TRUE);
        UpdateStatusBar(wParam ? L"Recovery Completed" : L"Recovery Failed");
        break;

    case WM_SORT_COMPLETE:
        {
            // Refresh ListView after background sort completes.
            int count = static_cast<int>(m_filteredFiles.size());
            if (count > 0) {
                ListView_RedrawItems(m_hwndListView, 0, count - 1);
                UpdateWindow(m_hwndListView);
            }
            
            wchar_t status[256];
            swprintf_s(status, L"Sorted %zu files          |          💡 TIP: Use Shift/Ctrl+Arrows to select", 
                       m_filteredFiles.size());
            UpdateStatusBar(status);
        }
        break;

    case WM_SIZE:
        SendMessage(m_hwndStatusBar, WM_SIZE, 0, 0); // Resize status bar
        OnSize(LOWORD(lParam), HIWORD(lParam));      // Re-layout controls
        break;

    case WM_DESTROY:
        PostQuitMessage(0);                       // Exit message loop
        break;

    default:
        return DefWindowProc(m_hwnd, uMsg, wParam, lParam);
    }

    return 0;
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
// Initiate a new scan operation.
void RecoveryApplication::OnStartScan() {
    if (m_isScanning) return;                    // Prevent concurrent scans

    int idx = static_cast<int>(SendMessage(m_hwndDriveCombo, CB_GETCURSEL, 0, 0));
    if (idx == CB_ERR) {
        MessageBoxW(m_hwnd, L"Please select a drive to scan", L"No Drive Selected", MB_OK | MB_ICONWARNING);
        return;
    }

    wchar_t driveLetter[4] = {};
    SendMessage(m_hwndDriveCombo, CB_GETLBTEXT, idx, (LPARAM)driveLetter);
    
    m_lastScannedDrive = driveLetter[0];         // Remember scanned drive

    wchar_t buffer[MAX_PATH];
    GetWindowTextW(m_hwndFolderEdit, buffer, MAX_PATH);
    std::wstring folderFilter = buffer;          // Folder filter input

    GetWindowTextW(m_hwndFilenameEdit, buffer, MAX_PATH);
    std::wstring filenameFilter = buffer;        // Filename filter input

    bool enableMft = (SendMessage(m_hwndCheckMft, BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool enableUsn = (SendMessage(m_hwndCheckUsn, BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool enableCarving = (SendMessage(m_hwndCheckCarving, BM_GETCHECK, 0, 0) == BST_CHECKED);
    if (!enableMft && !enableUsn && !enableCarving) {
        MessageBoxW(m_hwnd, L"Please select at least one scan mode", L"No Scan Mode Selected", MB_OK | MB_ICONWARNING);
        return;
    }

    m_deletedFiles.clear();                      // Clear previous results
    m_filteredFiles.clear();                     // Clear filtered view
    ListView_SetItemCountEx(m_hwndListView, 0, 0);

    // Update UI for scanning state.
    ShowWindow(m_hwndScanButton, SW_HIDE);
    ShowWindow(m_hwndStopButton, SW_SHOW);
    EnableWindow(m_hwndDriveCombo, FALSE);
    EnableWindow(m_hwndCheckMft, FALSE);
    EnableWindow(m_hwndCheckUsn, FALSE);
    EnableWindow(m_hwndCheckCarving, FALSE);

    m_isScanning = true;
    m_shouldStopScan = false;

    // Launch background scan thread.
    m_scanThread = std::make_unique<std::thread>([this, drive = driveLetter[0], folderFilter, filenameFilter, enableMft, enableUsn, enableCarving]() {
        StartBackgroundScan(drive, folderFilter, filenameFilter, enableMft, enableUsn, enableCarving);
    });
}

// Signal the scan thread to stop.
void RecoveryApplication::OnStopScan() {
    m_shouldStopScan = true;                     // Cooperative cancellation flag
    UpdateStatusBar(L"Stopping scan...");
}

// Perform scan in a worker thread.
void RecoveryApplication::StartBackgroundScan(wchar_t driveLetter, std::wstring folderFilter,
                                               std::wstring filenameFilter, bool enableMft,
                                               bool enableUsn, bool enableCarving) {
    auto onProgress = [this](const std::wstring& status, float progress) {
        std::wstring finalStatus = status + L"          |          💡 TIP: Use Shift/Ctrl+Arrows to select, Ctrl+A for All";
        SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)finalStatus.c_str()); // Update status text
        PostMessage(m_hwnd, WM_SCAN_PROGRESS, static_cast<WPARAM>(progress * 100), 0); // Update progress bar
    };
    
    auto onFile = [this](const DeletedFileEntry& file) {
        {
            std::lock_guard<std::mutex> lock(m_filesMutex); // Protect shared results
            m_deletedFiles.push_back(file);   // Append discovered file
        }
        // Synchronous update to ensure UI consistency.
        SendMessage(m_hwnd, WM_SCAN_FILE_FOUND, 0, 0);
    };

    bool success = m_forensicsCore->StartScan(
        driveLetter,
        folderFilter,
        filenameFilter,
        onFile,
        onProgress,
        reinterpret_cast<bool&>(m_shouldStopScan), // Cancellation flag
        enableMft,
        enableUsn,
        enableCarving
    );

    // Notify UI that scan has completed.
    PostMessage(m_hwnd, WM_SCAN_COMPLETE, success ? 1 : 0, 0);
}

// Refresh ListView contents after scan update.
void RecoveryApplication::PopulateResultsList() {
    FilterResults();                             // Re-apply filters and redraw
}

// Check if a file matches the selected type filter.
bool RecoveryApplication::IsFileOfType(const std::wstring& name, int typeIndex) {
    if (typeIndex <= 0) return true;             // All Files selected
    size_t dotPos = name.rfind(L'.');            // Locate file extension
    if (dotPos == std::wstring::npos) return false;

    std::wstring ext = name.substr(dotPos + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);

    switch (typeIndex) {
    case 1: // Documents
        return (ext == L"doc" || ext == L"docx" || ext == L"pdf" || ext == L"txt" || 
                ext == L"rtf" || ext == L"xls" || ext == L"xlsx" || ext == L"ppt" || ext == L"pptx");
    case 2: // Images
        return (ext == L"jpg" || ext == L"jpeg" || ext == L"png" || ext == L"bmp" || 
                ext == L"gif" || ext == L"tiff" || ext == L"raw" || ext == L"ico");
    case 3: // Videos
        return (ext == L"mp4" || ext == L"avi" || ext == L"mkv" || ext == L"mov" || 
                ext == L"wmv" || ext == L"flv" || ext == L"mpg");
    case 4: // Archives
        return (ext == L"zip" || ext == L"rar" || ext == L"7z" || ext == L"tar" || ext == L"gz");
    default:
        return true;
    }
}

// Apply text and type filters to scan results.
void RecoveryApplication::FilterResults() {
    int typeIndex = static_cast<int>(SendMessage(GetDlgItem(m_hwnd, TYPE_COMBO_ID), CB_GETCURSEL, 0, 0));
    wchar_t buffer[MAX_PATH];
    GetWindowTextW(GetDlgItem(m_hwnd, FILTER_EDIT_ID), buffer, MAX_PATH);
    std::wstring searchName = buffer;
    std::transform(searchName.begin(), searchName.end(), searchName.begin(), ::towlower);

    {
        std::lock_guard<std::mutex> lock(m_filesMutex); // Protect shared data
        m_filteredFiles.clear();

        for (const auto& file : m_deletedFiles) {
            if (!searchName.empty()) {
                std::wstring lowerName = file.name;
                std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
                if (lowerName.find(searchName) == std::wstring::npos) {
                    continue;                  // Skip non-matching names
                }
            }

            if (!IsFileOfType(file.name, typeIndex)) {
                continue;                      // Skip non-matching types
            }

            m_filteredFiles.push_back(file);    // Add matching file
        }
    }

    // Update virtual ListView item count.
    ListView_SetItemCountEx(m_hwndListView, m_filteredFiles.size(), LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);

    if (!m_filteredFiles.empty()) {
        ListView_RedrawItems(m_hwndListView, 0, static_cast<int>(m_filteredFiles.size()) - 1);
    }
    UpdateWindow(m_hwndListView);

    wchar_t status[256];
    swprintf_s(status, L"Showing %zu of %zu files          |          💡 TIP: Use Shift/Ctrl+Arrows to select, Ctrl+A for All", 
               m_filteredFiles.size(), m_deletedFiles.size());
    UpdateStatusBar(status);
}

// Recover files selected via checkboxes.
void RecoveryApplication::OnRecoverSelected() {
    std::vector<DeletedFileEntry> selectedFiles;
    int itemCount = ListView_GetItemCount(m_hwndListView);
    for (int i = 0; i < itemCount; ++i) {
        if (ListView_GetCheckState(m_hwndListView, i)) {
            std::lock_guard<std::mutex> lock(m_filesMutex);
            if (i < static_cast<int>(m_filteredFiles.size())) {
                selectedFiles.push_back(m_filteredFiles[i]);
            }
        }
    }

    if (selectedFiles.empty()) {
        MessageBoxW(m_hwnd, L"No files selected for recovery", L"No Selection", MB_OK | MB_ICONINFORMATION);
        return;
    }

    RecoverMultipleFiles(selectedFiles);         // Start recovery workflow
}

// Recover multiple files to a user-selected destination.
void RecoveryApplication::RecoverMultipleFiles(const std::vector<DeletedFileEntry>& files) {
    std::wstring destFolder;
    bool folderSelected = false;

    // Check if running in WinRE environment and use appropriate file picker.
    if (IsWinRE()) {
        OPENFILENAMEW ofn = { 0 };
        wchar_t path[MAX_PATH] = { 0 };
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = m_hwnd;
        ofn.lpstrFile = path;
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrTitle = L"[WinRE Mode] Select any file inside destination folder";
        ofn.Flags = OFN_NOCHANGEDIR | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_DONTADDTORECENT;

        if (GetOpenFileNameW(&ofn)) {
            destFolder = path;
            size_t lastSlash = destFolder.find_last_of(L"\\");
            if (lastSlash != std::wstring::npos) {
                destFolder = destFolder.substr(0, lastSlash);
                if (destFolder.empty() || destFolder.back() != L'\\') {
                    destFolder += L'\\';        // Ensure trailing slash
                }
                folderSelected = true;
            }
        }
    } else {
        BROWSEINFO bi = { 0 };
        bi.hwndOwner = m_hwnd;
        bi.lpszTitle = L"Select destination folder for recovered files";
        bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

        LPITEMIDLIST pidl = SHBrowseForFolder(&bi);
        if (pidl) {
            wchar_t path[MAX_PATH];
            if (SHGetPathFromIDList(pidl, path)) {
                destFolder = path;
                folderSelected = true;
            }
            CoTaskMemFree(pidl);
        }
    }

    if (folderSelected) {
        if (!m_recoveryEngine->ValidateDestination(m_lastScannedDrive, destFolder)) {
            MessageBoxW(m_hwnd, 
                L"Cannot recover to the source drive!\n\n"
                L"Please select a folder on a different drive (e.g., USB drive, D:\\, E:\\).\n\n"
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

        UpdateStatusBar(L"Recovering files... Please wait.");

        std::thread recoveryThread([this, files, destFolder]() {
            PostMessage(m_hwnd, WM_SCAN_PROGRESS, 0, 0);

            bool success = m_recoveryEngine->RecoverMultipleFiles(
                files,
                m_lastScannedDrive,
                destFolder,
                [this](const std::wstring& msg, float progress) {
                    SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)msg.c_str());

                    if (progress >= 0.0f) {
                        PostMessage(m_hwnd, WM_SCAN_PROGRESS, static_cast<WPARAM>(progress * 100), 0);
                    }
                }
            );

            PostMessage(m_hwnd, WM_RECOVERY_COMPLETE, success ? 1 : 0, 0);

            if (success) {
                wchar_t msg[256];
                swprintf_s(msg, 256, L"Recovery finished! Check folder:\n%s", destFolder.c_str());
                MessageBoxW(NULL, msg, L"Recovery Complete", MB_OK | MB_ICONINFORMATION);
            } else {
                MessageBoxW(NULL, 
                    L"Recovery failed!\n\nCheck status bar for details.", 
                    L"Recovery Error", 
                    MB_OK | MB_ICONERROR);
            }
        });
        recoveryThread.detach();                 // Run recovery asynchronously
    }
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
        std::wofstream csvFile(fileName);
        if (csvFile.is_open()) {
            csvFile << L"Name,Path,Size,Filesystem,Recoverable\n";
            
            std::lock_guard<std::mutex> lock(m_filesMutex);
            for (const auto& file : m_filteredFiles) {
                std::wstring cleanName = file.name;
                std::replace(cleanName.begin(), cleanName.end(), L',', L'_');

                csvFile << cleanName << L"," 
                       << file.path << L"," 
                       << file.sizeFormatted << L"," 
                       << file.filesystemType << L"," 
                       << (file.isRecoverable ? L"Yes" : L"No") << L"\n";
            }
            
            MessageBoxW(m_hwnd, L"CSV export completed successfully", L"Export Complete", MB_OK | MB_ICONINFORMATION);
        }
    }
}

// Display the About dialog.
void RecoveryApplication::OnAbout() {
    DialogBox(m_hInstance, MAKEINTRESOURCE(IDD_ABOUTBOX), m_hwnd, AboutDialogProc);
}

// Handle application exit.
void RecoveryApplication::OnExit() {
    if (m_isScanning) {
        int result = MessageBoxW(m_hwnd,
            L"A scan is currently in progress. Are you sure you want to exit?",
            L"Confirm Exit",
            MB_YESNO | MB_ICONWARNING);
        if (result == IDNO) {
            return;                              // Abort exit
        }
        
        m_shouldStopScan = true;
        if (m_scanThread && m_scanThread->joinable()) {
            m_scanThread->join();                // Wait for scan to stop
        }
    }
    DestroyWindow(m_hwnd);                       // Close main window
}

// Update text displayed in the status bar.
void RecoveryApplication::UpdateStatusBar(const std::wstring& text) {
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)text.c_str());
}

// Display an error message box.
void RecoveryApplication::ShowError(const std::wstring& message) {
    MessageBoxW(m_hwnd, message.c_str(), L"Error", MB_OK | MB_ICONERROR);
}

// Format file size into a human-readable string.
std::wstring RecoveryApplication::FormatFileSize(uint64_t bytes) {
    wchar_t buffer[64];
    if (bytes >= 1000000000) {
        swprintf_s(buffer, L"%.2f GB", bytes / 1000000000.0);
    } else if (bytes >= 1000000) {
        swprintf_s(buffer, L"%.2f MB", bytes / 1000000.0);
    } else if (bytes >= 1000) {
        swprintf_s(buffer, L"%.2f KB", bytes / 1000.0);
    } else {
        swprintf_s(buffer, L"%llu bytes", bytes);
    }
    return buffer;
}

// Recover a single file.
void RecoveryApplication::RecoverFile(const DeletedFileEntry& file) {
    std::vector<DeletedFileEntry> files = { file };
    RecoverMultipleFiles(files);
}

// Handle window resize and reposition child controls.
void RecoveryApplication::OnSize(WORD width, WORD height) {
    if (!m_hwndListView) return; 

    int margin = 20;
    int rightMargin = 20;
    int bottomMargin = 25;

    HWND hGroupScan = GetDlgItem(m_hwnd, GROUP_SCAN_ID);
    HWND hGroupFilter = GetDlgItem(m_hwnd, GROUP_FILTER_ID);

    if (hGroupScan) MoveWindow(hGroupScan, margin, 20, width - (margin + rightMargin), 150, TRUE);
    if (hGroupFilter) MoveWindow(hGroupFilter, margin, 185, width - (margin + rightMargin), 60, TRUE);

    if (m_hwndFolderEdit) {
        int folderEditX = 390;
        int buttonWidth = 30;
        int spacing = 5;
        int folderEditWidth = width - folderEditX - 40 - buttonWidth - spacing;

        if (folderEditWidth > 50) {
            MoveWindow(m_hwndFolderEdit, folderEditX, 48, folderEditWidth, 24, TRUE);
            MoveWindow(m_hwndBrowseFolderButton, folderEditX + folderEditWidth + spacing, 47, buttonWidth, 26, TRUE);
        }
    }

    if (m_hwndProgress) {
        int progressX = 1010;
        int progressWidth = width - progressX - 40;
        if (progressWidth > 50) MoveWindow(m_hwndProgress, progressX, 120, progressWidth, 20, TRUE);
    }

    int listY = 260;
    int listHeight = height - listY - bottomMargin;

    if (listHeight > 100) {
        MoveWindow(m_hwndListView, margin, listY, width - (margin + rightMargin), listHeight, TRUE);
    }
}

// Update internal scan status string.
void RecoveryApplication::UpdateScanStatus(const std::wstring& status) {
    m_scanStatus = status;
}

// Handle column header clicks for sorting.
void RecoveryApplication::OnColumnClick(LPNMLISTVIEW pnmv) {
    // Update sorting state on UI thread.
    if (pnmv->iSubItem == m_sortColumn) {
        m_sortAscending = !m_sortAscending;
    } else {
        m_sortColumn = pnmv->iSubItem;
        m_sortAscending = true;
    }

    UpdateStatusBar(L"Sorting files... please wait");

    // Launch background sorting thread to avoid UI freeze on large datasets.
    std::thread([this, col = m_sortColumn, asc = m_sortAscending]() {
        
        std::vector<DeletedFileEntry> tempFiles;

        // Copy working data with minimal mutex lock time.
        {
            std::lock_guard<std::mutex> lock(m_filesMutex);
            tempFiles = m_filteredFiles;
        }

        // Sort on background thread without holding mutex.
        std::sort(tempFiles.begin(), tempFiles.end(), 
            [col, asc](const DeletedFileEntry& a, const DeletedFileEntry& b) {
                int result = 0;
                switch (col) {
                case 0: // Name
                    result = _wcsicmp(a.name.c_str(), b.name.c_str());
                    break;
                case 1: // Path
                    result = _wcsicmp(a.path.c_str(), b.path.c_str());
                    break;
                case 2: // Size
                    if (a.size < b.size) result = -1;
                    else if (a.size > b.size) result = 1;
                    break;
                case 3: // Type
                    result = _wcsicmp(a.filesystemType.c_str(), b.filesystemType.c_str());
                    break;
                case 4: // Recoverable
                    if (a.isRecoverable == b.isRecoverable) result = 0;
                    else result = (a.isRecoverable ? 1 : -1);
                    break;
                }
                return asc ? (result < 0) : (result > 0);
            });

        // Swap sorted data back with minimal mutex lock time.
        {
            std::lock_guard<std::mutex> lock(m_filesMutex);
            m_filteredFiles = std::move(tempFiles);
        }

        // Notify UI thread that sort is complete.
        PostMessage(m_hwnd, WM_SORT_COMPLETE, 0, 0);

    }).detach();
}

// Show context menu on ListView right-click.
void RecoveryApplication::OnListViewRightClick(LPNMITEMACTIVATE pnmitem) {
    if (pnmitem->iItem == -1) {
        return;                                // Ignore empty space clicks
    }

    ListView_SetItemState(m_hwndListView, pnmitem->iItem, 
                          LVIS_SELECTED | LVIS_FOCUSED, 
                          LVIS_SELECTED | LVIS_FOCUSED);

    POINT pt;
    GetCursorPos(&pt);

    HMENU hMenu = CreatePopupMenu();
    if (hMenu) {
        int selectedCount = ListView_GetSelectedCount(m_hwndListView);
        wchar_t menuText[64];
        if (selectedCount > 1) {
            swprintf_s(menuText, L"Save %d files as...", selectedCount);
        } else {
            wcscpy_s(menuText, L"Save As...");
        }

        AppendMenuW(hMenu, MF_STRING, ID_CONTEXT_SAVE_AS, menuText);
        TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_RIGHTBUTTON, 
                       pt.x, pt.y, 0, m_hwnd, nullptr);
        DestroyMenu(hMenu);
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

// Open folder selection dialog for folder filter input.
void RecoveryApplication::OnBrowseFolderInput() {
    // Check if running in WinRE environment and use appropriate picker.
    if (IsWinRE()) {
        OPENFILENAMEW ofn = { 0 };
        wchar_t path[MAX_PATH] = { 0 };
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = m_hwnd;
        ofn.lpstrFilter = L"Folders\0*.none\0All Files\0*.*\0";
        ofn.lpstrFile = path;
        ofn.nMaxFile = MAX_PATH;
        ofn.lpstrTitle = L"[WinRE Mode] Select any file in target folder";
        ofn.Flags = OFN_NOCHANGEDIR | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_DONTADDTORECENT;

        if (GetOpenFileNameW(&ofn)) {
            std::wstring folderPath = path;
            size_t lastSlash = folderPath.find_last_of(L"\\");
            if (lastSlash != std::wstring::npos) {
                folderPath = folderPath.substr(0, lastSlash);
            }
            SetWindowTextW(m_hwndFolderEdit, folderPath.c_str());
        }
    } else {
        BROWSEINFO bi = { 0 };
        bi.hwndOwner = m_hwnd;
        bi.lpszTitle = L"Select folder to filter by";
        bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_NONEWFOLDERBUTTON;

        LPITEMIDLIST pidl = SHBrowseForFolder(&bi);
        if (pidl) {
            wchar_t path[MAX_PATH];
            if (SHGetPathFromIDList(pidl, path)) {
                SetWindowTextW(m_hwndFolderEdit, path);
            }
            CoTaskMemFree(pidl);
        }
    }
}

// Detect if running in Windows Recovery Environment.
bool RecoveryApplication::IsWinRE() {
    wchar_t winDir[MAX_PATH];
    GetWindowsDirectoryW(winDir, MAX_PATH);
    std::wstring checkPath = std::wstring(winDir) + L"\\System32\\winpeshl.exe";
    return (GetFileAttributesW(checkPath.c_str()) != INVALID_FILE_ATTRIBUTES);
}

} // namespace KVC
