// Child controls and DPI-aware layout.

#include "gui/RecoveryApplication.h"
#include "io/VolumeLocator.h"
#include "filesystems/FilesystemDetector.h"
#include "support/StringUtils.h"
#include <algorithm>

namespace KVC {

// Create and layout all child controls.
void RecoveryApplication::CreateControls() {
    HFONT hFont = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

    // Scan configuration group box.
    HWND hGroupBox = CreateWindowExW(0, L"BUTTON", L"Scan Configuration",
        WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
        20, 20, 1140, 150, m_hwnd,
        reinterpret_cast<HMENU>(static_cast<UINT_PTR>(GROUP_SCAN_ID)),
        m_hInstance, nullptr);
    SendMessage(hGroupBox, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Drive letter label.
    m_labels[0] = CreateWindowExW(0, L"STATIC", L"Source:",
        WS_VISIBLE | WS_CHILD,
        40, 50, 100, 20, m_hwnd, nullptr, m_hInstance, nullptr);

    // Drive selection combo box.
    m_hwndDriveCombo = CreateWindowExW(0, L"COMBOBOX", nullptr,
        WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL | CBS_OWNERDRAWFIXED | CBS_HASSTRINGS,
        150, 48, 100, 200, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(DRIVE_COMBO_ID)), m_hInstance, nullptr);
    SendMessage(m_hwndDriveCombo, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Every volume: lettered ones, and partitions without a letter (Linux
    // ext4 among them), each shown with the file system it holds.
    for (const auto& volume : EnumerateVolumes()) {
        DiskHandle disk(volume.path);
        if (!disk.Open()) continue;
        const VolumeInfo info = DetectFilesystem(disk);
        std::wstring label = volume.letters.empty()
            ? volume.ntDevice.substr(volume.ntDevice.rfind(L'\\') + 1)
            : volume.letters;
        label += L"  " + info.name;
        SendMessage(m_hwndDriveCombo, CB_ADDSTRING, 0, (LPARAM)label.c_str());
        m_volumePaths.push_back(volume.path);
    }
    for (const auto& path : EnumeratePhysicalDisks()) {
        DiskHandle disk(path);
        if (!disk.Open()) continue;
        const std::wstring label = path.substr(4) + L"  (whole disk, RAW)  " + StringUtils::FormatFileSize(disk.GetDiskSize());
        SendMessageW(m_hwndDriveCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str()));
        m_volumePaths.push_back(path);
    }
    SendMessage(m_hwndDriveCombo, CB_SETCURSEL, 0, 0);
    SendMessage(m_hwndDriveCombo, CB_SETDROPPEDWIDTH, 280, 0);

    // Folder filter label.
    m_labels[1] = CreateWindowExW(0, L"STATIC", L"Folder:",
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
    m_labels[2] = CreateWindowExW(0, L"STATIC", L"Filename:",
        WS_VISIBLE | WS_CHILD,
        40, 85, 100, 20, m_hwnd, nullptr, m_hInstance, nullptr);

    // Filename filter edit box.
    m_hwndFilenameEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr,
        WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL,
        150, 83, 200, 24, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(FILENAME_EDIT_ID)), m_hInstance, nullptr);
    SendMessage(m_hwndFilenameEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Scan mode label.
    m_labels[3] = CreateWindowExW(0, L"STATIC", L"Methods:",
        WS_VISIBLE | WS_CHILD,
        40, 120, 100, 20, m_hwnd, nullptr, m_hInstance, nullptr);

    // MFT scan checkbox.
    m_hwndCheckMft = CreateWindowExW(0, L"BUTTON", L"File system metadata",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        150, 120, 140, 20, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(CHECK_MFT_ID)), m_hInstance, nullptr);
    SendMessage(m_hwndCheckMft, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hwndCheckMft, BM_SETCHECK, BST_CHECKED, 0); // Enabled by default

    // USN journal scan checkbox.
    m_hwndCheckUsn = CreateWindowExW(0, L"BUTTON", L"NTFS change journal",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        300, 120, 180, 20, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(CHECK_USN_ID)), m_hInstance, nullptr);
    SendMessage(m_hwndCheckUsn, WM_SETFONT, (WPARAM)hFont, TRUE);

    // File carving scan checkbox.
    m_hwndCheckCarving = CreateWindowExW(0, L"BUTTON", L"File signatures",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        490, 120, 170, 20, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(CHECK_CARVING_ID)), m_hInstance, nullptr);
    SendMessage(m_hwndCheckCarving, WM_SETFONT, (WPARAM)hFont, TRUE);
    m_hwndCheckRaw = CreateWindowExW(0, L"BUTTON", L"RAW: all source bytes",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 0, 0, 196, 28, m_hwnd,
        reinterpret_cast<HMENU>(static_cast<UINT_PTR>(CHECK_RAW_ID)), m_hInstance, nullptr);
    m_hwndOpenImageButton = CreateWindowExW(0, L"BUTTON", L"Open image...",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 0, 0, 144, 30, m_hwnd,
        reinterpret_cast<HMENU>(static_cast<UINT_PTR>(OPEN_IMAGE_ID)), m_hInstance, nullptr);

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
    m_hwndRecoverButton = CreateWindowExW(0, L"BUTTON", L"Recover selected...",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 0, 0, 180, 32, m_hwnd,
        reinterpret_cast<HMENU>(static_cast<UINT_PTR>(RECOVER_BUTTON_ID)), m_hInstance, nullptr);

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
    m_labels[4] = CreateWindowExW(0, L"STATIC", L"Search:",
        WS_VISIBLE | WS_CHILD,
        40, 215, 60, 20, m_hwnd, nullptr, m_hInstance, nullptr);

    // Search filter edit box.
    HWND hFilterEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr,
        WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL,
        110, 213, 300, 24, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(FILTER_EDIT_ID)), m_hInstance, nullptr);
    SendMessage(hFilterEdit, WM_SETFONT, (WPARAM)hFont, TRUE);

    // File type filter label.
    m_labels[5] = CreateWindowExW(0, L"STATIC", L"Type:",
        WS_VISIBLE | WS_CHILD,
        430, 215, 50, 20, m_hwnd, nullptr, m_hInstance, nullptr);

    // File type filter combo box.
    HWND hTypeCombo = CreateWindowExW(0, L"COMBOBOX", nullptr,
        WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST | CBS_OWNERDRAWFIXED | CBS_HASSTRINGS,
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
        WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_OWNERDATA | WS_BORDER | WS_TABSTOP,
        20, 260, 1140, 450, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(LISTVIEW_ID)), m_hInstance, nullptr);
    SendMessage(m_hwndListView, WM_SETFONT, (WPARAM)hFont, TRUE);

    // Enable extended ListView styles.
    ListView_SetExtendedListViewStyle(m_hwndListView,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

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

    col.pszText = const_cast<LPWSTR>(L"Quality");
    col.cx = 100;
    ListView_InsertColumn(m_hwndListView, 4, &col);
}

// Handle window resize and reposition child controls.
void RecoveryApplication::OnSize(WORD width, WORD height) {
    if (!m_hwndListView) return;
    const int w = m_appearance.Unscale(width);
    const int h = m_appearance.Unscale(height);
    auto move = [&](HWND child, int x, int y, int cx, int cy) {
        if (child) MoveWindow(child, m_appearance.Scale(x), m_appearance.Scale(y),
                             m_appearance.Scale(std::max(1, cx)), m_appearance.Scale(std::max(1, cy)), TRUE);
    };
    const bool narrow = w < 760;
    const bool compact = h < 600;
    const int top = compact ? 64 : 80;
    const int gap = compact ? 32 : 40;
    const int row = top + 26;
    int methods, actions;
    move(m_labels[0], 36, row + 6, 80, 24); move(m_hwndDriveCombo, 128, row, narrow ? w - 324 : 210, 220);
    move(m_hwndOpenImageButton, narrow ? w - 180 : 424, narrow ? row : row + gap, 144, 30);
    if (narrow) {
        move(m_labels[1], 36, row + gap + 6, 88, 24); move(m_hwndFolderEdit, 128, row + gap, w - 204, 28);
        move(m_hwndBrowseFolderButton, w - 68, row + gap - 1, 32, 30);
        move(m_labels[2], 36, row + 2 * gap + 6, 88, 24); move(m_hwndFilenameEdit, 128, row + 2 * gap, w - 164, 28);
        methods = row + 3 * gap;
        actions = methods + 2 * gap;
    } else {
        move(m_labels[1], 364, row + 6, 88, 24); move(m_hwndFolderEdit, 460, row, w - 536, 28);
        move(m_hwndBrowseFolderButton, w - 68, row - 1, 32, 30);
        move(m_labels[2], 36, row + gap + 6, 88, 24); move(m_hwndFilenameEdit, 128, row + gap, 260, 28);
        methods = row + 2 * gap;
        actions = methods + gap;
    }
    const bool twoMethodRows = w < 960;
    actions = methods + (twoMethodRows ? 2 * gap : gap);
    move(m_labels[3], 36, methods + 4, 88, 24);
    move(m_hwndCheckMft, 128, methods, 196, 28); move(m_hwndCheckUsn, 340, methods, 192, 28);
    move(m_hwndCheckCarving, narrow ? 128 : 548, narrow ? methods + gap : methods, 172, 28);
    move(m_hwndCheckRaw, narrow ? 340 : (twoMethodRows ? 128 : 736), twoMethodRows ? methods + gap : methods, 196, 28);
    move(m_hwndScanButton, 36, actions, 160, 32); move(m_hwndStopButton, 36, actions, 160, 32);
    move(m_hwndRecoverButton, 212, actions, 192, 32); move(m_hwndProgress, 424, actions + 5, w - 460, 22);
    move(GetDlgItem(m_hwnd, GROUP_SCAN_ID), 16, top, w - 32, actions + 48 - top);
    const int filterTop = actions + 60;
    move(GetDlgItem(m_hwnd, GROUP_FILTER_ID), 16, filterTop, w - 32, 64);
    move(m_labels[4], 36, filterTop + 28, 60, 24); move(GetDlgItem(m_hwnd, FILTER_EDIT_ID), 104, filterTop + 22, w - 436, 28);
    move(m_labels[5], w - 312, filterTop + 28, 48, 24); move(GetDlgItem(m_hwnd, TYPE_COMBO_ID), w - 256, filterTop + 20, 220, 200);
    RECT status{}; GetWindowRect(m_hwndStatusBar, &status);
    const int statusHeight = m_appearance.Unscale(status.bottom - status.top);
    const int listTop = filterTop + 80;
    move(m_hwndListView, 16, listTop, w - 32, h - listTop - 12 - statusHeight);
}

} // namespace KVC
