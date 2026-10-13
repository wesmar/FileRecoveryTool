// Application lifetime and the message loop.

#include "gui/RecoveryApplication.h"
#include "recovery/RecoveryEngine.h"
#include "resources/resource.h"

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
    , m_lastScannedVolume(L"\\\\.\\C:")
{
    m_forensicsCore = std::make_unique<DiskForensicsCore>();   // Low-level disk scanner
    m_recoveryEngine = std::make_unique<RecoveryEngine>();    // File recovery engine
}

// Ensure background scan thread is stopped on destruction.
RecoveryApplication::~RecoveryApplication() {
    if (m_scanThread && m_scanThread->joinable()) {
        m_shouldStopScan = true;                 // Signal scan thread to stop
        m_scanThread->join();                    // Wait for thread termination
    }
    if (m_recoveryThread && m_recoveryThread->joinable()) m_recoveryThread->join();
    if (m_sortThread && m_sortThread->joinable()) m_sortThread->join();
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

// Enter the main message loop.
int RecoveryApplication::Run(int nShowCmd) {
    ShowWindow(m_hwnd, nShowCmd);                // Show main window
    UpdateWindow(m_hwnd);                       // Force initial paint

    HACCEL hAccelTable = LoadAccelerators(m_hInstance, MAKEINTRESOURCE(IDC_MAINACCEL));
    MSG msg = {};

    while (GetMessage(&msg, nullptr, 0, 0)) {   // Standard message loop
        if (!TranslateAccelerator(m_hwnd, hAccelTable, &msg) && !IsDialogMessage(m_hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    return static_cast<int>(msg.wParam);        // Return application exit code
}

// Handle application exit.
void RecoveryApplication::OnExit() {
    if (m_closing) return;
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
    m_closing = true;
    m_shouldStopScan = true;
    if (m_scanThread && m_scanThread->joinable()) m_scanThread->join();
    if (m_recoveryThread && m_recoveryThread->joinable()) m_recoveryThread->join();
    if (m_sortThread && m_sortThread->joinable()) m_sortThread->join();
    DestroyWindow(m_hwnd);
}

} // namespace KVC
