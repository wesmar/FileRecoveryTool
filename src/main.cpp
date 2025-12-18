// ============================================================================
// KVC File Recovery Tool - Main Entry Point
// ============================================================================
// Professional data salvage tool for Windows with WinAPI GUI
// Supports NTFS filesystem with three-stage recovery:
//   - MFT (Master File Table) scanning for recently deleted files
//   - USN Journal analysis for deletion events
//   - File carving from raw disk sectors
//
// Dual Mode Support:
//   - GUI mode: Launch without arguments (default)
//   - CLI mode: Launch with --cli argument for command-line operation
//
// (c) 2025 - Modern C++ Implementation
// ============================================================================

#define NOMINMAX  // Prevent Windows.h min/max macros
#include "RecoveryApplication.h"
#include "main_cli.h"
#include "resource.h"
#include <Windows.h>
#include <CommCtrl.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

int WINAPI wWinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR lpCmdLine,
    _In_ int nShowCmd)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Parse command line to detect CLI mode
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    
    // CLI mode detected - run command-line interface
    if (argc > 1) {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        if (FAILED(hr)) {
            wprintf(L"[ERROR] Failed to initialize COM library\n");
            LocalFree(argv);
            return 3;
        }
        
        int result = KVC::RunCLI(argc, argv);
        
        CoUninitialize();
        LocalFree(argv);
        return result;
    }
    
    LocalFree(argv);

    // GUI mode - initialize COM library (required for shell dialogs like Save File and Browse Folder)
    // This fixes the issue where Export/Recover dialogs wouldn't appear
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(hr)) {
        MessageBoxW(nullptr, L"Failed to initialize COM library.", L"Critical Error", MB_OK | MB_ICONERROR);
        return -1;
    }

    // Initialize common controls (ProgressBar, ListView, etc.)
    INITCOMMONCONTROLSEX icex{};
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);

    // Create and initialize the main application instance
    KVC::RecoveryApplication app(hInstance);
    if (!app.Initialize()) {
        MessageBoxW(nullptr, L"Failed to initialize application", L"Error", MB_OK | MB_ICONERROR);
        CoUninitialize(); // Clean up COM before exiting on error
        return -1;
    }

    // Run the application message loop
    int result = app.Run(nShowCmd);

    // Uninitialize COM library before shutting down
    CoUninitialize();

    return result;
}