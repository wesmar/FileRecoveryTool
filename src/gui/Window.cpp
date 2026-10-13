// Window creation and message routing.

#include "gui/RecoveryApplication.h"
#include <algorithm>

namespace KVC {

// Create the main top-level window.
void RecoveryApplication::CreateMainWindow() {
    m_hwnd = CreateWindowExW(
        0,
        L"KVCRecoveryWindowClass",
        L"KVC File Recovery",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        1200, 720,
        nullptr,
        nullptr,
        m_hInstance,
        this                                   // Pass application pointer to WM_NCCREATE
    );

    if (!m_hwnd) {
        return;                                // Abort if window creation failed
    }

    CreateControls();                           // Initialize child controls
    m_appearance.Initialize(m_hwnd);
    MONITORINFO monitor{sizeof(monitor)};
    if (GetMonitorInfoW(MonitorFromWindow(m_hwnd, MONITOR_DEFAULTTONEAREST), &monitor)) {
        RECT desired{0, 0, m_appearance.Scale(1100), m_appearance.Scale(680)};
        AdjustWindowRectExForDpi(&desired, WS_OVERLAPPEDWINDOW, TRUE, 0, GetDpiForWindow(m_hwnd));
        const RECT& work = monitor.rcWork;
        const int width = std::min(desired.right - desired.left, work.right - work.left);
        const int height = std::min(desired.bottom - desired.top, work.bottom - work.top);
        SetWindowPos(m_hwnd, nullptr, work.left + (work.right - work.left - width) / 2,
                     work.top + (work.bottom - work.top - height) / 2, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
    }
    RECT client;
    GetClientRect(m_hwnd, &client);
    OnSize(static_cast<WORD>(client.right), static_cast<WORD>(client.bottom));
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
    LRESULT appearanceResult = 0;
    if (m_appearance.HandleMessage(uMsg, wParam, lParam, appearanceResult)) return appearanceResult;
    switch (uMsg) {
    case WM_CLOSE:
        OnExit();
        break;
    case WM_DPICHANGED:
        {
            m_appearance.SetDpi(HIWORD(wParam));
            const RECT* suggested = reinterpret_cast<const RECT*>(lParam);
            SetWindowPos(m_hwnd, nullptr, suggested->left, suggested->top,
                         suggested->right - suggested->left, suggested->bottom - suggested->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
        }
        break;
    case WM_GETMINMAXINFO:
        {
            const UINT dpi = GetDpiForWindow(m_hwnd);
            auto* info = reinterpret_cast<MINMAXINFO*>(lParam);
            MONITORINFO monitor{sizeof(monitor)};
            GetMonitorInfoW(MonitorFromWindow(m_hwnd, MONITOR_DEFAULTTONEAREST), &monitor);
            info->ptMinTrackSize = {std::min<LONG>(MulDiv(640, static_cast<int>(dpi), 96), monitor.rcWork.right - monitor.rcWork.left),
                                   std::min<LONG>(MulDiv(480, static_cast<int>(dpi), 96), monitor.rcWork.bottom - monitor.rcWork.top)};
        }
        break;
    case WM_COMMAND:
        OnCommand(wParam, lParam);
        break;

    case WM_NOTIFY:
        OnListNotification(reinterpret_cast<LPNMHDR>(lParam));
        break;

    case WM_SCAN_PROGRESS:
        {
            std::lock_guard<std::mutex> lock(m_progressMutex);
            UpdateStatusBar(m_pendingStatus);
            if (m_pendingProgress >= 0) SendMessage(m_hwndProgress, PBM_SETPOS, m_pendingProgress, 0);
            m_progressPosted = false;
        }
        break;

    case WM_SCAN_FILE_FOUND:
        m_resultsPosted = false;
        PopulateResultsList();                   // Refresh results when file is found
        break;

    case WM_SCAN_COMPLETE:
        OnScanComplete(wParam != 0);
        break;

    case WM_RECOVERY_COMPLETE:
        OnRecoveryComplete(wParam != 0);
        break;

    case WM_SORT_COMPLETE:
        OnSortComplete();
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

} // namespace KVC
