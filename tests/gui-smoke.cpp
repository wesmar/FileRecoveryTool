// Hidden-window regressions for the production GUI. Runs in the VM, without
// desktop input. DPI transitions are simulated, not physical monitor moves.
#include "gui/RecoveryApplication.h"
#include "recovery/RecoveryEngine.h"
#include <cstdio>
#include <stdexcept>

namespace KVC {
struct GuiSmokeTest {
    static void Require(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
    static void CheckMenus(RecoveryApplication& app) {
        RECT frame{}; GetWindowRect(app.m_hwnd, &frame);
        const int width = frame.right - frame.left, height = frame.bottom - frame.top;
        BITMAPINFO bitmap{}; bitmap.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bitmap.bmiHeader.biWidth = width; bitmap.bmiHeader.biHeight = -height;
        bitmap.bmiHeader.biPlanes = 1; bitmap.bmiHeader.biBitCount = 32; bitmap.bmiHeader.biCompression = BI_RGB;
        void* pixels = nullptr; HDC dc = CreateCompatibleDC(nullptr);
        HBITMAP image = CreateDIBSection(dc, &bitmap, DIB_RGB_COLORS, &pixels, nullptr, 0);
        Require(dc && image && pixels, "menu pixel surface");
        HGDIOBJ previous = SelectObject(dc, image);
        const auto inspect = [&](RECT area, COLORREF background) {
            GdiFlush();
            unsigned glyphPixels = 0;
            const auto* data = static_cast<const uint32_t*>(pixels);
            for (LONG y = area.top; y < area.bottom; ++y) for (LONG x = area.left; x < area.right; ++x) {
                const uint32_t pixel = data[y * width + x];
                Require((pixel >> 24) == 255, "menu alpha must be opaque on the Mica frame");
                if (RGB((pixel >> 16) & 255, (pixel >> 8) & 255, pixel & 255) != background) ++glyphPixels;
            }
            Require(glyphPixels > 5, "menu text must be visible against its background");
        };
        for (int mode = 0; mode < 3; ++mode) {
            app.m_appearance.m_dark = mode == 1; app.m_appearance.m_highContrast = mode == 2;
            app.m_appearance.UpdatePalette();
            app.m_appearance.PaintMenuBar(dc);
            for (int index = 0; index < 4; ++index) {
                RECT area{}; Require(GetMenuItemRect(app.m_hwnd, GetMenu(app.m_hwnd), index, &area), "menu rectangle");
                OffsetRect(&area, -frame.left, -frame.top);
                inspect(area, app.m_appearance.m_control);
            }
            MENUITEMINFOW info{sizeof(info)}; info.fMask = MIIM_DATA;
            Require(GetMenuItemInfoW(GetSubMenu(GetMenu(app.m_hwnd), 0), 0, TRUE, &info) && info.dwItemData, "popup draw data");
            for (UINT state : {0u, static_cast<UINT>(ODS_SELECTED), static_cast<UINT>(ODS_DISABLED)}) {
                DRAWITEMSTRUCT item{}; item.CtlType = ODT_MENU; item.itemData = info.dwItemData;
                item.hDC = dc; item.rcItem = {0, 0, 300, 40}; item.itemState = state;
                LRESULT result = 0;
                Require(app.m_appearance.HandleMessage(WM_DRAWITEM, 0, reinterpret_cast<LPARAM>(&item), result) && result, "popup draw dispatch");
                inspect(item.rcItem, state == ODS_SELECTED ? app.m_appearance.m_accent : app.m_appearance.m_control);
            }
            std::printf("PASS GUI menu pixels/alpha mode=%d (bar + normal/selected/disabled popup)\n", mode);
        }
        SelectObject(dc, previous); DeleteObject(image); DeleteDC(dc);
        app.m_appearance.Refresh();
    }
    static void Run(RecoveryApplication& app) {
        std::printf("GUI awareness before Initialize: %d, V2=%d\n", static_cast<int>(GetAwarenessFromDpiAwarenessContext(GetThreadDpiAwarenessContext())),
                    AreDpiAwarenessContextsEqual(GetThreadDpiAwarenessContext(), DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2));
        Require(app.Initialize(), "initialize GUI");
        Require(GetMenu(app.m_hwnd) != nullptr && GetMenuItemCount(GetMenu(app.m_hwnd)) == 4, "main menu resource");
        for (const auto& item : app.m_appearance.m_menuItems) Require(!item->label.empty(), "menu label lost during owner-draw conversion");
        ShowWindow(app.m_hwnd, SW_SHOWNOACTIVATE); UpdateWindow(app.m_hwnd);
        for (int index = 0; index < 4; ++index) {
            wchar_t label[256]{}; MENUITEMINFOW info{sizeof(info)};
            info.fMask = MIIM_STRING | MIIM_FTYPE; info.dwTypeData = label; info.cch = 256;
            const BOOL textOk = GetMenuItemInfoW(GetMenu(app.m_hwnd), index, TRUE, &info);
            RECT rect{}; const BOOL rectOk = GetMenuItemRect(app.m_hwnd, GetMenu(app.m_hwnd), index, &rect);
            Require(textOk && wcslen(label) != 0 && !(info.fType & MFT_OWNERDRAW) && rectOk && rect.right > rect.left, "visible native menu bar");
        }
        CheckMenus(app);
        ShowWindow(app.m_hwnd, SW_HIDE);
        Require(AreDpiAwarenessContextsEqual(GetThreadDpiAwarenessContext(), DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2), "PerMonitorV2 manifest");
        for (UINT dpi : {96u, 120u, 144u, 192u, 240u}) {
            app.m_appearance.SetDpi(dpi);
            for (SIZE size : {SIZE{640,480}, SIZE{760,600}, SIZE{1100,680}}) {
                RECT frame{0,0,app.m_appearance.Scale(size.cx),app.m_appearance.Scale(size.cy)};
                AdjustWindowRectExForDpi(&frame, WS_OVERLAPPEDWINDOW, TRUE, 0, GetDpiForWindow(app.m_hwnd));
                SetWindowPos(app.m_hwnd, nullptr, 0, 0, frame.right - frame.left, frame.bottom - frame.top, SWP_NOZORDER | SWP_NOACTIVATE);
                RECT client; GetClientRect(app.m_hwnd, &client);
                app.OnSize(static_cast<WORD>(client.right), static_cast<WORD>(client.bottom));
                for (HWND child = GetWindow(app.m_hwnd, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT)) {
                    wchar_t cls[32]; GetClassNameW(child, cls, 32);
                    if (child == app.m_hwndStatusBar) continue;
                    RECT rect; GetWindowRect(child, &rect);
                    MapWindowPoints(nullptr, app.m_hwnd, reinterpret_cast<POINT*>(&rect), 2);
                    // Combo dropdown rectangles include a hidden popup. Its
                    // visible edit portion is the only part inside the layout.
                    if (_wcsicmp(cls, L"ComboBox") == 0) rect.bottom = rect.top + app.m_appearance.Scale(28);
                    Require(rect.left >= 0 && rect.top >= 0 && rect.right <= client.right && rect.bottom <= client.bottom,
                            "control outside client area");
                }
                LOGFONTW font{};
                auto handle = reinterpret_cast<HFONT>(SendMessageW(app.m_hwndFilenameEdit, WM_GETFONT, 0, 0));
                Require(GetObjectW(handle, sizeof(font), &font) == sizeof(font) && font.lfHeight == -app.m_appearance.Scale(14), "DPI font size");
                std::printf("PASS GUI %u DPI %ldx%ld\n", dpi, size.cx, size.cy);
            }
        }
        // Repeated batches must append only unseen results, including while
        // the worker is still producing candidates.
        app.m_appearance.SetDpi(GetDpiForWindow(app.m_hwnd));
        for (size_t batch = 0; batch < 4; ++batch) {
            for (size_t n = 0; n < 500; ++n) {
                RecoveryCandidate candidate; candidate.name = L"image_" + std::to_wstring(batch * 500 + n) + L".jpg";
                app.m_deletedFiles.push_back(std::move(candidate));
            }
            app.PopulateResultsList(); app.PopulateResultsList();
            Require(app.m_filteredFiles.size() == (batch + 1) * 500, "duplicate or missing GUI results");
        }
        std::puts("PASS GUI incremental result batches");
        SendMessageW(app.m_hwndCheckRaw, BM_SETCHECK, BST_CHECKED, 0);
        app.OnCommand(MAKEWPARAM(RecoveryApplication::CHECK_RAW_ID, BN_CLICKED), reinterpret_cast<LPARAM>(app.m_hwndCheckRaw));
        for (HWND method : {app.m_hwndCheckMft, app.m_hwndCheckUsn, app.m_hwndCheckCarving})
            Require(SendMessageW(method, BM_GETCHECK, 0, 0) == BST_UNCHECKED, "RAW must exclude metadata/free-space modes");
        SendMessageW(app.m_hwndCheckMft, BM_SETCHECK, BST_CHECKED, 0);
        app.OnCommand(MAKEWPARAM(RecoveryApplication::CHECK_MFT_ID, BN_CLICKED), reinterpret_cast<LPARAM>(app.m_hwndCheckMft));
        Require(SendMessageW(app.m_hwndCheckRaw, BM_GETCHECK, 0, 0) == BST_UNCHECKED, "metadata must exit RAW mode");
        std::puts("PASS GUI RAW mode exclusivity");
        // Worker progress never waits synchronously for the UI thread.
        std::thread worker([&]() { for (int n = 0; n < 1000; ++n) app.PostProgress(L"progress", n / 10.0f); });
        worker.join();
        app.HandleMessage(RecoveryApplication::WM_SCAN_PROGRESS, 0, 0);
        std::puts("PASS GUI worker progress joins without pumping UI messages");
        // Exercise the GUI scan worker with an unaligned, exact-length RAW
        // source, then use the same recovery engine as the CLI.
        struct TemporaryFiles {
            wchar_t source[MAX_PATH]{}, output[MAX_PATH]{};
            ~TemporaryFiles() { DeleteFileW(source); DeleteFileW(output); }
        } temporary;
        wchar_t directory[MAX_PATH]{};
        Require(GetTempPathW(MAX_PATH, directory) != 0 &&
            GetTempFileNameW(directory, L"frt", 0, temporary.source) != 0 &&
            GetTempFileNameW(directory, L"frt", 0, temporary.output) != 0, "GUI RAW temporary paths");
        const std::vector<uint8_t> wave = {'R','I','F','F',40,0,0,0,'W','A','V','E',
            'f','m','t',' ',16,0,0,0,1,0,1,0,0x40,0x1F,0,0,0x80,0x3E,0,0,2,0,16,0,
            'd','a','t','a',4,0,0,0,0,0,1,0};
        std::vector<uint8_t> image(31, 0); image.insert(image.end(), wave.begin(), wave.end());
        HANDLE file = CreateFileW(temporary.source, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        DWORD written = 0;
        const bool saved = file != INVALID_HANDLE_VALUE && WriteFile(file, image.data(), static_cast<DWORD>(image.size()), &written, nullptr) && written == image.size();
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
        Require(saved, "GUI RAW source write");
        const auto index = SendMessageW(app.m_hwndDriveCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(temporary.source));
        Require(index >= 0, "GUI RAW source selection");
        app.m_volumePaths.emplace_back(temporary.source);
        SendMessageW(app.m_hwndDriveCombo, CB_SETCURSEL, index, 0);
        SendMessageW(app.m_hwndCheckRaw, BM_SETCHECK, BST_CHECKED, 0);
        app.OnCommand(MAKEWPARAM(RecoveryApplication::CHECK_RAW_ID, BN_CLICKED), reinterpret_cast<LPARAM>(app.m_hwndCheckRaw));
        app.OnStartScan();
        Require(app.m_scanThread != nullptr, "GUI RAW scan worker");
        app.m_scanThread->join();
        app.OnScanComplete(true);
        Require(app.m_filteredFiles.size() == 1 && app.m_filteredFiles[0].filesystemType == L"RAW" &&
            app.m_filteredFiles[0].fileSize == wave.size() && app.m_forensicsCore->LastCarvingStatistics().readErrorBatches == 0, "GUI RAW candidate");
        app.m_recoveryEngine->RecoverFile(app.m_filteredFiles[0], temporary.source, temporary.output, {});
        DiskHandle recovered(temporary.output);
        Require(recovered.Open() && recovered.ReadBytes(0, wave.size()) == wave, "GUI RAW byte-exact recovery");
        recovered.Close();
        std::puts("PASS GUI RAW worker and shared-engine byte-exact recovery");
        app.OnExit();
    }
};
}

int main() {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&controls);
    int result = 0;
    try { KVC::RecoveryApplication app(GetModuleHandleW(nullptr)); KVC::GuiSmokeTest::Run(app); }
    catch (const std::exception& error) { std::fprintf(stderr, "FAIL GUI: %s\n", error.what()); result = 1; }
    CoUninitialize();
    return result;
}
