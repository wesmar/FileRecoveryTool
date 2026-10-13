#include "gui/WindowAppearance.h"
#include <CommCtrl.h>
#include <dwmapi.h>
#include <uxtheme.h>
#include <vssym32.h>
#include <algorithm>
#include <string>
#include <cwctype>

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "advapi32.lib")

namespace KVC {
WindowAppearance::~WindowAppearance() {
    if (m_font) DeleteObject(m_font);
    if (m_headingFont) DeleteObject(m_headingFont);
    if (m_menuFont) DeleteObject(m_menuFont);
    if (m_backgroundBrush) DeleteObject(m_backgroundBrush);
    if (m_controlBrush) DeleteObject(m_controlBrush);
    if (m_bufferedPaint) BufferedPaintUnInit();
}

void WindowAppearance::Initialize(HWND window) {
    m_window = window;
    m_bufferedPaint = SUCCEEDED(BufferedPaintInit());
    // Keep standard checkbox behavior; draw push buttons and combos ourselves
    // so dark colors do not depend on undocumented uxtheme ordinals.
    for (HWND child = GetWindow(window, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT)) {
        wchar_t cls[32]; GetClassNameW(child, cls, 32);
        LONG_PTR style = GetWindowLongPtrW(child, GWL_STYLE);
        if (_wcsicmp(cls, L"Button") == 0 && (style & BS_TYPEMASK) == BS_PUSHBUTTON)
            SetWindowLongPtrW(child, GWL_STYLE, (style & ~BS_TYPEMASK) | BS_OWNERDRAW | WS_TABSTOP);
        if (_wcsicmp(cls, L"ComboBox") == 0)
            SetWindowLongPtrW(child, GWL_STYLE, style | CBS_OWNERDRAWFIXED | CBS_HASSTRINGS | WS_TABSTOP);
        if (_wcsicmp(cls, L"Edit") == 0 || (style & BS_TYPEMASK) == BS_AUTOCHECKBOX)
            SetWindowLongPtrW(child, GWL_STYLE, GetWindowLongPtrW(child, GWL_STYLE) | WS_TABSTOP);
        SetWindowTheme(child, L"", L"");
        if (_wcsicmp(cls, WC_LISTVIEWW) == 0) {
            HWND header = ListView_GetHeader(child);
            SetWindowSubclass(header, SurfaceProc, 1, reinterpret_cast<DWORD_PTR>(this));
        }
        if (_wcsicmp(cls, STATUSCLASSNAMEW) == 0)
            SetWindowSubclass(child, SurfaceProc, 1, reinterpret_cast<DWORD_PTR>(this));
    }
    PrepareMenu(GetMenu(window), true);
    SetDpi(GetDpiForWindow(window));
    Refresh();
}

void WindowAppearance::PrepareMenu(HMENU menu, bool topLevel) {
    if (!menu) return;
    for (int i = 0; i < GetMenuItemCount(menu); ++i) {
        wchar_t label[256]{};
        MENUITEMINFOW item{sizeof(item)};
        item.fMask = MIIM_STRING | MIIM_FTYPE | MIIM_SUBMENU;
        item.dwTypeData = label; item.cch = 256;
        if (!GetMenuItemInfoW(menu, static_cast<UINT>(i), TRUE, &item)) continue;
        if (item.hSubMenu) PrepareMenu(item.hSubMenu, false);
        if ((item.fType & MFT_SEPARATOR) != 0) continue;
        // Keep native menu-bar items for Windows layout, accessibility and
        // keyboard tracking. Only popup items use WM_DRAWITEM.
        if (topLevel) continue;
        auto data = std::make_unique<MenuItem>(MenuItem{label, false});
        item.fMask = MIIM_FTYPE | MIIM_DATA;
        item.fType |= MFT_OWNERDRAW;
        item.dwItemData = reinterpret_cast<ULONG_PTR>(data.get());
        SetMenuItemInfoW(menu, static_cast<UINT>(i), TRUE, &item);
        m_menuItems.push_back(std::move(data));
    }
}

void WindowAppearance::SetDpi(UINT dpi) {
    const UINT oldDpi = m_dpi;
    m_dpi = dpi ? dpi : 96;
    HFONT font = CreateFontW(-Scale(14), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH, L"Segoe UI");
    HFONT heading = CreateFontW(-Scale(22), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH, L"Segoe UI");
    NONCLIENTMETRICSW metrics{sizeof(metrics)};
    HFONT menuFont = SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, sizeof(metrics), &metrics, 0, m_dpi)
        ? CreateFontIndirectW(&metrics.lfMenuFont) : nullptr;
    if (!font || !heading) { if (font) DeleteObject(font); if (heading) DeleteObject(heading); if (menuFont) DeleteObject(menuFont); return; }
    for (HWND child = GetWindow(m_window, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT)) {
        SendMessageW(child, WM_SETFONT, reinterpret_cast<WPARAM>(font), FALSE);
        wchar_t cls[32]; GetClassNameW(child, cls, 32);
        if (_wcsicmp(cls, L"ComboBox") == 0) {
            SendMessageW(child, CB_SETITEMHEIGHT, static_cast<WPARAM>(-1), Scale(24));
            SendMessageW(child, CB_SETITEMHEIGHT, 0, Scale(24));
        }
        if (_wcsicmp(cls, WC_LISTVIEWW) == 0) {
            HWND header = ListView_GetHeader(child);
            SendMessageW(header, WM_SETFONT, reinterpret_cast<WPARAM>(font), FALSE);
            for (int i = 0; i < Header_GetItemCount(header); ++i)
                ListView_SetColumnWidth(child, i, MulDiv(ListView_GetColumnWidth(child, i), static_cast<int>(m_dpi), static_cast<int>(oldDpi)));
        }
    }
    if (m_font) DeleteObject(m_font);
    if (m_headingFont) DeleteObject(m_headingFont);
    if (m_menuFont) DeleteObject(m_menuFont);
    m_menuFont = menuFont;
    m_font = font; m_headingFont = heading;
    MARGINS margins{0, 0, m_mica ? Scale(72) : 0, 0};
    DwmExtendFrameIntoClientArea(m_window, &margins);
    InvalidateRect(m_window, nullptr, TRUE);
    DrawMenuBar(m_window);
}

void WindowAppearance::Refresh() {
    HIGHCONTRASTW contrast{sizeof(contrast)};
    m_highContrast = SystemParametersInfoW(SPI_GETHIGHCONTRAST, sizeof(contrast), &contrast, 0) &&
                     (contrast.dwFlags & HCF_HIGHCONTRASTON) != 0;
    DWORD light = 1, size = sizeof(light);
    RegGetValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
        L"AppsUseLightTheme", RRF_RT_REG_DWORD, nullptr, &light, &size);
    m_dark = light == 0 && !m_highContrast;
    UpdatePalette();
    const BOOL dark = m_dark;
    DwmSetWindowAttribute(m_window, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
    const DWM_SYSTEMBACKDROP_TYPE backdrop = m_highContrast ? DWMSBT_NONE : DWMSBT_MAINWINDOW;
    m_mica = SUCCEEDED(DwmSetWindowAttribute(m_window, DWMWA_SYSTEMBACKDROP_TYPE, &backdrop, sizeof(backdrop))) && !m_highContrast;
    MARGINS margins{0, 0, m_mica ? Scale(72) : 0, 0};
    DwmExtendFrameIntoClientArea(m_window, &margins);
    for (HWND child = GetWindow(m_window, GW_CHILD); child; child = GetWindow(child, GW_HWNDNEXT)) {
        wchar_t cls[32]; GetClassNameW(child, cls, 32);
        if (_wcsicmp(cls, WC_LISTVIEWW) == 0) {
            ListView_SetBkColor(child, m_control); ListView_SetTextBkColor(child, m_control); ListView_SetTextColor(child, m_text);
        }
        if (_wcsicmp(cls, PROGRESS_CLASSW) == 0) {
            SendMessageW(child, PBM_SETBKCOLOR, 0, m_control);
            SendMessageW(child, PBM_SETBARCOLOR, 0, m_accent);
        }
    }
    RedrawWindow(m_window, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_FRAME);
    DrawMenuBar(m_window);
    PaintMenuBar();
}

void WindowAppearance::UpdatePalette() {
    m_background = m_highContrast ? GetSysColor(COLOR_WINDOW) : (m_dark ? RGB(25,27,32) : RGB(246,248,251));
    m_control = m_highContrast ? GetSysColor(COLOR_WINDOW) : (m_dark ? RGB(35,38,44) : RGB(255,255,255));
    m_text = m_highContrast ? GetSysColor(COLOR_WINDOWTEXT) : (m_dark ? RGB(235,238,244) : RGB(26,34,48));
    m_border = m_highContrast ? GetSysColor(COLOR_WINDOWTEXT) : (m_dark ? RGB(78,84,96) : RGB(180,190,204));
    m_accent = m_highContrast ? GetSysColor(COLOR_HIGHLIGHT) : RGB(31,112,184);
    m_muted = m_highContrast ? GetSysColor(COLOR_GRAYTEXT) : m_dark ? RGB(160,168,182) : RGB(105,113,125);
    if (m_backgroundBrush) DeleteObject(m_backgroundBrush);
    if (m_controlBrush) DeleteObject(m_controlBrush);
    m_backgroundBrush = CreateSolidBrush(m_background);
    m_controlBrush = CreateSolidBrush(m_control);
    MENUINFO menuInfo{sizeof(menuInfo)};
    menuInfo.fMask = MIM_BACKGROUND | MIM_APPLYTOSUBMENUS;
    menuInfo.hbrBack = m_controlBrush;
    SetMenuInfo(GetMenu(m_window), &menuInfo);
}

void WindowAppearance::Paint(HDC dc) {
    RECT client; GetClientRect(m_window, &client);
    FillRect(dc, &client, m_backgroundBrush);
    RECT header{0, 0, client.right, Scale(72)};
    HTHEME theme = m_mica && m_bufferedPaint ? OpenThemeData(m_window, L"WINDOW") : nullptr;
    HDC buffered = nullptr;
    HPAINTBUFFER buffer = theme ? BeginBufferedPaint(dc, &header, BPBF_TOPDOWNDIB, nullptr, &buffered) : nullptr;
    HDC target = buffer ? buffered : dc;
    if (buffer) FillRect(target, &header, static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
    auto text = [&](const wchar_t* label, RECT rect, HFONT font) {
        HGDIOBJ old = SelectObject(target, font);
        SetBkMode(target, TRANSPARENT); SetTextColor(target, m_text);
        if (theme && buffer) {
            DTTOPTS options{sizeof(options)}; options.dwFlags = DTT_COMPOSITED | DTT_TEXTCOLOR; options.crText = m_text;
            DrawThemeTextEx(theme, target, WP_CAPTION, CS_ACTIVE, label, -1, DT_LEFT | DT_SINGLELINE | DT_VCENTER, &rect, &options);
        } else DrawTextW(target, label, -1, &rect, DT_LEFT | DT_SINGLELINE | DT_VCENTER);
        SelectObject(target, old);
    };
    text(L"KVC File Recovery", {Scale(24), Scale(8), client.right - Scale(24), Scale(38)}, m_headingFont);
    text(L"Find deleted files. Recover to a different disk.", {Scale(24), Scale(40), client.right - Scale(24), Scale(64)}, m_font);
    if (theme) CloseThemeData(theme);
    if (buffer) EndBufferedPaint(buffer, TRUE);
}

void WindowAppearance::PaintMenuBar(HDC supplied) {
    MENUBARINFO bar{sizeof(bar)};
    if (!GetMenuBarInfo(m_window, OBJID_MENU, 0, &bar)) return;
    RECT window{}; GetWindowRect(m_window, &window);
    RECT area = bar.rcBar; OffsetRect(&area, -window.left, -window.top);
    HDC windowDc = supplied ? supplied : GetWindowDC(m_window);
    if (!windowDc) return;
    // The menu bar lies in DWM's extended frame. Ordinary GDI text has zero
    // alpha there and can disappear despite correct RGB colors. Composite
    // an opaque buffered surface, including the glyphs.
    HDC buffered = nullptr;
    HPAINTBUFFER buffer = m_bufferedPaint ? BeginBufferedPaint(windowDc, &area, BPBF_TOPDOWNDIB, nullptr, &buffered) : nullptr;
    HDC dc = buffer ? buffered : windowDc;
    const int saved = SaveDC(dc);
    IntersectClipRect(dc, area.left, area.top, area.right, area.bottom);
    FillRect(dc, &area, m_controlBrush);
    SelectObject(dc, m_menuFont ? m_menuFont : m_font);
    SetBkMode(dc, TRANSPARENT);
    HMENU menu = GetMenu(m_window);
    for (int i = 0; i < GetMenuItemCount(menu); ++i) {
        RECT itemRect{};
        if (!GetMenuItemRect(m_window, menu, static_cast<UINT>(i), &itemRect)) continue;
        OffsetRect(&itemRect, -window.left, -window.top);
        wchar_t label[256]{};
        MENUITEMINFOW item{sizeof(item)};
        item.fMask = MIIM_STRING | MIIM_STATE; item.dwTypeData = label; item.cch = 256;
        if (!GetMenuItemInfoW(menu, static_cast<UINT>(i), TRUE, &item)) continue;
        const bool selected = (item.fState & MFS_HILITE) != 0;
        if (selected) { HBRUSH brush = CreateSolidBrush(m_accent); FillRect(dc, &itemRect, brush); DeleteObject(brush); }
        const COLORREF selectedText = m_highContrast ? GetSysColor(COLOR_HIGHLIGHTTEXT) : RGB(255,255,255);
        SetTextColor(dc, (item.fState & MFS_DISABLED) ? m_muted : selected ? selectedText : m_text);
        UINT uiState = static_cast<UINT>(SendMessageW(m_window, WM_QUERYUISTATE, 0, 0));
        DrawTextW(dc, label, -1, &itemRect, DT_CENTER | DT_SINGLELINE | DT_VCENTER | ((uiState & UISF_HIDEACCEL) ? DT_HIDEPREFIX : 0));
    }
    RestoreDC(dc, saved);
    if (buffer) {
        BufferedPaintSetAlpha(buffer, &area, 255);
        EndBufferedPaint(buffer, TRUE);
    }
    if (!supplied) ReleaseDC(m_window, windowDc);
}

void WindowAppearance::DrawButton(const DRAWITEMSTRUCT& item) {
    const bool disabled = (item.itemState & ODS_DISABLED) != 0;
    const bool pressed = (item.itemState & ODS_SELECTED) != 0;
    RECT rect = item.rcItem;
    FillRect(item.hDC, &rect, m_backgroundBrush);
    HBRUSH fill = CreateSolidBrush(pressed ? m_accent : m_control);
    HPEN pen = CreatePen(PS_SOLID, Scale(1), m_border);
    HGDIOBJ oldBrush = SelectObject(item.hDC, fill), oldPen = SelectObject(item.hDC, pen);
    RoundRect(item.hDC, rect.left, rect.top, rect.right, rect.bottom, Scale(8), Scale(8));
    SelectObject(item.hDC, oldBrush); SelectObject(item.hDC, oldPen); DeleteObject(fill); DeleteObject(pen);
    wchar_t label[128]; GetWindowTextW(item.hwndItem, label, 128);
    SetBkMode(item.hDC, TRANSPARENT);
    SetTextColor(item.hDC, disabled ? GetSysColor(COLOR_GRAYTEXT) : (pressed ? RGB(255,255,255) : m_text));
    HGDIOBJ oldFont = SelectObject(item.hDC, m_font);
    DrawTextW(item.hDC, label, -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE | ((item.itemState & ODS_NOACCEL) ? DT_HIDEPREFIX : 0));
    SelectObject(item.hDC, oldFont);
    if ((item.itemState & ODS_FOCUS) && !(item.itemState & ODS_NOFOCUSRECT)) {
        InflateRect(&rect, -Scale(4), -Scale(4)); DrawFocusRect(item.hDC, &rect);
    }
}

bool WindowAppearance::HandleMessage(UINT message, WPARAM wParam, LPARAM lParam, LRESULT& result) {
    if (!m_window) return false;
    switch (message) {
    case WM_NCPAINT: case WM_NCACTIVATE:
        result = DefWindowProcW(m_window, message, wParam, lParam);
        PaintMenuBar();
        return true;
    case WM_MENUSELECT:
        result = DefWindowProcW(m_window, message, wParam, lParam);
        PaintMenuBar();
        return true;
    case WM_MENUCHAR: {
        HMENU menu = reinterpret_cast<HMENU>(lParam);
        for (int i = 0; i < GetMenuItemCount(menu); ++i) {
            MENUITEMINFOW item{sizeof(item)}; item.fMask = MIIM_DATA | MIIM_STATE | MIIM_FTYPE;
            if (!GetMenuItemInfoW(menu, static_cast<UINT>(i), TRUE, &item) || !item.dwItemData ||
                !(item.fType & MFT_OWNERDRAW) || (item.fState & MFS_DISABLED)) continue;
            const auto& label = reinterpret_cast<const MenuItem*>(item.dwItemData)->label;
            for (size_t k = 0; k + 1 < label.size(); ++k) {
                if (label[k] != L'&') continue;
                if (label[k + 1] == L'&') { ++k; continue; }
                if (std::towlower(label[k + 1]) == std::towlower(static_cast<wchar_t>(LOWORD(wParam)))) {
                    result = MAKELRESULT(i, MNC_EXECUTE); return true;
                }
            }
        }
        break;
    }
    case WM_SETTINGCHANGE: case WM_THEMECHANGED: case WM_DWMCOMPOSITIONCHANGED:
        Refresh(); return false;
    case WM_ERASEBKGND:
        result = 1; return true;
    case WM_PAINT: {
        PAINTSTRUCT paint; HDC dc = BeginPaint(m_window, &paint); Paint(dc); EndPaint(m_window, &paint);
        result = 0; return true;
    }
    case WM_CTLCOLORSTATIC: case WM_CTLCOLORBTN: case WM_CTLCOLOREDIT: case WM_CTLCOLORLISTBOX: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        bool edit = message == WM_CTLCOLOREDIT || message == WM_CTLCOLORLISTBOX;
        SetTextColor(dc, m_text); SetBkColor(dc, edit ? m_control : m_background);
        result = reinterpret_cast<LRESULT>(edit ? m_controlBrush : m_backgroundBrush); return true;
    }
    case WM_DRAWITEM: {
        const auto& item = *reinterpret_cast<const DRAWITEMSTRUCT*>(lParam);
        if (item.CtlType == ODT_MENU && item.itemData) {
            const auto& menu = *reinterpret_cast<const MenuItem*>(item.itemData);
            HDC buffered = nullptr;
            HPAINTBUFFER buffer = m_bufferedPaint ? BeginBufferedPaint(item.hDC, &item.rcItem, BPBF_TOPDOWNDIB, nullptr, &buffered) : nullptr;
            HDC dc = buffer ? buffered : item.hDC;
            const bool selected = (item.itemState & ODS_SELECTED) != 0;
            HBRUSH brush = CreateSolidBrush(selected ? m_accent : m_control);
            FillRect(dc, &item.rcItem, brush); DeleteObject(brush);
            SetBkMode(dc, TRANSPARENT);
            const COLORREF selectedText = m_highContrast ? GetSysColor(COLOR_HIGHLIGHTTEXT) : RGB(255,255,255);
            SetTextColor(dc, (item.itemState & ODS_DISABLED) ? m_muted : (selected ? selectedText : m_text));
            RECT rect = item.rcItem; rect.left += Scale(menu.topLevel ? 8 : 16); rect.right -= Scale(16);
            HGDIOBJ oldFont = SelectObject(dc, m_font);
            const size_t tab = menu.label.find(L'\t');
            const std::wstring label = menu.label.substr(0, tab);
            DrawTextW(dc, label.c_str(), -1, &rect, DT_LEFT | DT_VCENTER | DT_SINGLELINE | ((item.itemState & ODS_NOACCEL) ? DT_HIDEPREFIX : 0));
            if (tab != std::wstring::npos) DrawTextW(dc, menu.label.c_str() + tab + 1, -1, &rect, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
            SelectObject(dc, oldFont);
            if (buffer) { BufferedPaintSetAlpha(buffer, &item.rcItem, 255); EndBufferedPaint(buffer, TRUE); }
            result = TRUE; return true;
        }
        if (item.CtlType == ODT_BUTTON) { DrawButton(item); result = TRUE; return true; }
        if (item.CtlType == ODT_COMBOBOX) {
            const bool selected = (item.itemState & ODS_SELECTED) && !(item.itemState & ODS_COMBOBOXEDIT);
            HBRUSH brush = CreateSolidBrush(selected ? m_accent : m_control);
            FillRect(item.hDC, &item.rcItem, brush); DeleteObject(brush);
            SetTextColor(item.hDC, selected ? RGB(255,255,255) : m_text); SetBkMode(item.hDC, TRANSPARENT);
            if (item.itemID != UINT_MAX) {
                LRESULT length = SendMessageW(item.hwndItem, CB_GETLBTEXTLEN, item.itemID, 0);
                if (length >= 0) {
                    std::wstring label(static_cast<size_t>(length) + 1, L'\0');
                    SendMessageW(item.hwndItem, CB_GETLBTEXT, item.itemID, reinterpret_cast<LPARAM>(label.data()));
                    RECT rect = item.rcItem; rect.left += Scale(8);
                    HGDIOBJ oldFont = SelectObject(item.hDC, m_font);
                    DrawTextW(item.hDC, label.c_str(), -1, &rect, DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);
                    SelectObject(item.hDC, oldFont);
                }
            }
            result = TRUE; return true;
        }
        break;
    }
    case WM_MEASUREITEM: {
        auto& item = *reinterpret_cast<MEASUREITEMSTRUCT*>(lParam);
        if (item.CtlType == ODT_MENU && item.itemData) {
            const auto& menu = *reinterpret_cast<const MenuItem*>(item.itemData);
            HDC dc = GetDC(m_window); HGDIOBJ oldFont = SelectObject(dc, m_font);
            RECT rect{}; DrawTextW(dc, menu.label.c_str(), -1, &rect, DT_CALCRECT | DT_SINGLELINE | DT_EXPANDTABS);
            item.itemWidth = static_cast<UINT>(rect.right + Scale(menu.topLevel ? 16 : 48));
            item.itemHeight = static_cast<UINT>(Scale(menu.topLevel ? 24 : 30));
            SelectObject(dc, oldFont); ReleaseDC(m_window, dc);
            result = TRUE; return true;
        }
        break;
    }
    case WM_NOTIFY: {
        const auto* hdr = reinterpret_cast<const NMHDR*>(lParam);
        if (hdr->code == NM_CUSTOMDRAW) {
            wchar_t cls[32]; GetClassNameW(hdr->hwndFrom, cls, 32);
            if (_wcsicmp(cls, L"Button") == 0 && (GetWindowLongPtrW(hdr->hwndFrom, GWL_STYLE) & BS_TYPEMASK) == BS_AUTOCHECKBOX) {
                const auto& draw = *reinterpret_cast<const NMCUSTOMDRAW*>(lParam);
                if (draw.dwDrawStage == CDDS_PREPAINT) {
                    FillRect(draw.hdc, &draw.rc, m_backgroundBrush);
                    RECT box = draw.rc; box.right = box.left + Scale(16); box.top += (box.bottom - box.top - Scale(16)) / 2; box.bottom = box.top + Scale(16);
                    UINT state = DFCS_BUTTONCHECK;
                    if (SendMessageW(hdr->hwndFrom, BM_GETCHECK, 0, 0) == BST_CHECKED) state |= DFCS_CHECKED;
                    if (!IsWindowEnabled(hdr->hwndFrom)) state |= DFCS_INACTIVE;
                    DrawFrameControl(draw.hdc, &box, DFC_BUTTON, state);
                    RECT text = draw.rc; text.left = box.right + Scale(8);
                    wchar_t label[128]; GetWindowTextW(hdr->hwndFrom, label, 128);
                    HGDIOBJ oldFont = SelectObject(draw.hdc, m_font);
                    SetTextColor(draw.hdc, IsWindowEnabled(hdr->hwndFrom) ? m_text : GetSysColor(COLOR_GRAYTEXT)); SetBkMode(draw.hdc, TRANSPARENT);
                    DrawTextW(draw.hdc, label, -1, &text, DT_SINGLELINE | DT_VCENTER);
                    if (GetFocus() == hdr->hwndFrom) DrawFocusRect(draw.hdc, &text);
                    SelectObject(draw.hdc, oldFont);
                    result = CDRF_SKIPDEFAULT; return true;
                }
            }
        }
        break;
    }
    }
    return false;
}

LRESULT CALLBACK WindowAppearance::SurfaceProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam, UINT_PTR id, DWORD_PTR data) {
    auto& self = *reinterpret_cast<WindowAppearance*>(data);
    if (message == WM_PAINT) {
        PAINTSTRUCT paint; HDC dc = BeginPaint(hwnd, &paint);
        RECT client; GetClientRect(hwnd, &client); FillRect(dc, &client, self.m_backgroundBrush);
        HGDIOBJ oldFont = SelectObject(dc, self.m_font); SetBkMode(dc, TRANSPARENT); SetTextColor(dc, self.m_text);
        wchar_t cls[32]; GetClassNameW(hwnd, cls, 32);
        if (_wcsicmp(cls, STATUSCLASSNAMEW) == 0) {
            const size_t length = LOWORD(SendMessageW(hwnd, SB_GETTEXTLENGTHW, 0, 0));
            std::wstring label(length + 1, L'\0');
            SendMessageW(hwnd, SB_GETTEXTW, 0, reinterpret_cast<LPARAM>(label.data()));
            client.left += self.Scale(12); client.right -= self.Scale(20);
            DrawTextW(dc, label.c_str(), -1, &client, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
        } else for (int i = 0; i < Header_GetItemCount(hwnd); ++i) {
            RECT rect; Header_GetItemRect(hwnd, i, &rect);
            wchar_t label[128]; HDITEMW item{}; item.mask = HDI_TEXT; item.pszText = label; item.cchTextMax = 128;
            if (Header_GetItem(hwnd, i, &item)) { rect.left += self.Scale(10); DrawTextW(dc, label, -1, &rect, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS); }
        }
        SelectObject(dc, oldFont); EndPaint(hwnd, &paint); return 0;
    }
    if (message == WM_NCDESTROY) RemoveWindowSubclass(hwnd, SurfaceProc, id);
    return DefSubclassProc(hwnd, message, wParam, lParam);
}
}
