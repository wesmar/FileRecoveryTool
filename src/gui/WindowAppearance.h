#pragma once
#include <Windows.h>
#include <memory>
#include <string>
#include <vector>

namespace KVC {

// Documented Win32/DWM APIs only. The system chooses the Mica fallback.
class WindowAppearance {
public:
    ~WindowAppearance();
    void Initialize(HWND window);
    void SetDpi(UINT dpi);
    int Scale(int value) const { return MulDiv(value, static_cast<int>(m_dpi), 96); }
    int Unscale(int value) const { return MulDiv(value, 96, static_cast<int>(m_dpi)); }
    bool HandleMessage(UINT message, WPARAM wParam, LPARAM lParam, LRESULT& result);
private:
#ifdef FRT_GUI_SMOKE
    friend struct GuiSmokeTest;
#endif
    void Refresh();
    void UpdatePalette();
    void Paint(HDC dc);
    void PaintMenuBar(HDC dc = nullptr);
    void DrawButton(const DRAWITEMSTRUCT& item);
    void PrepareMenu(HMENU menu, bool topLevel);
    struct MenuItem { std::wstring label; bool topLevel; };
    std::vector<std::unique_ptr<MenuItem>> m_menuItems;
    static LRESULT CALLBACK SurfaceProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam,
                                      UINT_PTR id, DWORD_PTR data);
    HWND m_window = nullptr;
    HFONT m_font = nullptr;
    HFONT m_headingFont = nullptr;
    HFONT m_menuFont = nullptr;
    HBRUSH m_backgroundBrush = nullptr;
    HBRUSH m_controlBrush = nullptr;
    UINT m_dpi = 96;
    bool m_dark = false;
    bool m_highContrast = false;
    bool m_mica = false;
    bool m_bufferedPaint = false;
    COLORREF m_background = 0;
    COLORREF m_control = 0;
    COLORREF m_text = 0;
    COLORREF m_border = 0;
    COLORREF m_accent = 0;
    COLORREF m_muted = 0;
};
}
