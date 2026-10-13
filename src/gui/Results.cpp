// Virtual results, filtering, sorting and selection menus.

#include "gui/RecoveryApplication.h"
#include <algorithm>
#include <cwctype>

namespace KVC {

void RecoveryApplication::OnListNotification(LPNMHDR header) {
    {
        LPNMHDR pnmh = header;
        if (pnmh->hwndFrom == m_hwndListView) {
            if (pnmh->code == LVN_COLUMNCLICK) {
                OnColumnClick(reinterpret_cast<LPNMLISTVIEW>(header)); // Sort by column
            }
            else if (pnmh->code == LVN_GETDISPINFO) {
                NMLVDISPINFOW* pDispInfo = reinterpret_cast<NMLVDISPINFOW*>(header);
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
                                     file.quality == RecoveryQuality::Full ? L"Full" :
                                     file.quality == RecoveryQuality::Partial ? L"Partial" :
                                     file.quality == RecoveryQuality::MetadataOnly ? L"Metadata only" : L"Unavailable", _TRUNCATE);
                            break;
                        }
                    }
                }
            }
            else if (pnmh->code == NM_RCLICK) {
                OnListViewRightClick(reinterpret_cast<LPNMITEMACTIVATE>(header)); // Show context menu
            }
        }
    }
}

// Refresh ListView contents after scan update.
void RecoveryApplication::PopulateResultsList() {
    // Each arriving candidate is filtered once. Changing the user's filter
    // still rebuilds the view, but receiving n files no longer does n sweeps.
    int typeIndex = static_cast<int>(SendMessage(GetDlgItem(m_hwnd, TYPE_COMBO_ID), CB_GETCURSEL, 0, 0));
    wchar_t buffer[MAX_PATH]; GetWindowTextW(GetDlgItem(m_hwnd, FILTER_EDIT_ID), buffer, MAX_PATH);
    std::wstring search = buffer;
    std::transform(search.begin(), search.end(), search.begin(), ::towlower);
    size_t count;
    {
        std::lock_guard<std::mutex> lock(m_filesMutex);
        while (m_displayedResultCount < m_deletedFiles.size()) {
            const auto& file = m_deletedFiles[m_displayedResultCount++];
            if (!IsFileOfType(file.name, typeIndex)) continue;
            if (!search.empty()) {
                std::wstring lower = file.name;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                if (lower.find(search) == std::wstring::npos) continue;
            }
            m_filteredFiles.push_back(file);
        }
        count = m_filteredFiles.size();
    }
    ListView_SetItemCountEx(m_hwndListView, static_cast<int>(count), LVSICF_NOSCROLL);
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
    if (m_isSorting) return;
    int typeIndex = static_cast<int>(SendMessage(GetDlgItem(m_hwnd, TYPE_COMBO_ID), CB_GETCURSEL, 0, 0));
    wchar_t buffer[MAX_PATH];
    GetWindowTextW(GetDlgItem(m_hwnd, FILTER_EDIT_ID), buffer, MAX_PATH);
    std::wstring searchName = buffer;
    std::transform(searchName.begin(), searchName.end(), searchName.begin(), ::towlower);

    size_t totalCount = 0;
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
        m_displayedResultCount = totalCount = m_deletedFiles.size();
    }

    // Update virtual ListView item count.
    ListView_SetItemCountEx(m_hwndListView, m_filteredFiles.size(), LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);

    if (!m_filteredFiles.empty()) {
        ListView_RedrawItems(m_hwndListView, 0, static_cast<int>(m_filteredFiles.size()) - 1);
    }
    UpdateWindow(m_hwndListView);

    wchar_t status[256];
    swprintf_s(status, L"Showing %zu of %zu files          |          💡 TIP: Use Shift/Ctrl+Arrows to select, Ctrl+A for All",
               m_filteredFiles.size(), totalCount);
    UpdateStatusBar(status);
}

// Handle column header clicks for sorting.
void RecoveryApplication::OnColumnClick(LPNMLISTVIEW pnmv) {
    if (m_isScanning || m_isRecovering || m_isSorting) return;
    // Update sorting state on UI thread.
    if (pnmv->iSubItem == m_sortColumn) {
        m_sortAscending = !m_sortAscending;
    } else {
        m_sortColumn = pnmv->iSubItem;
        m_sortAscending = true;
    }

    UpdateStatusBar(L"Sorting files... please wait");

    // Launch background sorting thread to avoid UI freeze on large datasets.
    m_isSorting = true;
    m_sortThread = std::make_unique<std::thread>([this, col = m_sortColumn, asc = m_sortAscending]() {

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

    });
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

void RecoveryApplication::OnSortComplete() {
    if (m_sortThread && m_sortThread->joinable()) m_sortThread->join();
    m_isSorting = false;
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
}

} // namespace KVC
