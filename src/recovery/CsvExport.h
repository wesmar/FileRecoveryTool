// ============================================================================
// CsvExport.h - Scan results as CSV
// ============================================================================
// UTF-8 with a byte order mark (Excel reads non-ASCII names right), fields
// quoted as RFC 4180 asks.
// ============================================================================

#pragma once

#include "core/RecoveryCandidate.h"
#include <string>
#include <vector>

namespace KVC {

bool ExportCandidatesToCsv(const std::wstring& path, const std::vector<RecoveryCandidate>& files);

} // namespace KVC
