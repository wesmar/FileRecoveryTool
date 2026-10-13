// ============================================================================
// OverlapResolver.h - deleted files that claim the same clusters
// ============================================================================
// A cluster freed by one delete and taken by a file written later holds the
// later file's bytes - and when that file is deleted too, the bitmap shows
// the cluster free again. Of the deleted files that claim one cluster, the
// one written last owns it; the others are overwritten there. Which one was
// written last is what each file system records: the MFT record's log
// sequence number, the journal transaction, the creation time on FAT.
// ============================================================================

#pragma once

#include "core/RecoveryCandidate.h"
#include <vector>

namespace KVC {

// Marks the candidates whose clusters a newer candidate also claims.
// Returns how many were marked.
size_t ResolveClusterOverlaps(std::vector<RecoveryCandidate>& candidates);

} // namespace KVC
