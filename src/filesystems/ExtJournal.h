// ============================================================================
// ExtJournal.h - the jbd2 journal of an ext3/ext4 volume as a block archive
// ============================================================================
// Every metadata block a transaction logged stays in the journal until the
// log wraps over it - long after the transaction was checkpointed and the
// journal marked empty. Here every descriptor block in the log is read, and
// for each file system block the copies the log still holds are listed,
// newest first: inode table blocks from before a delete, directory blocks
// from before their entries were wiped, extent and indirect blocks.
// ============================================================================

#pragma once

#include "filesystems/ExtFilesystem.h"
#include <atomic>
#include <unordered_map>
#include <vector>

namespace KVC {

struct ExtJournalCopy {
    uint32_t sequence = 0;          // the transaction
    uint64_t journalBlock = 0;      // where the copy lies in the log
    bool escaped = false;           // its first four bytes were the journal magic
};

class ExtJournal {
public:
    explicit ExtJournal(ExtVolume& volume);

    bool Load(std::atomic<bool>& shouldStop);
    bool Loaded() const { return m_loaded; }

    // the copies of a file system block, newest first; null when none
    const std::vector<ExtJournalCopy>* Copies(uint64_t fsBlock) const;
    const std::unordered_map<uint64_t, std::vector<ExtJournalCopy>>& All() const { return m_copies; }
    std::vector<uint8_t> ReadCopy(const ExtJournalCopy& copy);

    // newest copy accepted by valid, or the block as it is on the volume
    std::vector<uint8_t> NewestValid(uint64_t fsBlock, bool (*valid)(const std::vector<uint8_t>&));

private:
    std::vector<uint8_t> ReadLogBlock(uint64_t logBlock);

    ExtVolume& m_volume;
    bool m_loaded = false;
    std::vector<ClusterRun> m_runs;             // the journal inode's blocks
    uint64_t m_first = 0;                       // first log block after the superblock
    uint64_t m_maxLen = 0;                      // log blocks
    uint32_t m_incompat = 0;
    std::unordered_map<uint64_t, std::vector<ExtJournalCopy>> m_copies;
};

} // namespace KVC
