// ============================================================================
// main_cli.h - Command-Line Interface Mode
// ============================================================================
// Provides CLI access to all recovery features for automation and scripting.
// Supports batch operations, progress reporting, and diagnostic output.
// ============================================================================

#pragma once

#include <Windows.h>

namespace KVC {

// Forward declarations
struct CarvingStatistics;

// Main CLI entry point - called from wWinMain when command-line args detected
int RunCLI(int argc, LPWSTR* argv);

// Print carving diagnostics
void PrintDiagnostics(const CarvingStatistics& stats);

} // namespace KVC