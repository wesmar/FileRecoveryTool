// ============================================================================
// FileSignatures.h - File Signature Definitions
// ============================================================================
// Defines binary signatures (magic numbers) for supported file formats.
// Used by the FileCarver to identify file types in raw disk data.
// ============================================================================
#pragma once

#include <cstdint>
#include <vector>

namespace KVC {

struct FileSignature {
    const char* extension;
    const uint8_t* signature;
    size_t signatureSize;
    const wchar_t* description;
};

class FileSignatures {
public:
    static const FileSignature PNG;
    static const FileSignature JPEG;
    static const FileSignature GIF;
    static const FileSignature BMP;
    static const FileSignature PDF;
    static const FileSignature ZIP;
    static const FileSignature DOCX;
    static const FileSignature XLSX;
    static const FileSignature PPTX;
    static const FileSignature DOC;
    static const FileSignature XLS;
    static const FileSignature PPT;
    static const FileSignature MP4;
    static const FileSignature AVI;
    static const FileSignature MKV;
    static const FileSignature MP3;
    static const FileSignature WAV;
    static const FileSignature RAR;
    static const FileSignature SEVEN_ZIP;
    
    static std::vector<FileSignature> GetAllSignatures();
};

// Signature byte arrays
namespace Signatures {
    constexpr uint8_t PNG_SIG[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    constexpr uint8_t JPEG_SIG[] = {0xFF, 0xD8, 0xFF};
    constexpr uint8_t GIF_SIG[] = {0x47, 0x49, 0x46, 0x38};
    constexpr uint8_t BMP_SIG[] = {0x42, 0x4D};
    constexpr uint8_t PDF_SIG[] = {0x25, 0x50, 0x44, 0x46};
    constexpr uint8_t ZIP_SIG[] = {0x50, 0x4B, 0x03, 0x04};
    constexpr uint8_t OLE2_SIG[] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    constexpr uint8_t MP4_SIG[] = {0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70};
    constexpr uint8_t AVI_SIG[] = {0x52, 0x49, 0x46, 0x46};
    constexpr uint8_t MKV_SIG[] = {0x1A, 0x45, 0xDF, 0xA3};
    constexpr uint8_t MP3_SIG[] = {0xFF, 0xFB};
    constexpr uint8_t WAV_SIG[] = {0x52, 0x49, 0x46, 0x46};
    constexpr uint8_t RAR_SIG[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07};
    constexpr uint8_t SEVEN_ZIP_SIG[] = {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C};
}

} // namespace KVC