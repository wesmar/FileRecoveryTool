// FileSignatures.cpp

#include "FileSignatures.h"
#include <climits>

namespace KVC {

const FileSignature FileSignatures::PNG = {
    "png", Signatures::PNG_SIG, sizeof(Signatures::PNG_SIG), L"PNG image"
};

const FileSignature FileSignatures::JPEG = {
    "jpg", Signatures::JPEG_SIG, sizeof(Signatures::JPEG_SIG), L"JPEG image"
};

const FileSignature FileSignatures::GIF = {
    "gif", Signatures::GIF_SIG, sizeof(Signatures::GIF_SIG), L"GIF image"
};

const FileSignature FileSignatures::BMP = {
    "bmp", Signatures::BMP_SIG, sizeof(Signatures::BMP_SIG), L"BMP image"
};

const FileSignature FileSignatures::PDF = {
    "pdf", Signatures::PDF_SIG, sizeof(Signatures::PDF_SIG), L"PDF document"
};

const FileSignature FileSignatures::ZIP = {
    "zip", Signatures::ZIP_SIG, sizeof(Signatures::ZIP_SIG), L"ZIP archive"
};

const FileSignature FileSignatures::DOCX = {
    "docx", Signatures::ZIP_SIG, sizeof(Signatures::ZIP_SIG), L"Word document (DOCX)"
};

const FileSignature FileSignatures::XLSX = {
    "xlsx", Signatures::ZIP_SIG, sizeof(Signatures::ZIP_SIG), L"Excel spreadsheet (XLSX)"
};

const FileSignature FileSignatures::PPTX = {
    "pptx", Signatures::ZIP_SIG, sizeof(Signatures::ZIP_SIG), L"PowerPoint presentation (PPTX)"
};

const FileSignature FileSignatures::DOC = {
    "doc", Signatures::OLE2_SIG, sizeof(Signatures::OLE2_SIG), L"Word document (DOC)"
};

const FileSignature FileSignatures::XLS = {
    "xls", Signatures::OLE2_SIG, sizeof(Signatures::OLE2_SIG), L"Excel spreadsheet (XLS)"
};

const FileSignature FileSignatures::PPT = {
    "ppt", Signatures::OLE2_SIG, sizeof(Signatures::OLE2_SIG), L"PowerPoint presentation (PPT)"
};

const FileSignature FileSignatures::MP4 = {
    "mp4", Signatures::MP4_SIG, sizeof(Signatures::MP4_SIG), L"MP4 video"
};

const FileSignature FileSignatures::AVI = {
    "avi", Signatures::AVI_SIG, sizeof(Signatures::AVI_SIG), L"AVI video"
};

const FileSignature FileSignatures::MKV = {
    "mkv", Signatures::MKV_SIG, sizeof(Signatures::MKV_SIG), L"MKV video"
};

const FileSignature FileSignatures::MP3 = {
    "mp3", Signatures::MP3_SIG, sizeof(Signatures::MP3_SIG), L"MP3 audio"
};

const FileSignature FileSignatures::WAV = {
    "wav", Signatures::WAV_SIG, sizeof(Signatures::WAV_SIG), L"WAV audio"
};

const FileSignature FileSignatures::RAR = {
    "rar", Signatures::RAR_SIG, sizeof(Signatures::RAR_SIG), L"RAR archive"
};

const FileSignature FileSignatures::SEVEN_ZIP = {
    "7z", Signatures::SEVEN_ZIP_SIG, sizeof(Signatures::SEVEN_ZIP_SIG), L"7-Zip archive"
};

std::vector<FileSignature> FileSignatures::GetAllSignatures() {
    return {
        PNG, JPEG, GIF, BMP, PDF,
        ZIP, DOCX, XLSX, PPTX,
        DOC, XLS, PPT,
        MP4, AVI, MKV,
        MP3, WAV,
        RAR, SEVEN_ZIP
    };
}

} // namespace KVC
