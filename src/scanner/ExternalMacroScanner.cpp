#include "scanner/ExternalMacroScanner.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")

#include <algorithm>
#include <execution>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;

namespace scanner {


static const std::vector<std::string> TIER1_SIGNATURES = {

};

static const std::vector<std::string> TIER2_SIGNATURES = {
    "toggleUI",
    "/getConfig",
    "/saveConfig",
    "hwidLogin",
    "rapid_fire",
    "auto_click",
    "triggerbot",
    "no_recoil",
    "macros-unprotected",
};


static std::string ComputeMD5(const std::string& filepath) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;

    std::ifstream file(filepath, std::ios::binary);
    if (!file) return "";

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return "";
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }

    char buffer[65536];
    while (file.read(buffer, sizeof(buffer)) || file.gcount())
        CryptHashData(hHash, (BYTE*)buffer, (DWORD)file.gcount(), 0);

    BYTE hash[16];
    DWORD hashLen = 16;
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);

    std::ostringstream oss;
    for (auto b : hash)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return oss.str();
}

static uint32_t PeHeaderCRC32(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return 0;

    char header[1024] = {};
    file.read(header, sizeof(header));
    size_t bytesRead = (size_t)file.gcount();

    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < bytesRead; i++) {
        crc ^= (uint8_t)header[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return ~crc;
}


static const std::unordered_set<std::string> KNOWN_BAD_MD5 = {
};

static const std::unordered_set<uint32_t> KNOWN_BAD_PE_CRC = {
};


struct ScanFileResult {
    std::string filepath;
    bool detected = false;
    MacroDetectReason reason = MacroDetectReason::NONE;
    std::string matchedSignature;
    int tier2Score = 0;
};

static ScanFileResult ScanFile(const fs::path& path) {
    ScanFileResult result;
    result.filepath = path.string();

    std::error_code ec;
    auto fileSize = fs::file_size(path, ec);
    if (ec || fileSize < 10240 || fileSize > 524288000)
        return result;

    std::string md5 = ComputeMD5(path.string());
    if (!md5.empty() && KNOWN_BAD_MD5.count(md5)) {
        result.detected = true;
        result.reason = MacroDetectReason::MD5_MATCH;
        result.matchedSignature = md5;
        return result;
    }

    uint32_t peCRC = PeHeaderCRC32(path.string());
    if (KNOWN_BAD_PE_CRC.count(peCRC)) {
        result.detected = true;
        result.reason = MacroDetectReason::PE_CRC_MATCH;
        result.matchedSignature = std::to_string(peCRC);
        return result;
    }

    std::ifstream file(path.string(), std::ios::binary);
    if (!file) return result;

    size_t readSize = (size_t)std::min(fileSize, (uintmax_t)4194304);
    std::string content(readSize, '\0');
    file.read(content.data(), readSize);

    for (const auto& sig : TIER1_SIGNATURES) {
        if (content.find(sig) != std::string::npos) {
            result.detected = true;
            result.reason = MacroDetectReason::TIER1_STRING;
            result.matchedSignature = sig;
            return result;
        }
    }

    for (const auto& sig : TIER2_SIGNATURES) {
        if (content.find(sig) != std::string::npos)
            result.tier2Score++;
    }
    if (result.tier2Score >= 2) {
        result.detected = true;
        result.reason = MacroDetectReason::TIER2_STRING_SCORE;
        result.matchedSignature = "score=" + std::to_string(result.tier2Score);
    }

    return result;
}


ExternalMacroScanner::ExternalMacroScanner() = default;

ExternalMacroScanner::~ExternalMacroScanner() {
    Cancel();
}

void ExternalMacroScanner::Start(const std::string& rootPath, const std::string& generatedBy) {
    if (m_running.load()) {
        return;
    }
    m_running = true;
    m_cancel = false;
    m_progress = 0.0f;
    m_filesScanned = 0;
    m_summary = MacroScanSummary();
    m_lastError.clear();
    m_worker = std::thread(&ExternalMacroScanner::Worker, this, rootPath, generatedBy);
}

void ExternalMacroScanner::Cancel() {
    if (m_running.load()) {
        m_cancel = true;
        if (m_worker.joinable()) {
            m_worker.join();
        }
        m_running = false;
    }
}

bool ExternalMacroScanner::IsRunning() const {
    return m_running.load();
}

float ExternalMacroScanner::Progress() const {
    return m_progress.load();
}

const MacroScanSummary& ExternalMacroScanner::Summary() const {
    return m_summary;
}

std::string ExternalMacroScanner::LastError() const {
    return m_lastError;
}

std::string ExternalMacroScanner::NowTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

void ExternalMacroScanner::Worker(std::string rootPath, std::string generatedBy) {
    try {
        std::vector<fs::path> exePaths;
        std::atomic<std::size_t> filesFound{0};

        for (auto& entry : fs::recursive_directory_iterator(rootPath,
            fs::directory_options::skip_permission_denied)) {
            if (m_cancel.load()) break;

            std::error_code ec;
            if (entry.is_regular_file(ec) && !ec) {
                auto ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext == ".exe") {
                    exePaths.push_back(entry.path());
                    filesFound++;
                    m_progress = 0.5f * std::min(1.0f, static_cast<float>(filesFound) / 5000.0f);
                }
            }
        }

        m_summary.scanPath = rootPath;
        m_summary.generatedBy = generatedBy;
        m_filesScanned = 0;
        std::size_t totalFiles = exePaths.size();

        if (totalFiles == 0) {
            m_summary.filesScanned = 0;
            m_progress = 1.0f;
            m_running = false;
            return;
        }

        std::vector<ScanFileResult> results(exePaths.size());
        std::mutex printMutex;
        std::atomic<std::size_t> scannedCount{0};

        std::transform(std::execution::par_unseq,
            exePaths.begin(), exePaths.end(),
            results.begin(),
            [&](const fs::path& path) -> ScanFileResult {
                if (m_cancel.load())
                    return ScanFileResult{path.string(), false, MacroDetectReason::NONE, "", 0};

                auto r = ScanFile(path);
                scannedCount++;
                m_progress = 0.5f + 0.5f * (static_cast<float>(scannedCount.load()) / static_cast<float>(totalFiles));

                if (r.detected) {
                    std::lock_guard<std::mutex> lock(printMutex);
                    MacroDetection det;
                    det.timestamp = NowTimestamp();
                    det.filePath = r.filepath;
                    det.reason = r.reason;
                    det.matchedSignature = r.matchedSignature;
                    det.tier2Score = r.tier2Score;
                    m_summary.detections.push_back(det);
                    m_summary.detectCount++;
                }
                return r;
            });

        m_summary.filesScanned = totalFiles;
        m_progress = 1.0f;

    } catch (const std::exception& e) {
        m_lastError = e.what();
    }

    m_running = false;
}

}
