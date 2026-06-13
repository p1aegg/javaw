#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>
#include <unordered_set>

namespace scanner {

enum class MacroDetectReason {
    MD5_MATCH,
    PE_CRC_MATCH,
    TIER1_STRING,
    TIER2_STRING_SCORE,
    NONE
};

struct MacroDetection {
    std::string timestamp;
    std::string filePath;
    MacroDetectReason reason{MacroDetectReason::NONE};
    std::string matchedSignature;
    int tier2Score{0};
};

struct MacroScanSummary {
    std::string scanPath;
    std::string scanType{"External Macro Scan"};
    std::string generatedBy;
    std::vector<MacroDetection> detections;
    std::size_t filesScanned{0};
    std::size_t detectCount{0};
};

class ExternalMacroScanner {
public:
    ExternalMacroScanner();
    ~ExternalMacroScanner();

    void Start(const std::string& rootPath, const std::string& generatedBy = "");
    void Cancel();
    bool IsRunning() const;
    float Progress() const;
    const MacroScanSummary& Summary() const;
    std::string LastError() const;

private:
    void Worker(std::string rootPath, std::string generatedBy);
    static std::string NowTimestamp();

    std::atomic<bool> m_running{false};
    std::atomic<bool> m_cancel{false};
    std::atomic<float> m_progress{0.0f};
    std::atomic<std::size_t> m_filesScanned{0};
    std::thread m_worker;
    MacroScanSummary m_summary;
    std::string m_lastError;
};

}
