#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

namespace scanner {

enum class Severity {
    Detect,
    Warning,
    Suspicious
};

struct Detection {
    std::string timestamp;
    std::string message;
    Severity severity{Severity::Detect};
    uintptr_t address{0};
    uintptr_t baseAddress{0};
    std::vector<uintptr_t> hitAddresses;
    std::size_t hits{0};
};

struct ScanOptions {
    bool deepScan{false};
    std::string generatedBy;
};

struct ScanSummary {
    uint32_t pid{0};
    std::string processStartTime;
    std::string scanType;
    std::string generatedBy;
    std::vector<Detection> detections;
    std::size_t detectCount{0};
    std::size_t warningCount{0};
    std::size_t suspiciousCount{0};
};

class MemoryScanner {
public:
    MemoryScanner();
    ~MemoryScanner();

    void Start(uint32_t pid, const ScanOptions& options, std::string processStartTime);
    void Cancel();
    bool IsRunning() const;
    float Progress() const;
    const ScanSummary& Summary() const;
    std::string LastError() const;

private:
    void Worker(uint32_t pid, ScanOptions options, std::string processStartTime);
    void RegisterDetection(ScanSummary& summary, std::string key, Severity severity, uintptr_t address, uintptr_t baseAddress);
    static std::string NowTimestamp();
    static std::string ToLower(std::string value);
    static std::vector<std::string> CheckWindowsServices();

    std::atomic<bool> m_running{false};
    std::atomic<bool> m_cancel{false};
    std::atomic<float> m_progress{0.0f};
    std::thread m_worker;
    ScanSummary m_summary;
    std::string m_lastError;
};

const std::vector<std::string>& NormalScanStrings();
const std::vector<std::string>& DeepScanStrings();

}
