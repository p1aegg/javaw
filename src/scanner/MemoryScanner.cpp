#include "scanner/MemoryScanner.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <functional>
#include <queue>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <intrin.h>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace scanner {

using HitFn = std::function<void(int)>;

struct AhoCorasick {
    struct State {
        int next[256];
        int fail;
        std::vector<int> output;
        State() : fail(0) { std::fill(next, next + 256, -1); }
    };

    std::vector<State> states;

    AhoCorasick() {
        states.emplace_back();
    }

    void AddPattern(const std::string& pat, int patternIndex) {
        int cur = 0;
        for (unsigned char c : pat) {
            if (states[cur].next[c] == -1) {
                states[cur].next[c] = static_cast<int>(states.size());
                states.emplace_back();
            }
            cur = states[cur].next[c];
        }
        states[cur].output.push_back(patternIndex);
    }

    void Build() {
        std::queue<int> q;
        for (int c = 0; c < 256; c++) {
            int s = states[0].next[c];
            if (s == -1) {
                states[0].next[c] = 0;
            } else {
                states[s].fail = 0;
                q.push(s);
            }
        }
        while (!q.empty()) {
            int r = q.front(); q.pop();
            for (int idx : states[states[r].fail].output)
                states[r].output.push_back(idx);

            for (int c = 0; c < 256; c++) {
                int s = states[r].next[c];
                if (s == -1) {
                    states[r].next[c] = states[states[r].fail].next[c];
                } else {
                    states[s].fail = states[states[r].fail].next[c];
                    q.push(s);
                }
            }
        }
    }

    bool Search(const char* buf, size_t len, HitFn hit) const {
        int cur = 0;
        bool any = false;
        for (size_t i = 0; i < len; i++) {
            cur = states[cur].next[static_cast<unsigned char>(buf[i])];
            if (!states[cur].output.empty()) {
                for (int idx : states[cur].output) {
                    hit(idx);
                    any = true;
                }
            }
        }
        return any;
    }
};

namespace {

struct CpuInfo {
    int cores;
    int logicalProcessors;
    bool hasSSE2;
    bool hasAVX;
    bool hasAVX2;
    bool hasAVX512;
    size_t cacheSizeL3;
};

CpuInfo DetectCpuInfo() {
    CpuInfo info = {};

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    info.logicalProcessors = sysInfo.dwNumberOfProcessors;

    info.cores = info.logicalProcessors;

    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0);
    int maxLeaf = cpuInfo[0];

    if (maxLeaf >= 1) {
        __cpuid(cpuInfo, 1);
        info.hasSSE2 = (cpuInfo[3] & (1 << 26)) != 0;
        info.hasAVX = (cpuInfo[2] & (1 << 28)) != 0;
    }

    if (maxLeaf >= 7) {
        __cpuidex(cpuInfo, 7, 0);
        info.hasAVX2 = (cpuInfo[1] & (1 << 5)) != 0;
        info.hasAVX512 = (cpuInfo[1] & (1 << 16)) != 0;
    }

    if (maxLeaf >= 4) {
        for (int i = 0; i < 4; ++i) {
            __cpuidex(cpuInfo, 4, i);
            int cacheType = (cpuInfo[0] >> 5) & 0x7;
            if (cacheType == 3) {
                int ways = ((cpuInfo[1] >> 22) & 0x3FF) + 1;
                int partitions = ((cpuInfo[1] >> 12) & 0x3FF) + 1;
                int lineSize = (cpuInfo[1] & 0xFFF) + 1;
                int sets = cpuInfo[2] + 1;
                info.cacheSizeL3 = ways * partitions * lineSize * sets;
                break;
            }
        }
    }

    if (info.cacheSizeL3 == 0) {
        info.cacheSizeL3 = 8 * 1024 * 1024;
    }

    return info;
}

} // end anonymous namespace

struct ScanConfig {
    size_t chunkSize;
    int threadCount;
    bool useSIMD;
};

ScanConfig OptimizeScanConfig(const CpuInfo& cpu) {
    ScanConfig config = {};

    size_t optimalChunk = cpu.cacheSizeL3 / 4;
    config.chunkSize = std::clamp(optimalChunk, size_t(1 * 1024 * 1024), size_t(64 * 1024 * 1024));

    config.threadCount = std::min(cpu.logicalProcessors, cpu.cores * 2);
    config.threadCount = std::clamp(config.threadCount, 1, 16);

    config.useSIMD = cpu.hasAVX2 || cpu.hasAVX || cpu.hasSSE2;

    return config;
}

constexpr SIZE_T kDefaultChunkSize = 16 * 1024 * 1024;

std::string NormalizeFullwidthUnicode(const std::string& str) {
    std::string result;
    result.reserve(str.size());
    
    size_t i = 0;
    while (i < str.size()) {
        unsigned char byte1 = static_cast<unsigned char>(str[i]);
        
        if (byte1 == 0xEF && i + 2 < str.size()) {
            unsigned char byte2 = static_cast<unsigned char>(str[i + 1]);
            unsigned char byte3 = static_cast<unsigned char>(str[i + 2]);
            
            if (byte2 == 0xBC && byte3 >= 0xA1 && byte3 <= 0xBA) {
                result += static_cast<char>('A' + (byte3 - 0xA1));
                i += 3;
                continue;
            }
            if (byte2 == 0xBD && byte3 >= 0x81 && byte3 <= 0x9A) {
                result += static_cast<char>('a' + (byte3 - 0x81));
                i += 3;
                continue;
            }
            if (byte2 == 0xBC && byte3 >= 0x90 && byte3 <= 0x99) {
                result += static_cast<char>('0' + (byte3 - 0x90));
                i += 3;
                continue;
            }
        }
        
        result += str[i];
        i++;
    }
    
    return result;
}

const std::vector<std::string> kRedDetections = {
    // Strings of Disallowed Mods go here // Example: "MouseTweaks"
};

const std::vector<std::string> kYellowDetections = {
    // Strings of Generic Cheats go here // Example: "Auto Crystal"
};

const std::vector<std::string> kFullwidthObfuscatedCheats = {
    // Strings of Most common Generic Cheats go here // Example: "Autototem" ( This is in different fonts so it will detect stuff like dqrkis )
};

const std::vector<std::string> kJVMInjectionDetections = {
    // Strings of JVMInjections go here // Example: "-XX:+EnableDynamicAgentLoading"
};

const std::vector<std::string> kDNSCacheDetections = {
    // Strings of DNS Cache go here // Example: "vape.gg"
};

const std::vector<std::string> kWindowsServiceChecks = {
    "SysMain", "PcaSvc", "DPS", "EventLog", "Schedule", "Bam",
    "Dusmsvc", "Appinfo", "CDPSvc", "DcomLaunch", "PlugPlay", "wsearch"
};

const std::vector<std::string> kSystemTamperingDetections = {
    "ScriptBlockLogging", "EnableScriptBlockLogging", "ModuleLogging",
    "EnableModuleLogging", "EnableTranscripting", "Transcription",
    "wevtutil", "Clear-EventLog",
    "AppCompatCache", "ShimCache",
    "ExclusionPath",
    "JumpList", "AutomaticDestinations",
    "Start Menu\\Programs\\Startup"
};

const std::vector<std::string> kNormalScanStrings = [] {
    std::vector<std::string> all = kRedDetections;
    all.insert(all.end(), kYellowDetections.begin(), kYellowDetections.end());
    return all;
}();

const std::vector<std::string> kDeepScanStrings = [] {
    std::vector<std::string> all = kRedDetections;
    all.insert(all.end(), kYellowDetections.begin(), kYellowDetections.end());
    return all;
}();

struct ClientSignatureGroup {
    const char* label;
    std::vector<std::string> signatures;
};

const std::vector<ClientSignatureGroup> kClientSignatureGroups = {
    // like this { "Argon Client", { "dev/lvstrng/argon/", "another-string-if-needed-for-better-detection" }},
    // same goes for ofuscators
};

const std::unordered_set<std::string> kYellowLookup = [] {
    std::unordered_set<std::string> out;
    for (const auto& s : kYellowDetections) {
        out.insert(s);
    }
    return out;
}();

bool IsReadableProtection(DWORD protect) {
    constexpr DWORD mask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (protect & PAGE_GUARD) {
        return false;
    }
    return (protect & mask) != 0;
}

bool IsObfuscationSignature(const std::string& low) {
    return low.find("obfuscator") != std::string::npos ||
        low.find("mixin") != std::string::npos ||
        low.find("json") != std::string::npos;
}

struct CompiledSignature {
    std::string original;
    std::string lowered;
    Severity severity;
    char first{0};
};


const std::vector<std::string>& NormalScanStrings() { return kNormalScanStrings; }
const std::vector<std::string>& DeepScanStrings() { return kDeepScanStrings; }

MemoryScanner::MemoryScanner() = default;

MemoryScanner::~MemoryScanner() {
    Cancel();
    if (m_worker.joinable()) {
        m_worker.join();
    }
}

void MemoryScanner::Start(uint32_t pid, const ScanOptions& options, std::string processStartTime) {
    Cancel();
    if (m_worker.joinable()) {
        m_worker.join();
    }

    m_cancel.store(false);
    m_running.store(true);
    m_progress.store(0.0f);
    m_lastError.clear();
    m_summary = {};
    m_summary.pid = pid;
    m_summary.processStartTime = std::move(processStartTime);
    m_summary.scanType = "Full";
    m_summary.generatedBy = options.generatedBy;

    m_worker = std::thread(&MemoryScanner::Worker, this, pid, options, m_summary.processStartTime);
}

void MemoryScanner::Cancel() {
    m_cancel.store(true);
}

bool MemoryScanner::IsRunning() const {
    return m_running.load();
}

float MemoryScanner::Progress() const {
    return m_progress.load();
}

const ScanSummary& MemoryScanner::Summary() const {
    return m_summary;
}

std::string MemoryScanner::LastError() const {
    return m_lastError;
}

void MemoryScanner::RegisterDetection(ScanSummary& summary, std::string key, Severity severity, uintptr_t address, uintptr_t baseAddress) {
    for (auto& d : summary.detections) {
        if (d.message == key) {
            d.hits += 1;
            d.hitAddresses.push_back(address);
            if (d.baseAddress == 0) {
                d.baseAddress = baseAddress;
            }
            return;
        }
    }

    Detection d{};
    d.timestamp = NowTimestamp();
    d.message = std::move(key);
    d.severity = severity;
    d.address = address;
    d.baseAddress = baseAddress;
    d.hitAddresses.push_back(address);
    d.hits = 1;
    summary.detections.push_back(std::move(d));
}

static std::string ReadRemoteUnicodeString(HANDLE process, PVOID ustrAddr) {
    struct RemoteUStr {
        USHORT Length;
        USHORT MaximumLength;
        PVOID Buffer;
    };
    RemoteUStr us{};
    SIZE_T br = 0;
    if (!ReadProcessMemory(process, ustrAddr, &us, sizeof(us), &br) || !us.Buffer || us.Length == 0)
        return {};
    std::wstring w(static_cast<size_t>(us.Length / sizeof(wchar_t)), L'\0');
    if (!ReadProcessMemory(process, us.Buffer, w.data(), us.Length, &br))
        return {};
    std::string out;
    out.reserve(w.size());
    for (wchar_t c : w) out += (c > 0 && c < 128) ? static_cast<char>(c) : '?';
    return out;
}

static std::string ReadJvmCommandLine(HANDLE process) {
    using NtQIP_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto NtQIP = reinterpret_cast<NtQIP_t>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));
    if (!NtQIP) return {};

    struct PBI {
        PVOID ExitStatus;
        PVOID PebBaseAddress;
        PVOID AffinityMask;
        PVOID BasePriority;
        PVOID UniqueProcessId;
        PVOID InheritedFromUniqueProcessId;
    };
    PBI pbi{};
    ULONG retLen = 0;
    if (NtQIP(process, 0, &pbi, sizeof(pbi), &retLen) != 0 || !pbi.PebBaseAddress)
        return {};

    PVOID procParams = nullptr;
    SIZE_T br = 0;
    if (!ReadProcessMemory(process,
            reinterpret_cast<BYTE*>(pbi.PebBaseAddress) + 0x20,
            &procParams, sizeof(procParams), &br) || !procParams)
        return {};

    std::string result = ReadRemoteUnicodeString(process,
        reinterpret_cast<BYTE*>(procParams) + 0x70);

    PVOID envPtr = nullptr;
    if (ReadProcessMemory(process,
            reinterpret_cast<BYTE*>(procParams) + 0x80,
            &envPtr, sizeof(envPtr), &br) && envPtr) {

        SIZE_T envSize = 0;
        if (!ReadProcessMemory(process,
                reinterpret_cast<BYTE*>(procParams) + 0x3F0,
                &envSize, sizeof(envSize), &br) || envSize == 0 || envSize > 512 * 1024)
            envSize = 64 * 1024;

        std::vector<wchar_t> env(envSize / sizeof(wchar_t), L'\0');
        if (ReadProcessMemory(process, envPtr, env.data(), envSize, &br) && br > 0) {
            for (size_t i = 0; i < env.size(); ++i) {
                if (env[i] == L'\0') {
                } else {
                    result += (env[i] > 0 && env[i] < 128) ? static_cast<char>(env[i]) : '?';
                }
            }
        }
    }

    return result;
}

void MemoryScanner::Worker(uint32_t pid, ScanOptions options, std::string processStartTime) {
    (void)processStartTime;

    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!process) {
        m_lastError = "Access denied or process not found.";
        m_running.store(false);
        return;
    }

    CpuInfo cpu = DetectCpuInfo();
    ScanConfig config = OptimizeScanConfig(cpu);

    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    uintptr_t address = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    const uintptr_t endAddress = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    const auto& signatures = DeepScanStrings();

    std::vector<CompiledSignature> compiled;
    compiled.reserve(signatures.size() + kClientSignatureGroups.size() * 8 +
                     kJVMInjectionDetections.size() + kDNSCacheDetections.size() +
                     kSystemTamperingDetections.size());

    for (const auto& sig : signatures) {
        Severity sev = Severity::Detect;
        const std::string low = ToLower(sig);
        if (IsObfuscationSignature(low)) {
            sev = Severity::Suspicious;
        } else if (kYellowLookup.find(sig) != kYellowLookup.end()) {
            sev = Severity::Warning;
        } else if (low.find("mixin") != std::string::npos || low.find("json") != std::string::npos) {
            sev = Severity::Suspicious;
        } else if (low.find("injector") != std::string::npos) {
            sev = Severity::Warning;
        }
        if (low.empty()) {
            continue;
        }
        compiled.push_back({sig, low, sev, low[0]});
    }

    for (const auto& group : kClientSignatureGroups) {
        bool isObfuscationGroup = (std::string(group.label).find("Obfuscator") != std::string::npos);
        Severity groupSeverity = isObfuscationGroup ? Severity::Suspicious : Severity::Detect;
        for (const auto& sig : group.signatures) {
            const std::string low = ToLower(sig);
            if (!low.empty()) {
                compiled.push_back({group.label, low, groupSeverity, low[0]});
            }
        }
    }

    for (const auto& sig : kDNSCacheDetections) {
        const std::string low = ToLower(sig);
        if (!low.empty()) {
            compiled.push_back({sig + " (DNS Cache)", low, Severity::Detect, low[0]});
        }
    }

    for (const auto& sig : kSystemTamperingDetections) {
        const std::string low = ToLower(sig);
        if (!low.empty()) {
            compiled.push_back({sig + " (System Tampering)", low, Severity::Suspicious, low[0]});
        }
    }

    for (const auto& sig : kFullwidthObfuscatedCheats) {
        const std::string low = ToLower(sig);
        if (!low.empty()) {
            compiled.push_back({sig + " (Fullwidth Obfuscated)", low, Severity::Warning, low[0]});
        }
    }

    struct MemoryRegion {
        uintptr_t baseAddress;
        size_t size;
    };
    std::vector<MemoryRegion> regions;

    double totalBytes = 0.0;
    for (uintptr_t addr = address; addr < endAddress;) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(addr), &info, sizeof(info)) != sizeof(info)) {
            break;
        }
        if (info.State == MEM_COMMIT && IsReadableProtection(info.Protect) && info.Type == MEM_PRIVATE) {
            regions.push_back({reinterpret_cast<uintptr_t>(info.BaseAddress), info.RegionSize});
            totalBytes += static_cast<double>(info.RegionSize);
        }
        addr += info.RegionSize;
    }

    if (totalBytes <= 0.0 || regions.empty()) {
        m_summary = ScanSummary{pid, processStartTime, "full"};
        m_summary.generatedBy = options.generatedBy;
        m_progress.store(1.0f);
        m_running.store(false);
        CloseHandle(process);
        return;
    }

    std::vector<std::thread> threads;
    std::vector<ScanSummary> threadSummaries(config.threadCount, ScanSummary{pid, processStartTime, "full"});
    for (auto& summary : threadSummaries) {
        summary.generatedBy = options.generatedBy;
    }

    std::atomic<double> doneBytes{0.0};

    AhoCorasick ac;
    for (size_t i = 0; i < compiled.size(); i++)
        ac.AddPattern(compiled[i].lowered, static_cast<int>(i));
    ac.Build();

    std::atomic<size_t> nextRegion{0};

    auto scanRegion = [&](int threadId) {
        ScanSummary& localSummary = threadSummaries[threadId];

        std::vector<char> buffer(config.chunkSize);
        std::string lowerChunk;
        std::string normalizedChunk;
        lowerChunk.reserve(config.chunkSize);
        normalizedChunk.reserve(config.chunkSize);

        std::vector<bool> hitFlags(compiled.size(), false);

        size_t idx;
        while ((idx = nextRegion.fetch_add(1, std::memory_order_relaxed)) < regions.size()) {
            if (m_cancel.load()) break;

            const auto& region = regions[idx];
            uintptr_t regionAddr = region.baseAddress;
            size_t remaining = region.size;

            while (remaining > 0 && !m_cancel.load()) {
                size_t toRead = std::min(config.chunkSize, remaining);
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory(process,
                    reinterpret_cast<LPCVOID>(regionAddr),
                    buffer.data(), toRead, &bytesRead) && bytesRead > 0) {

                    lowerChunk.resize(bytesRead);
                    for (SIZE_T i = 0; i < bytesRead; ++i)
                        lowerChunk[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(buffer[i])));

                    normalizedChunk = NormalizeFullwidthUnicode(lowerChunk);

                    std::fill(hitFlags.begin(), hitFlags.end(), false);

                    ac.Search(lowerChunk.data(), lowerChunk.size(), [&](int i) {
                        if (!hitFlags[i]) {
                            hitFlags[i] = true;
                            RegisterDetection(localSummary,
                                compiled[i].original + " Found",
                                compiled[i].severity,
                                regionAddr, region.baseAddress);
                        }
                    });

                    if (lowerChunk != normalizedChunk) {
                        ac.Search(normalizedChunk.data(), normalizedChunk.size(), [&](int i) {
                            if (!hitFlags[i]) {
                                hitFlags[i] = true;
                                RegisterDetection(localSummary,
                                    compiled[i].original + " Found",
                                    compiled[i].severity,
                                    regionAddr, region.baseAddress);
                            }
                        });
                    }

                    if (lowerChunk.find(".client.mixins.json") != std::string::npos &&
                        (lowerChunk.find("fabric-events-interaction-v0") != std::string::npos ||
                         lowerChunk.find("mixin") != std::string::npos)) {
                        RegisterDetection(localSummary, "Client mixin JSON file Found", Severity::Suspicious,
                            regionAddr, region.baseAddress);
                    }
                }

                regionAddr += toRead;
                remaining -= toRead;

                doneBytes.fetch_add(static_cast<double>(toRead), std::memory_order_relaxed);
                const double p = doneBytes.load(std::memory_order_relaxed) / totalBytes;
                m_progress.store(static_cast<float>(std::clamp(p, 0.0, 1.0)));
            }
        }
    };

    for (int t = 0; t < config.threadCount; ++t)
        threads.emplace_back(scanRegion, t);

    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    ScanSummary finalSummary = threadSummaries[0];
    for (size_t i = 1; i < threadSummaries.size(); ++i) {
        finalSummary.detections.insert(
            finalSummary.detections.end(),
            threadSummaries[i].detections.begin(),
            threadSummaries[i].detections.end()
        );
    }

    for (const auto& d : finalSummary.detections) {
        if (d.severity == Severity::Detect) {
            finalSummary.detectCount += d.hits;
        } else if (d.severity == Severity::Warning) {
            finalSummary.warningCount += d.hits;
        } else {
            finalSummary.suspiciousCount += d.hits;
        }
    }

    {
        std::string cmdLine = ReadJvmCommandLine(process);
        if (!cmdLine.empty()) {
            std::string cmdLineLower = cmdLine;
            for (auto& c : cmdLineLower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

            for (const auto& sig : kJVMInjectionDetections) {
                std::string sigLower = ToLower(sig);
                if (cmdLineLower.find(sigLower) != std::string::npos) {
                    RegisterDetection(finalSummary, sig, Severity::Warning, 0, 0);
                }
            }
        }
    }

    std::vector<std::string> serviceIssues = CheckWindowsServices();
    for (const auto& issue : serviceIssues) {
        RegisterDetection(finalSummary, issue + " (System Integrity)", Severity::Suspicious, 0, 0);
    }

    m_summary = std::move(finalSummary);
    m_progress.store(1.0f);
    m_running.store(false);
    CloseHandle(process);
}

std::string MemoryScanner::NowTimestamp() {
    std::time_t t = std::time(nullptr);
    std::tm local{};
    localtime_s(&local, &t);
    std::ostringstream oss;
    oss << std::setfill('0')
        << std::setw(2) << local.tm_hour << ":"
        << std::setw(2) << local.tm_min << ":"
        << std::setw(2) << local.tm_sec;
    return oss.str();
}

std::string MemoryScanner::ToLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::vector<std::string> MemoryScanner::CheckWindowsServices() {
    std::vector<std::string> stoppedServices;

    SC_HANDLE scManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scManager) {
        return stoppedServices;
    }

    for (const auto& serviceName : kWindowsServiceChecks) {
        SC_HANDLE service = OpenServiceA(scManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
        if (service) {
            SERVICE_STATUS status;
            if (QueryServiceStatus(service, &status)) {
                if (status.dwCurrentState != SERVICE_RUNNING) {
                    stoppedServices.push_back(serviceName + " (Service Not Running)");
                }
            }
            CloseServiceHandle(service);
        } else {
            stoppedServices.push_back(serviceName + " (Service Not Found)");
        }
    }

    CloseServiceHandle(scManager);
    return stoppedServices;
}

} // namespace scanner