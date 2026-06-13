#include "scanner/ProcessEnumerator.hpp"

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include <iomanip>
#include <sstream>

namespace scanner {

namespace {

std::string FormatTime(const FILETIME& ft) {
    SYSTEMTIME stUtc{};
    SYSTEMTIME stLocal{};
    if (!FileTimeToSystemTime(&ft, &stUtc)) {
        return "--:--:--";
    }
    if (!SystemTimeToTzSpecificLocalTime(nullptr, &stUtc, &stLocal)) {
        return "--:--:--";
    }

    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(2) << stLocal.wDay << "/"
        << std::setw(2) << stLocal.wMonth << "/" << stLocal.wYear << " "
        << std::setw(2) << stLocal.wHour << ":" << std::setw(2) << stLocal.wMinute;
    return oss.str();
}

}

std::vector<ProcessInfo> EnumerateJavawProcesses() {
    std::vector<ProcessInfo> out;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return out;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snap, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, L"javaw.exe") != 0) {
                continue;
            }

            ProcessInfo info{};
            info.pid = entry.th32ProcessID;

            HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, info.pid);
            if (proc) {
                PROCESS_MEMORY_COUNTERS_EX pmc{};
                if (GetProcessMemoryInfo(proc, reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
                    info.memoryBytes = static_cast<std::size_t>(pmc.WorkingSetSize);
                }

                FILETIME createTime{}, exitTime{}, kernelTime{}, userTime{};
                if (GetProcessTimes(proc, &createTime, &exitTime, &kernelTime, &userTime)) {
                    info.startTime = FormatTime(createTime);
                }
                CloseHandle(proc);
            }

            if (info.startTime.empty()) {
                info.startTime = "Unknown";
            }
            out.push_back(info);
        } while (Process32NextW(snap, &entry));
    }

    CloseHandle(snap);
    return out;
}

}
