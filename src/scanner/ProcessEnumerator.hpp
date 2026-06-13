#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace scanner {

struct ProcessInfo {
    uint32_t pid{0};
    std::size_t memoryBytes{0};
    std::string startTime;
};

std::vector<ProcessInfo> EnumerateJavawProcesses();

}
