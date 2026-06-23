#pragma once

#include "scanner/MemoryScanner.hpp"

#include <string>

namespace report {

std::string GenerateHtmlReport(const scanner::ScanSummary& summary, const std::string& outPath);
void OpenInDefaultBrowser(const std::string& path);

}
