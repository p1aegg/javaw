#pragma once

#include "scanner/MemoryScanner.hpp"
#include "scanner/ExternalMacroScanner.hpp"

#include <string>

namespace report {

std::string GenerateHtmlReport(const scanner::ScanSummary& summary, const std::string& outPath);
std::string GenerateMacroHtmlReport(const scanner::MacroScanSummary& summary, const std::string& outPath);
void OpenInDefaultBrowser(const std::string& path);

}
