#pragma once

#include "gui/Starfield.hpp"
#include "scanner/MemoryScanner.hpp"
#include "scanner/ProcessEnumerator.hpp"

#include <memory>
#include <string>
#include <vector>

struct GLFWwindow;

namespace gui {

class JavaApp {
public:
    JavaApp();
    ~JavaApp();
    bool Initialize();
    void Run();
    void Shutdown();

private:
    enum class ViewState {
        Main,
        Scanning,
        Finished
    };

    void DrawMainWindow(float dt);
    void DrawScanningWindow(float dt);
    void DrawFinishedWindow(float dt);
    void DrawTitleBar();
    void RefreshProcesses();
    void StartScan();
    void HandleScanCompletion();
    bool Toggle(const char* label, bool* value);
    void DrawCenteredText(const char* text, float yOffset, float scale = 1.0f);

    GLFWwindow* m_window{nullptr};
    Starfield m_starfield;
    scanner::MemoryScanner m_scanner;
    std::vector<scanner::ProcessInfo> m_processes;
    int m_selectedProcess{-1};
    bool m_deepScan{false};
    ViewState m_view{ViewState::Main};
    float m_finishedTimer{6.0f};
    std::string m_lastError;
};

}