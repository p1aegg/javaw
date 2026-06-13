#include "gui/App.hpp"

#include "gui/Theme.hpp"
#include "report/ReportGenerator.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <dwmapi.h>
#include <shellapi.h>

#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3.h>
#include <GLFW/glfw3native.h>
#include <GL/gl.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>

#include <algorithm>
#include <cstring>
#include <iostream>

namespace gui {

namespace {

void ApplyRoundedWindow(HWND hwnd, int w, int h, int radiusPx) {
    if (!hwnd || w <= 0 || h <= 0) {
        return;
    }

    const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    const int DWMWCP_ROUND = 2;
    (void)DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &DWMWCP_ROUND, sizeof(DWMWCP_ROUND));

    const int r = std::max(8, radiusPx);
    HRGN region = CreateRoundRectRgn(0, 0, w + 1, h + 1, r, r);
    SetWindowRgn(hwnd, region, TRUE);
}

}

JavaApp::JavaApp() = default;
JavaApp::~JavaApp() = default;

bool JavaApp::Initialize() {
    if (!glfwInit()) {
        return false;
    }

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_DECORATED, GLFW_FALSE);
    glfwWindowHint(GLFW_RESIZABLE, GLFW_FALSE);
    glfwWindowHint(GLFW_TRANSPARENT_FRAMEBUFFER, GLFW_TRUE);

    m_window = glfwCreateWindow(670, 360, "P1AE javaw", nullptr, nullptr);
    if (!m_window) {
        return false;
    }

    if (GLFWmonitor* primary = glfwGetPrimaryMonitor()) {
        if (const GLFWvidmode* mode = glfwGetVideoMode(primary)) {
            int winW = 0, winH = 0;
            glfwGetWindowSize(m_window, &winW, &winH);
            glfwSetWindowPos(m_window, (mode->width - winW) / 2, (mode->height - winH) / 2);
        }
    }

    glfwMakeContextCurrent(m_window);
    glfwSwapInterval(1);
    glfwSetWindowAttrib(m_window, GLFW_FLOATING, GLFW_TRUE);
    if (HWND hwnd = glfwGetWin32Window(m_window)) {
        int ww = 0, wh = 0;
        glfwGetWindowSize(m_window, &ww, &wh);
        ApplyRoundedWindow(hwnd, ww, wh, 26);
    }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;

    ImGui_ImplGlfw_InitForOpenGL(m_window, true);
    ImGui_ImplOpenGL3_Init("#version 330");
    ApplyTheme();

    int w = 0;
    int h = 0;
    glfwGetFramebufferSize(m_window, &w, &h);
    m_starfield.Initialize(w, h);

    RefreshProcesses();
    return true;
}

void JavaApp::Shutdown() {
    m_scanner.Cancel();
    m_macroScanner.Cancel();
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    if (m_window) {
        glfwDestroyWindow(m_window);
    }
    glfwTerminate();
}

void JavaApp::RefreshProcesses() {
    m_processes = scanner::EnumerateJavawProcesses();
    if (m_selectedProcess >= static_cast<int>(m_processes.size())) {
        m_selectedProcess = -1;
    }
}

void JavaApp::StartScan() {
    if (m_scanType == ScanType::Memory) {
        if (m_selectedProcess < 0 || m_selectedProcess >= static_cast<int>(m_processes.size())) {
            m_lastError = "No javaw.exe process selected.";
            return;
        }
        m_lastError.clear();
        scanner::ScanOptions options{};
        options.deepScan = m_deepScan;
        const auto& selected = m_processes[static_cast<std::size_t>(m_selectedProcess)];
        m_scanner.Start(selected.pid, options, selected.startTime);
    } else if (m_scanType == ScanType::ExternalMacro) {
        m_lastError.clear();
        m_macroScanner.Start("C:\\");
    }
    m_view = ViewState::Scanning;
}

void JavaApp::HandleScanCompletion() {
    if (m_scanType == ScanType::Memory) {
        const auto& summary = m_scanner.Summary();
        const std::string reportPath = report::GenerateHtmlReport(summary, "detection-results.html");
        report::OpenInDefaultBrowser(reportPath);
    } else if (m_scanType == ScanType::ExternalMacro) {
        const auto& macroSummary = m_macroScanner.Summary();
        const std::string reportPath = report::GenerateMacroHtmlReport(macroSummary, "macro-scan-results.html");
        report::OpenInDefaultBrowser(reportPath);
    }

    m_finishedTimer = 6.0f;
    m_view = ViewState::Finished;
}

bool JavaApp::Toggle(const char* label, bool* value) {
    ImGui::PushID(label);
    ImGui::TextUnformatted(label);
    const float xRight = ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x;
    ImGui::SameLine(xRight - 44.0f);

    const ImVec2 p = ImGui::GetCursorScreenPos();
    const float w = 36.0f;
    const float h = 18.0f;

    ImGui::InvisibleButton("##toggle", ImVec2(w, h));
    const bool clicked = ImGui::IsItemClicked();
    if (clicked) {
        *value = !*value;
    }

    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImU32 bg = *value ? IM_COL32(232, 72, 82, 255) : IM_COL32(90, 90, 110, 255);
    if (*value) {
        dl->AddRectFilled(ImVec2(p.x - 1.0f, p.y - 1.0f), ImVec2(p.x + w + 1.0f, p.y + h + 1.0f), IM_COL32(232, 72, 82, 45), h * 0.5f);
    }
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), bg, h * 0.5f);
    const float cx = *value ? (p.x + w - h * 0.5f) : (p.x + h * 0.5f);
    dl->AddCircleFilled(ImVec2(cx, p.y + h * 0.5f), h * 0.34f, IM_COL32(255, 255, 255, 255));
    ImGui::PopID();
    return clicked;
}

void JavaApp::DrawTitleBar() {
    ImGui::SetCursorPos(ImVec2(14, 8));
    ImGui::TextColored(ImVec4(0.76f, 0.75f, 0.85f, 1.0f), "v1.3");

    const ImVec2 ws = ImGui::GetWindowSize();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 minPos(ws.x - 52.0f, 8.0f);
    const ImVec2 closePos(ws.x - 28.0f, 8.0f);
    dl->AddRectFilled(minPos, ImVec2(minPos.x + 18.0f, minPos.y + 16.0f), IM_COL32(112, 34, 46, 220), 4.0f);
    dl->AddRectFilled(closePos, ImVec2(closePos.x + 18.0f, closePos.y + 16.0f), IM_COL32(138, 42, 56, 220), 4.0f);
    dl->AddText(ImVec2(minPos.x + 6.0f, minPos.y + 1.0f), IM_COL32(220, 220, 255, 255), "-");
    dl->AddText(ImVec2(closePos.x + 5.5f, closePos.y + 1.0f), IM_COL32(220, 220, 255, 255), "x");

    ImGui::SetCursorScreenPos(minPos);
    ImGui::InvisibleButton("##min_btn", ImVec2(18.0f, 16.0f));
    if (ImGui::IsItemClicked()) {
        glfwIconifyWindow(m_window);
    }
    ImGui::SetCursorScreenPos(closePos);
    ImGui::InvisibleButton("##close_btn", ImVec2(18.0f, 16.0f));
    if (ImGui::IsItemClicked()) {
        glfwSetWindowShouldClose(m_window, GLFW_TRUE);
    }

    static bool dragging = false;
    static double dragOffsetX = 0.0;
    static double dragOffsetY = 0.0;
    double cursorX = 0.0;
    double cursorY = 0.0;
    glfwGetCursorPos(m_window, &cursorX, &cursorY);

    if (!ImGui::IsAnyItemHovered() && cursorY <= 28.0 && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        dragging = true;
        dragOffsetX = cursorX;
        dragOffsetY = cursorY;
    }
    if (dragging && ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
        int winX = 0;
        int winY = 0;
        glfwGetWindowPos(m_window, &winX, &winY);
        glfwSetWindowPos(m_window,
            winX + static_cast<int>(cursorX - dragOffsetX),
            winY + static_cast<int>(cursorY - dragOffsetY));
    }
    if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
        dragging = false;
    }
}

void JavaApp::DrawCenteredText(const char* text, float yOffset, float scale) {
    const ImVec2 ws = ImGui::GetWindowSize();
    const ImVec2 ts = ImGui::CalcTextSize(text);
    ImGui::SetCursorPos(ImVec2((ws.x - ts.x * scale) * 0.5f, yOffset));
    ImGui::SetWindowFontScale(scale);
    ImGui::TextUnformatted(text);
    ImGui::SetWindowFontScale(1.0f);
}

void JavaApp::DrawMainWindow(float dt) {
    (void)dt;
    const float pulse = 0.72f + 0.28f * std::sin(static_cast<float>(glfwGetTime()) * 2.1f);
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
    ImGui::Begin("Root", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove);

    DrawTitleBar();

    const ImVec2 full = ImGui::GetWindowSize();
    const ImVec2 cardSize(430.0f, 248.0f);
    const ImVec2 cardPos((full.x - cardSize.x) * 0.5f, 38.0f);
    ImGui::SetCursorPos(cardPos);
    ImGui::BeginChild("ScannerCard", cardSize, false, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    {
        const ImVec2 p = ImGui::GetWindowPos();
        ImDrawList* dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(p, ImVec2(p.x + cardSize.x, p.y + cardSize.y), IM_COL32(24, 8, 10, 180), 11.0f);
        dl->AddRect(p, ImVec2(p.x + cardSize.x, p.y + cardSize.y), IM_COL32(255, 92, 92, 56), 11.0f, 0, 1.0f);
        dl->AddRect(p, ImVec2(p.x + cardSize.x, p.y + cardSize.y), IM_COL32(255, 92, 92, static_cast<int>(32 * pulse)), 11.0f, 0, 2.5f);
    }

    DrawCenteredText("P1AE javaw", 6.0f, 1.24f);
    ImGui::Dummy(ImVec2(0, 14));
    const float padX = 10.0f;
    const float contentW = cardSize.x - padX * 2.0f;

    ImGui::SetCursorPosX(padX);
    ImGui::TextUnformatted("Scan Type:");
    ImGui::SameLine();
    const float scanTypeX = ImGui::GetCursorPosX();
    static int scanTypeSelection = 0;
    ImGui::RadioButton("Memory##scantype", &scanTypeSelection, 0);
    ImGui::SameLine(scanTypeX + 120.0f);
    ImGui::RadioButton("External Macro##scantype", &scanTypeSelection, 1);
    
    if (scanTypeSelection == 0) {
        m_scanType = ScanType::Memory;
    } else {
        m_scanType = ScanType::ExternalMacro;
    }
    ImGui::Dummy(ImVec2(0, 8));

    if (m_scanType == ScanType::Memory) {
        ImGui::SetCursorPosX(padX);
        if (ImGui::BeginTable("proc_table", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchSame, ImVec2(contentW, 0.0f))) {
            ImGui::TableSetupColumn("PID");
            ImGui::TableSetupColumn("Memory");
            ImGui::TableSetupColumn("Start Time");
            ImGui::TableHeadersRow();

            for (std::size_t i = 0; i < m_processes.size(); ++i) {
                const auto& p = m_processes[i];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                char label[64]{};
                sprintf_s(label, "%u##row%zu", p.pid, i);
                if (ImGui::Selectable(label, m_selectedProcess == static_cast<int>(i), ImGuiSelectableFlags_SpanAllColumns)) {
                    m_selectedProcess = static_cast<int>(i);
                }
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%.2f GB", static_cast<double>(p.memoryBytes) / (1024.0 * 1024.0 * 1024.0));
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(p.startTime.c_str());
            }
            ImGui::EndTable();
        }

        ImGui::SetCursorPosX(padX);
        if (ImGui::Button("Refresh Process List", ImVec2(contentW, 19.0f))) {
            RefreshProcesses();
        }
    } else if (m_scanType == ScanType::ExternalMacro) {
        ImGui::SetCursorPosX(padX);
        ImGui::TextUnformatted("Scanning entire system for external macro executables...");
    }

    if (m_scanType == ScanType::Memory) {
        ImGui::SetCursorPosX(padX);
        Toggle("Deep Memory Scan (BETA)", &m_deepScan);
    }
    ImGui::SetCursorPosX(padX);
    Toggle("Get results in private (Doesn't Work)", &m_privateResults);

    ImGui::Dummy(ImVec2(0, 2));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
    ImGui::SetCursorPosX(padX);
    const ImVec2 btnPos = ImGui::GetCursorScreenPos();
    const ImVec2 btnSize(contentW, 22.0f);
    if (ImGui::Button("START SCAN", btnSize)) {
        StartScan();
    }
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const bool hovered = ImGui::IsItemHovered();
    dl->AddRect(btnPos, ImVec2(btnPos.x + btnSize.x, btnPos.y + btnSize.y), IM_COL32(255, 92, 92, hovered ? 220 : 120), 8.0f, 0, hovered ? 2.4f : 1.2f);
    if (hovered) {
        dl->AddRect(btnPos, ImVec2(btnPos.x + btnSize.x, btnPos.y + btnSize.y), IM_COL32(255, 92, 92, 45), 8.0f, 0, 7.0f);
    }
    ImGui::PopStyleVar();

    if (!m_lastError.empty()) {
        ImGui::TextColored(ImVec4(1, 0.4f, 0.4f, 1), "%s", m_lastError.c_str());
    }


    ImGui::EndChild();

    ImGui::End();
}

void JavaApp::DrawScanningWindow(float dt) {
    (void)dt;
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
    ImGui::Begin("Scanning", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove);

    DrawTitleBar();
    DrawCenteredText("P1AE javaw", 130.0f, 1.30f);

    float progress = 0.0f;
    const char* scanText = "";
    bool isRunning = false;
    if (m_scanType == ScanType::Memory) {
        progress = std::clamp(m_scanner.Progress(), 0.0f, 1.0f);
        scanText = "Scanning memory...";
        isRunning = m_scanner.IsRunning();
    } else if (m_scanType == ScanType::ExternalMacro) {
        progress = std::clamp(m_macroScanner.Progress(), 0.0f, 1.0f);
        scanText = "Scanning for external macros...";
        isRunning = m_macroScanner.IsRunning();
    }
    const ImVec2 ws = ImGui::GetWindowSize();
    const float barW = ws.x * 0.70f;
    const float barH = 8.0f;
    const float barX = ws.x * 0.15f;
    const float barY = 176.0f;
    ImGui::SetCursorPos(ImVec2(barX, barY));
    ImGui::InvisibleButton("##scanbar", ImVec2(barW, barH));
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 p = ImGui::GetItemRectMin();
    const ImVec2 q = ImGui::GetItemRectMax();
    dl->AddRectFilled(p, q, IM_COL32(86, 52, 62, 170), 4.0f);
    dl->AddRect(p, q, IM_COL32(255, 92, 92, 90), 4.0f, 0, 1.0f);
    const float fillW = barW * progress;
    if (fillW > 0.0f) {
        dl->AddRectFilled(p, ImVec2(p.x + fillW, q.y), IM_COL32(255, 132, 132, 245), 4.0f);
        dl->AddRectFilled(ImVec2(p.x, p.y - 1.0f), ImVec2(p.x + fillW, q.y + 1.0f), IM_COL32(255, 132, 132, 55), 4.0f);
        const float shineCenter = p.x + std::fmod(static_cast<float>(glfwGetTime()) * 120.0f, std::max(1.0f, fillW));
        const float shineL = std::max(p.x, shineCenter - 10.0f);
        const float shineR = std::min(p.x + fillW, shineCenter + 8.0f);
        if (shineR > shineL) {
            dl->AddRectFilled(ImVec2(shineL, p.y - 1.0f), ImVec2(shineR, q.y + 1.0f), IM_COL32(255, 255, 255, 55), 3.0f);
        }
    }

    char progressText[96]{};
    sprintf_s(progressText, "%s - %d%%", scanText, static_cast<int>(progress * 100.0f));
    DrawCenteredText(progressText, 194.0f);


    ImGui::End();

    bool scanComplete = false;
    if (m_scanType == ScanType::Memory) {
        scanComplete = !m_scanner.IsRunning();
    } else if (m_scanType == ScanType::ExternalMacro) {
        scanComplete = !m_macroScanner.IsRunning();
    }
    
    if (scanComplete) {
        HandleScanCompletion();
    }
}

void JavaApp::DrawFinishedWindow(float dt) {
    m_finishedTimer -= dt;

    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
    ImGui::Begin("Finished", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove);

    const ImVec2 ws = ImGui::GetWindowSize();
    const ImVec2 modalSize(420, 220);
    ImGui::SetCursorPos(ImVec2((ws.x - modalSize.x) * 0.5f, (ws.y - modalSize.y) * 0.5f));
    ImGui::BeginChild("DoneCard", modalSize, true);

    DrawCenteredText("Scan finished", 58.0f, 1.2f);
    DrawCenteredText("The scan completed successfully.", 95.0f);

    char timer[64]{};
    sprintf_s(timer, "Self-closing in %.0fs...", std::max(0.0f, m_finishedTimer));
    DrawCenteredText(timer, 122.0f);

    ImGui::SetCursorPos(ImVec2(26, 180));
    const float p = std::clamp(1.0f - (m_finishedTimer / 6.0f), 0.0f, 1.0f);
    ImGui::InvisibleButton("##donebar", ImVec2(368, 8));
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 a = ImGui::GetItemRectMin();
    const ImVec2 b = ImGui::GetItemRectMax();
    dl->AddRectFilled(a, b, IM_COL32(60, 46, 52, 170), 4.0f);
    dl->AddRect(a, b, IM_COL32(255, 92, 92, 90), 4.0f, 0, 1.0f);
    const float fw = (b.x - a.x) * p;
    if (fw > 0.0f) {
        dl->AddRectFilled(a, ImVec2(a.x + fw, b.y), IM_COL32(255, 132, 132, 240), 4.0f);
        const float shineCenter = a.x + std::fmod(static_cast<float>(glfwGetTime()) * 90.0f, std::max(1.0f, fw));
        const float shineL = std::max(a.x, shineCenter - 10.0f);
        const float shineR = std::min(a.x + fw, shineCenter + 6.0f);
        if (shineR > shineL) {
            dl->AddRectFilled(ImVec2(shineL, a.y - 1.0f), ImVec2(shineR, b.y + 1.0f), IM_COL32(255, 255, 255, 60), 3.0f);
        }
    }

    ImGui::EndChild();
    ImGui::End();

    if (m_finishedTimer <= 0.0f) {
        glfwSetWindowShouldClose(m_window, GLFW_TRUE);
    }
}

void JavaApp::Run() {
    float lastTime = static_cast<float>(glfwGetTime());

    while (!glfwWindowShouldClose(m_window)) {
        glfwPollEvents();

        float now = static_cast<float>(glfwGetTime());
        float dt = now - lastTime;
        lastTime = now;

        int w = 0;
        int h = 0;
        glfwGetFramebufferSize(m_window, &w, &h);
        m_starfield.Resize(w, h);

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImDrawList* bg = ImGui::GetBackgroundDrawList();
        m_starfield.Render(bg, ImVec2(0, 0), ImVec2(static_cast<float>(w), static_cast<float>(h)), now);

        if (m_view == ViewState::Main) {
            DrawMainWindow(dt);
        } else if (m_view == ViewState::Scanning) {
            DrawScanningWindow(dt);
        } else {
            DrawFinishedWindow(dt);
        }

        ImGui::Render();
        glViewport(0, 0, w, h);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(m_window);
    }
}

}
