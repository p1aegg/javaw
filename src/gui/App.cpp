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

static constexpr int   kWinW  = 480;
static constexpr int   kWinH  = 280;
static constexpr float kWinWf = static_cast<float>(kWinW);
static constexpr float kWinHf = static_cast<float>(kWinH);

namespace {

void ApplyRoundedWindow(HWND hwnd, int w, int h, int radiusPx) {
    if (!hwnd || w <= 0 || h <= 0) return;
    const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    const int DWMWCP_ROUND = 2;
    (void)DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &DWMWCP_ROUND, sizeof(DWMWCP_ROUND));
    const int r = std::max(8, radiusPx);
    HRGN region = CreateRoundRectRgn(0, 0, w + 1, h + 1, r, r);
    SetWindowRgn(hwnd, region, TRUE);
}

} // namespace

JavaApp::JavaApp() = default;
JavaApp::~JavaApp() = default;

bool JavaApp::Initialize() {
    if (!glfwInit()) return false;

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_DECORATED, GLFW_FALSE);
    glfwWindowHint(GLFW_RESIZABLE, GLFW_FALSE);
    glfwWindowHint(GLFW_TRANSPARENT_FRAMEBUFFER, GLFW_TRUE);

    m_window = glfwCreateWindow(kWinW, kWinH, "P1AE javaw", nullptr, nullptr);
    if (!m_window) return false;

    if (GLFWmonitor* primary = glfwGetPrimaryMonitor()) {
        if (const GLFWvidmode* mode = glfwGetVideoMode(primary)) {
            int ww = 0, wh = 0;
            glfwGetWindowSize(m_window, &ww, &wh);
            glfwSetWindowPos(m_window, (mode->width - ww) / 2, (mode->height - wh) / 2);
        }
    }

    glfwMakeContextCurrent(m_window);
    glfwSwapInterval(1);
    glfwSetWindowAttrib(m_window, GLFW_FLOATING, GLFW_TRUE);
    if (HWND hwnd = glfwGetWin32Window(m_window)) {
        int ww = 0, wh = 0;
        glfwGetWindowSize(m_window, &ww, &wh);
        ApplyRoundedWindow(hwnd, ww, wh, 20);
    }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;

    ImGui_ImplGlfw_InitForOpenGL(m_window, true);
    ImGui_ImplOpenGL3_Init("#version 330");
    ApplyTheme();

    int w = 0, h = 0;
    glfwGetFramebufferSize(m_window, &w, &h);
    m_starfield.Initialize(w, h);

    RefreshProcesses();
    return true;
}

void JavaApp::Shutdown() {
    m_scanner.Cancel();
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    if (m_window) glfwDestroyWindow(m_window);
    glfwTerminate();
}

void JavaApp::RefreshProcesses() {
    m_processes = scanner::EnumerateJavawProcesses();
    if (m_selectedProcess >= static_cast<int>(m_processes.size()))
        m_selectedProcess = -1;
}

void JavaApp::StartScan() {
    if (m_selectedProcess < 0 || m_selectedProcess >= static_cast<int>(m_processes.size())) {
        m_lastError = "No javaw.exe process selected.";
        return;
    }
    m_lastError.clear();
    scanner::ScanOptions options{};
    options.deepScan = m_deepScan;
    const auto& sel = m_processes[static_cast<std::size_t>(m_selectedProcess)];
    m_scanner.Start(sel.pid, options, sel.startTime);
    m_view = ViewState::Scanning;
}

void JavaApp::HandleScanCompletion() {
    const auto& summary = m_scanner.Summary();
    const std::string path = report::GenerateHtmlReport(summary, "detection-results.html");
    report::OpenInDefaultBrowser(path);
    m_finishedTimer = 6.0f;
    m_view = ViewState::Finished;
}

bool JavaApp::Toggle(const char* label, bool* value) {
    ImGui::PushID(label);
    ImGui::TextUnformatted(label);
    const float xRight = ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x;
    ImGui::SameLine(xRight - 40.0f);

    const ImVec2 p = ImGui::GetCursorScreenPos();
    constexpr float tw = 32.0f;
    constexpr float th = 16.0f;

    ImGui::InvisibleButton("##t", ImVec2(tw, th));
    const bool clicked = ImGui::IsItemClicked();
    if (clicked) *value = !*value;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImU32 bg = *value ? IM_COL32(232, 72, 82, 255) : IM_COL32(80, 80, 100, 255);
    if (*value)
        dl->AddRectFilled(ImVec2(p.x - 1, p.y - 1), ImVec2(p.x + tw + 1, p.y + th + 1),
                          IM_COL32(232, 72, 82, 40), th * 0.5f);
    dl->AddRectFilled(p, ImVec2(p.x + tw, p.y + th), bg, th * 0.5f);
    const float cx = *value ? (p.x + tw - th * 0.5f) : (p.x + th * 0.5f);
    dl->AddCircleFilled(ImVec2(cx, p.y + th * 0.5f), th * 0.34f, IM_COL32(255, 255, 255, 255));
    ImGui::PopID();
    return clicked;
}

void JavaApp::DrawCenteredText(const char* text, float yOffset, float scale) {
    const ImVec2 ws = ImGui::GetWindowSize();
    const ImVec2 ts = ImGui::CalcTextSize(text);
    ImGui::SetCursorPos(ImVec2((ws.x - ts.x * scale) * 0.5f, yOffset));
    ImGui::SetWindowFontScale(scale);
    ImGui::TextUnformatted(text);
    ImGui::SetWindowFontScale(1.0f);
}

void JavaApp::DrawTitleBar() {
    const ImVec2 ws = ImGui::GetWindowSize();
    ImDrawList*  dl = ImGui::GetWindowDrawList();
    const ImVec2 wp = ImGui::GetWindowPos();

    ImGui::SetCursorPos(ImVec2(10.0f, 7.0f));
    ImGui::TextColored(ImVec4(0.45f, 0.44f, 0.54f, 1.0f), "v1.4");

    ImGui::SetWindowFontScale(1.06f);
    const char*  title = "P1AE javaw";
    const ImVec2 ts    = ImGui::CalcTextSize(title);
    ImGui::SetCursorPos(ImVec2((ws.x - ts.x) * 0.5f, 7.0f));
    ImGui::TextColored(ImVec4(0.92f, 0.92f, 0.99f, 1.0f), "%s", title);
    ImGui::SetWindowFontScale(1.0f);

    dl->AddLine(ImVec2(wp.x + 6.0f, wp.y + 26.0f),
                ImVec2(wp.x + ws.x - 6.0f, wp.y + 26.0f),
                IM_COL32(255, 92, 92, 35), 1.0f);

    const ImVec2 minPos(ws.x - 46.0f, 6.0f);
    const ImVec2 minMax(minPos.x + 16.0f, minPos.y + 14.0f);
    const bool   minHov = ImGui::IsMouseHoveringRect(minPos, minMax, false);
    dl->AddRectFilled(minPos, minMax,
        minHov ? IM_COL32(140, 42, 58, 255) : IM_COL32(100, 30, 42, 200), 3.0f);
    dl->AddText(ImVec2(minPos.x + 5.0f, minPos.y + 0.5f), IM_COL32(210, 210, 245, 220), "-");

    ImGui::SetCursorScreenPos(minPos);
    ImGui::InvisibleButton("##min", ImVec2(16.0f, 14.0f));
    if (ImGui::IsItemClicked()) glfwIconifyWindow(m_window);

    const ImVec2 closePos(ws.x - 24.0f, 6.0f);
    const ImVec2 closeMax(closePos.x + 16.0f, closePos.y + 14.0f);
    const bool   closeHov = ImGui::IsMouseHoveringRect(closePos, closeMax, false);
    dl->AddRectFilled(closePos, closeMax,
        closeHov ? IM_COL32(200, 50, 66, 255) : IM_COL32(130, 38, 52, 200), 3.0f);
    dl->AddText(ImVec2(closePos.x + 4.5f, closePos.y + 0.5f), IM_COL32(210, 210, 245, 220), "x");

    ImGui::SetCursorScreenPos(closePos);
    ImGui::InvisibleButton("##close", ImVec2(16.0f, 14.0f));
    if (ImGui::IsItemClicked()) glfwSetWindowShouldClose(m_window, GLFW_TRUE);

    static bool   s_drag = false;
    static double s_ox   = 0.0, s_oy = 0.0;
    double cx = 0.0, cy = 0.0;
    glfwGetCursorPos(m_window, &cx, &cy);

    if (!ImGui::IsAnyItemHovered() && cy <= 26.0 && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        s_drag = true; s_ox = cx; s_oy = cy;
    }
    if (s_drag && ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
        int wx = 0, wy = 0;
        glfwGetWindowPos(m_window, &wx, &wy);
        glfwSetWindowPos(m_window, wx + (int)(cx - s_ox), wy + (int)(cy - s_oy));
    }
    if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) s_drag = false;
}


void JavaApp::DrawMainWindow(float dt) {
    (void)dt;
    const float pulse = 0.72f + 0.28f * std::sin(static_cast<float>(glfwGetTime()) * 2.1f);

    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
    ImGui::Begin("Root", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove);

    DrawTitleBar();

    const ImVec2 screen  = ImGui::GetWindowSize();
    const ImVec2 cardSz(380.0f, 220.0f);
    const ImVec2 cardPos((screen.x - cardSz.x) * 0.5f, (screen.y - cardSz.y) * 0.5f + 8.0f);

    ImGui::SetCursorPos(cardPos);
    ImGui::BeginChild("Card", cardSz, false,
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    {
        const ImVec2 cp = ImGui::GetWindowPos();
        ImDrawList*  dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(cp, ImVec2(cp.x + cardSz.x, cp.y + cardSz.y), IM_COL32(24, 8, 10, 120), 9.0f);
        dl->AddRect(cp, ImVec2(cp.x + cardSz.x, cp.y + cardSz.y), IM_COL32(255, 92, 92, 54), 9.0f, 0, 1.0f);
        dl->AddRect(cp, ImVec2(cp.x + cardSz.x, cp.y + cardSz.y),
                    IM_COL32(255, 92, 92, static_cast<int>(28 * pulse)), 9.0f, 0, 2.2f);
    }

    const float padX    = 10.0f;
    const float contentW = cardSz.x - padX * 2.0f;

    {
        ImGui::SetWindowFontScale(1.10f);
        char headerText[128]{};
        sprintf_s(headerText, "Javaw Processes (%zu)", m_processes.size());
        const ImVec2 ts = ImGui::CalcTextSize(headerText);
        ImGui::SetCursorPos(ImVec2((cardSz.x - ts.x * 1.10f) * 0.5f, 8.0f));
        ImGui::TextColored(ImVec4(0.92f, 0.92f, 0.99f, 1.0f), "%s", headerText);
        ImGui::SetWindowFontScale(1.0f);
    }

    ImGui::SetCursorPos(ImVec2(padX, 26.0f));
    const ImGuiTableFlags tflags =
        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchSame;

    if (ImGui::BeginTable("proc_table", 3, tflags, ImVec2(contentW, 0.0f))) {
        ImGui::TableSetupColumn("PID",        ImGuiTableColumnFlags_WidthStretch, 0.26f);
        ImGui::TableSetupColumn("Memory",     ImGuiTableColumnFlags_WidthStretch, 0.30f);
        ImGui::TableSetupColumn("Start Time", ImGuiTableColumnFlags_WidthStretch, 0.44f);
        ImGui::TableHeadersRow();

        for (std::size_t i = 0; i < m_processes.size(); ++i) {
            const auto& proc = m_processes[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            char lbl[64]{};
            sprintf_s(lbl, "%u##r%zu", proc.pid, i);
            if (ImGui::Selectable(lbl, m_selectedProcess == static_cast<int>(i),
                                  ImGuiSelectableFlags_SpanAllColumns))
                m_selectedProcess = static_cast<int>(i);
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%.2f GB",
                static_cast<double>(proc.memoryBytes) / (1024.0 * 1024.0 * 1024.0));
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(proc.startTime.c_str());
        }
        ImGui::EndTable();
    }

    const float refreshBtnW = 80.0f;
    ImGui::SetCursorPosX(cardSz.x - padX - refreshBtnW);
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.70f, 0.25f, 0.30f, 0.75f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.80f, 0.32f, 0.38f, 0.85f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.70f, 0.25f, 0.30f, 0.95f));
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 3.0f));
    if (ImGui::Button("Refresh##ref", ImVec2(refreshBtnW, 0)))
        RefreshProcesses();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor(3);

    {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        const ImVec2 wp = ImGui::GetWindowPos();
        const float  dy = ImGui::GetCursorPosY() + 3.0f;
        dl->AddLine(ImVec2(wp.x + padX, wp.y + dy),
                    ImVec2(wp.x + cardSz.x - padX, wp.y + dy),
                    IM_COL32(255, 92, 92, 28), 1.0f);
    }
    ImGui::Dummy(ImVec2(0, 6.0f));

    if (!m_lastError.empty()) {
        ImGui::SetCursorPosX(padX);
        ImGui::TextColored(ImVec4(1.0f, 0.38f, 0.38f, 1.0f), "%s", m_lastError.c_str());
    }

    {
        const float bottomY = cardSz.y - 28.0f;
        ImDrawList* dl      = ImGui::GetWindowDrawList();
        const ImVec2 wp     = ImGui::GetWindowPos();

        dl->AddLine(ImVec2(wp.x + padX, wp.y + bottomY - 3.0f),
                    ImVec2(wp.x + cardSz.x - padX, wp.y + bottomY - 3.0f),
                    IM_COL32(255, 92, 92, 28), 1.0f);

        ImGui::SetCursorPos(ImVec2(padX, bottomY - 24.0f));
        Toggle("Deep Scan (BETA)", &m_deepScan);

        const bool processSelected = (m_selectedProcess >= 0);

        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 7.0f);
        ImGui::SetCursorPos(ImVec2(padX, bottomY));
        const ImVec2 btnSz(contentW, 22.0f);

        if (!processSelected) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.24f, 0.16f, 0.18f, 0.55f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.24f, 0.16f, 0.18f, 0.55f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.24f, 0.16f, 0.18f, 0.55f));
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.5f, 0.5f, 0.5f, 1.0f));
        } else {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.70f, 0.25f, 0.30f, 0.75f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.80f, 0.32f, 0.38f, 0.85f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.70f, 0.25f, 0.30f, 0.95f));
        }

        if (ImGui::Button("START SCAN", btnSz)) StartScan();

        if (!processSelected) {
            ImGui::PopStyleColor(4);
        } else {
            ImGui::PopStyleColor(3);
        }
        ImGui::PopStyleVar();
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

    const float progress = std::clamp(m_scanner.Progress(), 0.0f, 1.0f);
    const ImVec2 ws      = ImGui::GetWindowSize();
    ImDrawList*  dl      = ImGui::GetWindowDrawList();

    const ImVec2 cardSz(ws.x - 80.0f, 84.0f);
    const ImVec2 cTL((ws.x - cardSz.x) * 0.5f, (ws.y - cardSz.y) * 0.5f);
    const ImVec2 cBR(cTL.x + cardSz.x, cTL.y + cardSz.y);

    const float pulse = 0.72f + 0.28f * std::sin(static_cast<float>(glfwGetTime()) * 2.1f);
    dl->AddRectFilled(cTL, cBR, IM_COL32(24, 8, 10, 185), 9.0f);
    dl->AddRect(cTL, cBR, IM_COL32(255, 92, 92, 54), 9.0f, 0, 1.0f);
    dl->AddRect(cTL, cBR, IM_COL32(255, 92, 92, static_cast<int>(28 * pulse)), 9.0f, 0, 2.2f);

    dl->AddLine(ImVec2(cTL.x + 12.0f, cTL.y + 30.0f),
                ImVec2(cBR.x - 12.0f, cTL.y + 30.0f),
                IM_COL32(255, 92, 92, 32), 1.0f);

    const float  barPad = 16.0f;
    const ImVec2 bTL(cTL.x + barPad, cTL.y + 40.0f);
    const ImVec2 bBR(cBR.x - barPad, bTL.y + 7.0f);

    dl->AddRectFilled(bTL, bBR, IM_COL32(80, 48, 58, 170), 3.0f);
    dl->AddRect(bTL, bBR, IM_COL32(255, 92, 92, 80), 3.0f, 0, 1.0f);
    const float fw = (bBR.x - bTL.x) * progress;
    if (fw > 0.0f) {
        dl->AddRectFilled(bTL, ImVec2(bTL.x + fw, bBR.y), IM_COL32(255, 132, 132, 240), 3.0f);
        const float sc = bTL.x + std::fmod(static_cast<float>(glfwGetTime()) * 110.0f, std::max(1.0f, fw));
        const float sl = std::max(bTL.x, sc - 9.0f);
        const float sr = std::min(bTL.x + fw, sc + 7.0f);
        if (sr > sl)
            dl->AddRectFilled(ImVec2(sl, bTL.y), ImVec2(sr, bBR.y), IM_COL32(255, 255, 255, 52), 3.0f);
    }

    {
        char buf[64]{};
        sprintf_s(buf, "Scanning memory...  %d%%", static_cast<int>(progress * 100.0f));
        const ImVec2 ts = ImGui::CalcTextSize(buf);
        ImGui::SetCursorPos(ImVec2((ws.x - ts.x) * 0.5f, cTL.y + 54.0f));
        ImGui::TextColored(ImVec4(0.74f, 0.73f, 0.83f, 1.0f), "%s", buf);
    }

    {
        const char*  n  = "P1AE javaw";
        const ImVec2 ts = ImGui::CalcTextSize(n);
        ImGui::SetCursorPos(ImVec2((ws.x - ts.x) * 0.5f, cTL.y + 8.0f));
        ImGui::TextColored(ImVec4(0.88f, 0.88f, 0.96f, 0.92f), "%s", n);
    }

    ImGui::End();

    if (!m_scanner.IsRunning()) HandleScanCompletion();
}

void JavaApp::DrawFinishedWindow(float dt) {
    m_finishedTimer -= dt;

    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
    ImGui::Begin("Finished", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove);

    DrawTitleBar();

    const ImVec2 ws = ImGui::GetWindowSize();
    ImDrawList*  dl = ImGui::GetWindowDrawList();

    const ImVec2 cardSz(340.0f, 148.0f);
    const ImVec2 cTL((ws.x - cardSz.x) * 0.5f, (ws.y - cardSz.y) * 0.5f);
    const ImVec2 cBR(cTL.x + cardSz.x, cTL.y + cardSz.y);

    const float pulse = 0.72f + 0.28f * std::sin(static_cast<float>(glfwGetTime()) * 2.1f);
    dl->AddRectFilled(cTL, cBR, IM_COL32(24, 8, 10, 195), 9.0f);
    dl->AddRect(cTL, cBR, IM_COL32(255, 92, 92, 54), 9.0f, 0, 1.0f);
    dl->AddRect(cTL, cBR, IM_COL32(255, 92, 92, static_cast<int>(28 * pulse)), 9.0f, 0, 2.2f);

    {
        ImGui::SetWindowFontScale(1.12f);
        const char*  h  = "Scan finished";
        const ImVec2 ts = ImGui::CalcTextSize(h);
        ImGui::SetCursorPos(ImVec2((ws.x - ts.x * 1.12f) * 0.5f, cTL.y + 12.0f));
        ImGui::TextColored(ImVec4(0.92f, 0.92f, 0.99f, 1.0f), "%s", h);
        ImGui::SetWindowFontScale(1.0f);
    }

    dl->AddLine(ImVec2(cTL.x + 12.0f, cTL.y + 38.0f),
                ImVec2(cBR.x - 12.0f, cTL.y + 38.0f),
                IM_COL32(255, 92, 92, 32), 1.0f);

    {
        const char*  b  = "The scan completed successfully.";
        const ImVec2 ts = ImGui::CalcTextSize(b);
        ImGui::SetCursorPos(ImVec2((ws.x - ts.x) * 0.5f, cTL.y + 46.0f));
        ImGui::TextColored(ImVec4(0.74f, 0.73f, 0.83f, 1.0f), "%s", b);
    }

    {
        char buf[48]{};
        sprintf_s(buf, "Closing in %.0fs", std::max(0.0f, m_finishedTimer));
        const ImVec2 ts = ImGui::CalcTextSize(buf);
        ImGui::SetCursorPos(ImVec2((ws.x - ts.x) * 0.5f, cTL.y + 62.0f));
        ImGui::TextColored(ImVec4(0.50f, 0.50f, 0.60f, 1.0f), "%s", buf);
    }

    dl->AddLine(ImVec2(cTL.x + 12.0f, cTL.y + 80.0f),
                ImVec2(cBR.x - 12.0f, cTL.y + 80.0f),
                IM_COL32(255, 92, 92, 25), 1.0f);

    {
        const float  p    = std::clamp(1.0f - (m_finishedTimer / 6.0f), 0.0f, 1.0f);
        const float  bPad = 22.0f;
        const ImVec2 a(cTL.x + bPad, cTL.y + 88.0f);
        const ImVec2 b(cBR.x - bPad, a.y + 7.0f);

        dl->AddRectFilled(a, b, IM_COL32(60, 46, 52, 170), 3.0f);
        dl->AddRect(a, b, IM_COL32(255, 92, 92, 80), 3.0f, 0, 1.0f);
        const float fw = (b.x - a.x) * p;
        if (fw > 0.0f) {
            dl->AddRectFilled(a, ImVec2(a.x + fw, b.y), IM_COL32(255, 132, 132, 235), 3.0f);
            const float sc = a.x + std::fmod(static_cast<float>(glfwGetTime()) * 85.0f, std::max(1.0f, fw));
            const float sl = std::max(a.x, sc - 9.0f);
            const float sr = std::min(a.x + fw, sc + 6.0f);
            if (sr > sl)
                dl->AddRectFilled(ImVec2(sl, a.y), ImVec2(sr, b.y), IM_COL32(255, 255, 255, 55), 3.0f);
        }
    }

    {
        const char*  msg = "Results opened in your browser.";
        const ImVec2 ts  = ImGui::CalcTextSize(msg);
        ImGui::SetCursorPos(ImVec2((ws.x - ts.x) * 0.5f, cTL.y + 103.0f));
        ImGui::TextColored(ImVec4(0.44f, 0.44f, 0.54f, 1.0f), "%s", msg);
    }

    ImGui::End();

    if (m_finishedTimer <= 0.0f)
        glfwSetWindowShouldClose(m_window, GLFW_TRUE);
}

void JavaApp::Run() {
    float lastTime = static_cast<float>(glfwGetTime());

    while (!glfwWindowShouldClose(m_window)) {
        glfwPollEvents();

        const float now = static_cast<float>(glfwGetTime());
        const float dt  = now - lastTime;
        lastTime        = now;

        int w = 0, h = 0;
        glfwGetFramebufferSize(m_window, &w, &h);
        m_starfield.Resize(w, h);

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ImDrawList* bg = ImGui::GetBackgroundDrawList();
        m_starfield.Render(bg, ImVec2(0, 0),
            ImVec2(static_cast<float>(w), static_cast<float>(h)), now);

        if (m_view == ViewState::Main)          DrawMainWindow(dt);
        else if (m_view == ViewState::Scanning) DrawScanningWindow(dt);
        else                                    DrawFinishedWindow(dt);

        ImGui::Render();
        glViewport(0, 0, w, h);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(m_window);
    }
}

}