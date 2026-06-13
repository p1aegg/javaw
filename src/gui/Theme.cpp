#include "gui/Theme.hpp"

#include <imgui.h>

namespace gui {

void ApplyTheme() {
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding = 10.0f;
    s.ChildRounding = 11.0f;
    s.FrameRounding = 7.0f;
    s.GrabRounding = 20.0f;
    s.PopupRounding = 8.0f;
    s.WindowPadding = ImVec2(8.0f, 8.0f);
    s.FramePadding = ImVec2(8.0f, 4.0f);
    s.ItemSpacing = ImVec2(7.0f, 7.0f);
    s.CellPadding = ImVec2(6.0f, 3.0f);
    s.ScrollbarSize = 8.0f;

    ImVec4* c = s.Colors;
    c[ImGuiCol_WindowBg] = ImVec4(0.08f, 0.02f, 0.03f, 0.97f);
    c[ImGuiCol_ChildBg] = ImVec4(0.11f, 0.03f, 0.04f, 0.78f);
    c[ImGuiCol_Border] = ImVec4(0.95f, 0.25f, 0.30f, 0.22f);
    c[ImGuiCol_Text] = ImVec4(0.92f, 0.92f, 0.99f, 1.0f);
    c[ImGuiCol_TextDisabled] = ImVec4(0.60f, 0.60f, 0.70f, 1.0f);
    c[ImGuiCol_Button] = ImVec4(0.72f, 0.18f, 0.22f, 0.92f);
    c[ImGuiCol_ButtonHovered] = ImVec4(0.90f, 0.25f, 0.30f, 1.0f);
    c[ImGuiCol_ButtonActive] = ImVec4(0.62f, 0.14f, 0.18f, 1.0f);
    c[ImGuiCol_FrameBg] = ImVec4(0.17f, 0.05f, 0.08f, 0.95f);
    c[ImGuiCol_FrameBgHovered] = ImVec4(0.25f, 0.08f, 0.12f, 0.95f);
    c[ImGuiCol_FrameBgActive] = ImVec4(0.30f, 0.10f, 0.14f, 1.0f);
    c[ImGuiCol_Header] = ImVec4(0.55f, 0.16f, 0.20f, 0.78f);
    c[ImGuiCol_HeaderHovered] = ImVec4(0.78f, 0.22f, 0.26f, 0.9f);
    c[ImGuiCol_HeaderActive] = ImVec4(0.88f, 0.26f, 0.30f, 1.0f);
    c[ImGuiCol_PlotHistogram] = ImVec4(0.98f, 0.42f, 0.42f, 1.0f);
    c[ImGuiCol_TableHeaderBg] = ImVec4(0.38f, 0.12f, 0.16f, 0.86f);
    c[ImGuiCol_TableBorderStrong] = ImVec4(0.78f, 0.22f, 0.26f, 0.35f);
    c[ImGuiCol_TableRowBg] = ImVec4(0.20f, 0.06f, 0.10f, 0.34f);
    c[ImGuiCol_TableRowBgAlt] = ImVec4(0.23f, 0.08f, 0.12f, 0.28f);
}

}
