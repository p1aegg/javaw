#include "gui/Starfield.hpp"

#include <imgui.h>

#include <cmath>
#include <random>

namespace gui {

void Starfield::Initialize(int width, int height) {
    m_width = width;
    m_height = height;
    m_stars.clear();

    std::mt19937 rng(1337u);
    std::uniform_real_distribution<float> xDist(0.0f, static_cast<float>(width));
    std::uniform_real_distribution<float> yDist(0.0f, static_cast<float>(height));
    std::uniform_real_distribution<float> rDist(0.7f, 2.2f);
    std::uniform_real_distribution<float> tDist(0.5f, 2.5f);
    std::uniform_real_distribution<float> sDist(0.1f, 0.5f);

    m_stars.reserve(220);
    for (int i = 0; i < 220; ++i) {
        m_stars.push_back({xDist(rng), yDist(rng), rDist(rng), tDist(rng), sDist(rng)});
    }
}

void Starfield::Resize(int width, int height) {
    m_width = width;
    m_height = height;
}

void Starfield::Render(ImDrawList* drawList, ImVec2 origin, ImVec2 size, float timeSeconds) {
    const ImVec2 maxPos(origin.x + size.x, origin.y + size.y);
    drawList->AddRectFilledMultiColor(
        origin,
        maxPos,
        IM_COL32(20, 4, 6, 255),
        IM_COL32(14, 3, 5, 255),
        IM_COL32(10, 2, 4, 255),
        IM_COL32(18, 4, 6, 255));
    drawList->AddRectFilledMultiColor(
        origin,
        maxPos,
        IM_COL32(116, 20, 28, 36),
        IM_COL32(84, 14, 22, 24),
        IM_COL32(58, 10, 16, 28),
        IM_COL32(102, 18, 26, 38));

    for (int i = 0; i < 260; ++i) {
        const float x = origin.x + std::fmod((i * 97.0f) + timeSeconds * (0.4f + (i % 7) * 0.03f), size.x);
        const float y = origin.y + std::fmod((i * 53.0f) + timeSeconds * (0.2f + (i % 5) * 0.02f), size.y);
        const int a = 8 + (i % 9);
        drawList->AddCircleFilled(ImVec2(x, y), 0.8f + (i % 3) * 0.35f, IM_COL32(170, 58, 68, a + 8));
    }

    for (std::size_t i = 0; i < m_stars.size(); ++i) {
        const Star& star = m_stars[i];
        const float pulse = 0.55f + 0.45f * std::sin(timeSeconds * (0.9f + star.speed) + star.twinkle);
        const ImU32 color = IM_COL32(255, 178, 178, static_cast<int>(95 + 150 * pulse));

        const float x = origin.x + std::fmod(star.x + timeSeconds * star.speed * 7.0f, static_cast<float>(m_width));
        const float y = origin.y + std::fmod(star.y + std::sin(timeSeconds * 0.2f + star.twinkle) * 3.0f, static_cast<float>(m_height));

        drawList->AddCircleFilled(ImVec2(x, y), star.radius, color);

        if (i % 5 == 0 && i + 1 < m_stars.size()) {
            const Star& n = m_stars[i + 1];
            const float nx = origin.x + std::fmod(n.x + timeSeconds * n.speed * 7.0f, static_cast<float>(m_width));
            const float ny = origin.y + std::fmod(n.y, static_cast<float>(m_height));
            drawList->AddLine(ImVec2(x, y), ImVec2(nx, ny), IM_COL32(194, 64, 82, 30), 1.0f);
        }
    }

    constexpr int kSnowCount = 520;
    for (int i = 0; i < kSnowCount; ++i) {
        const float seedA = static_cast<float>((i * 37) % 1000) / 1000.0f;
        const float seedB = static_cast<float>((i * 83 + 19) % 1000) / 1000.0f;
        const float seedC = static_cast<float>((i * 29 + 7) % 1000) / 1000.0f;
        const float fallSpeed = 30.0f + seedA * 50.0f;
        const float driftAmp = 7.0f + seedB * 15.0f;
        const float xBase = seedC * size.x;
        const float y = origin.y + std::fmod(seedA * size.y + timeSeconds * fallSpeed, size.y + 16.0f) - 8.0f;
        const float x = origin.x + std::fmod(xBase + std::sin(timeSeconds * (0.9f + seedB) + seedC * 6.28f) * driftAmp + size.x, size.x);
        const float r = 1.8f + seedB * 3.0f;
        const int alpha = 150 + static_cast<int>(seedC * 100.0f);
        drawList->AddCircleFilled(ImVec2(x, y), r + 1.9f, IM_COL32(132, 26, 38, alpha / 2));
        drawList->AddCircleFilled(ImVec2(x, y), r, IM_COL32(255, 160, 165, alpha));
        if (i % 3 == 0) {
            drawList->AddLine(ImVec2(x, y - 5.0f), ImVec2(x, y + 5.0f), IM_COL32(255, 136, 142, alpha / 2), 1.4f);
        }
    }
}

}
