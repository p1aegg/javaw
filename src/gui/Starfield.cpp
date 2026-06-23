#include "gui/Starfield.hpp"

#include <imgui.h>

#include <algorithm>
#include <cmath>
#include <cstdlib>

namespace gui {

static constexpr int   kNumParticles    = 35;
static constexpr float kConnectDist     = 100.0f;
static constexpr float kCursorDist      = 105.0f;
static constexpr float kParticleRadius  = 2.5f;
static constexpr float kSpeedMin        = 12.0f;
static constexpr float kSpeedMax        = 28.0f;

void Starfield::Initialize(int width, int height) {
    m_width  = width;
    m_height = height;
    m_initialized = false;
}

void Starfield::Resize(int width, int height) {
    m_width  = width;
    m_height = height;
}

static void SeedParticles(std::vector<Starfield::Particle>& particles,
                          float ox, float oy, float w, float h) {
    particles.resize(kNumParticles);

    const int cols = static_cast<int>(std::ceil(std::sqrt(static_cast<float>(kNumParticles) * (w / h))));
    const int rows = static_cast<int>(std::ceil(static_cast<float>(kNumParticles) / static_cast<float>(cols)));
    const float cellW = w / static_cast<float>(cols);
    const float cellH = h / static_cast<float>(rows);

    for (int i = 0; i < kNumParticles; ++i) {
        const int col = i % cols;
        const int row = i / cols;

        const float jx = (static_cast<float>(rand()) / static_cast<float>(RAND_MAX) - 0.5f) * cellW * 0.8f;
        const float jy = (static_cast<float>(rand()) / static_cast<float>(RAND_MAX) - 0.5f) * cellH * 0.8f;

        particles[i].x = ox + (col + 0.5f) * cellW + jx;
        particles[i].y = oy + (row + 0.5f) * cellH + jy;

        const float sign  = (rand() % 2 == 0) ? 1.0f : -1.0f;
        const float sign2 = (rand() % 2 == 0) ? 1.0f : -1.0f;
        const float mag1  = kSpeedMin + (kSpeedMax - kSpeedMin) * (static_cast<float>(rand()) / static_cast<float>(RAND_MAX));
        const float mag2  = kSpeedMin + (kSpeedMax - kSpeedMin) * (static_cast<float>(rand()) / static_cast<float>(RAND_MAX));
        particles[i].vx = sign  * mag1;
        particles[i].vy = sign2 * mag2;
    }
}

void Starfield::Render(ImDrawList* drawList, ImVec2 origin, ImVec2 size, float timeSeconds) {
    const float ox = origin.x;
    const float oy = origin.y;
    const float W  = size.x;
    const float H  = size.y;

    drawList->AddRectFilled(origin, ImVec2(ox + W, oy + H), IM_COL32(0, 0, 0, 255));

    if (!m_initialized) {
        SeedParticles(m_particles, ox, oy, W, H);
        m_lastTime    = timeSeconds;
        m_initialized = true;
    }

    const float dt = std::min(timeSeconds - m_lastTime, 0.05f);
    m_lastTime = timeSeconds;

    for (auto& p : m_particles) {
        p.x += p.vx * dt;
        p.y += p.vy * dt;
        if (p.x < ox)        p.x = ox + W;
        else if (p.x > ox + W) p.x = ox;

        if (p.y < oy)        p.y = oy + H;
        else if (p.y > oy + H) p.y = oy;
    }

    for (int i = 0; i < kNumParticles; ++i) {
        for (int j = i + 1; j < kNumParticles; ++j) {
            const float dx   = m_particles[j].x - m_particles[i].x;
            const float dy   = m_particles[j].y - m_particles[i].y;
            const float dist = std::sqrt(dx * dx + dy * dy);

            if (dist < kConnectDist) {
                const float opacity = 1.0f - (dist / kConnectDist);
                const int   alpha   = static_cast<int>(opacity * 255.0f);
                drawList->AddLine(
                    ImVec2(m_particles[i].x, m_particles[i].y),
                    ImVec2(m_particles[j].x, m_particles[j].y),
                    IM_COL32(255, 255, 255, alpha), 1.0f);
            }
        }
    }

    for (int i = 0; i < kNumParticles; ++i) {
        drawList->AddCircleFilled(
            ImVec2(m_particles[i].x, m_particles[i].y),
            kParticleRadius,
            IM_COL32(255, 255, 255, 255));
    }
}

} // namespace gui