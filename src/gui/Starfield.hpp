#pragma once

#include <vector>

struct ImVec2;
struct ImDrawList;

namespace gui {

class Starfield {
public:
    struct Particle {
        float x, y;
        float vx, vy;
    };

    void Initialize(int width, int height);
    void Resize(int width, int height);
    void Render(ImDrawList* drawList, ImVec2 origin, ImVec2 size, float timeSeconds);

private:
    std::vector<Particle> m_particles;
    int   m_width{1280};
    int   m_height{720};
    float m_lastTime{0.0f};
    bool  m_initialized{false};
};

}