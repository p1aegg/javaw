#pragma once

#include <vector>

struct ImVec2;
struct ImDrawList;

namespace gui {

class Starfield {
public:
    void Initialize(int width, int height);
    void Resize(int width, int height);
    void Render(ImDrawList* drawList, ImVec2 origin, ImVec2 size, float timeSeconds);

private:
    struct Star {
        float x;
        float y;
        float radius;
        float twinkle;
        float speed;
    };

    std::vector<Star> m_stars;
    int m_width{1280};
    int m_height{720};
};

}
