cmake_minimum_required(VERSION 3.22)
project(javaw VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(glfw3 CONFIG REQUIRED)
find_package(imgui CONFIG REQUIRED)
find_package(OpenGL REQUIRED)
find_package(CURL CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(javaw WIN32
    src/main.cpp
    src/gui/App.cpp
    src/gui/Theme.cpp
    src/gui/Starfield.cpp
    src/scanner/ProcessEnumerator.cpp
    src/scanner/MemoryScanner.cpp
    src/scanner/ExternalMacroScanner.cpp
    src/report/ReportGenerator.cpp
    src/version.rc
)

target_include_directories(javaw PRIVATE src)
set_target_properties(javaw PROPERTIES OUTPUT_NAME "P1AE Javaw")

target_link_libraries(javaw PRIVATE
    glfw
    imgui::imgui
    OpenGL::GL
    CURL::libcurl
    nlohmann_json::nlohmann_json
    psapi
    dwmapi
    shell32
    shlwapi
)

set_target_properties(javaw PROPERTIES OUTPUT_NAME "P1AE Javaw")

if(MSVC)
    target_link_options(javaw PRIVATE
        "/MANIFEST:EMBED"
        "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
    )
endif()
