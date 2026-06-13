#include "gui/App.hpp"
#include <Windows.h>
#include <shellapi.h>

static bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

static void RelaunchAsAdmin() {
    wchar_t exePath[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    ShellExecuteW(nullptr, L"runas", exePath, nullptr, nullptr, SW_SHOWNORMAL);
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    if (!IsRunningAsAdmin()) {
        RelaunchAsAdmin();
        return 0;
    }
    gui::JavaApp app;
    if (!app.Initialize()) {
        return 1;
    }
    app.Run();
    app.Shutdown();
    return 0;
}
