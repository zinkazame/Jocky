// CS2 External Cheat - Aimbot + Wallhack + No-Recoil + GDI Overlay
// Windows x64, MSVC or MinGW
// External: reads CS2 memory via ReadProcessMemory
// Target: cs2.exe

#include <windows.h>
#include <tlhelp32.h>
#include <math.h>
#include <stdio.h>
#include <stdint.h>

// ─── OFFSETS (update per CS2 build) ────────────────────────────────────────
#define OFF_LOCAL_PLAYER        0x1734FF8
#define OFF_ENTITY_LIST         0x18C3FB8
#define OFF_MATRIX              0x192E540
#define OFF_HEALTH              0x334
#define OFF_TEAM                0x3CB
#define OFF_BONE_MATRIX         0x1F8
#define OFF_VEC_ORIGIN          0x127C
#define OFF_ANGLES              0x1570
#define OFF_AIM_PUNCH_ANGLE     0x1400
#define OFF_AIM_PUNCH_ANGLE_VEL 0x1410
#define OFF_GLOW_INDEX          0x4A0
#define BONE_HEAD               6
#define MAX_ENTITIES            64
#define RECOIL_SCALE            0.85f
#define SMOOTH                  4.f

// ─── HOTKEYS ───────────────────────────────────────────────────────────────
#define KEY_TOGGLE_AIMBOT    VK_F1
#define KEY_TOGGLE_WALLHACK  VK_F2
#define KEY_TOGGLE_NORECOIL  VK_F3
#define KEY_TOGGLE_OVERLAY   VK_F4
#define KEY_QUIT             VK_END

// ─── TYPES ─────────────────────────────────────────────────────────────────
typedef struct { float x, y, z; } Vec3;
typedef struct { float m[4][4]; } Matrix4x4;

typedef struct {
    float r, g, b, a;
    uint8_t render_when_occluded;
    uint8_t render_when_unoccluded;
    uint8_t pad[14];
} GlowObject;

// ─── FEATURE TOGGLES ───────────────────────────────────────────────────────
typedef struct {
    volatile BOOL aimbot;
    volatile BOOL wallhack;
    volatile BOOL norecoil;
    volatile BOOL overlay_visible;
} Features;

// ─── GLOBALS ───────────────────────────────────────────────────────────────
HANDLE    g_proc         = NULL;
DWORD     g_pid          = 0;
uintptr_t g_base         = 0;
uintptr_t g_glow_manager = 0;
HWND      g_overlay_hwnd = NULL;
Features  g_feat         = { TRUE, TRUE, TRUE, TRUE };
Vec3      g_prev_punch   = {0.f, 0.f, 0.f};
volatile BOOL g_running  = TRUE;

// Screen dimensions (fetched at init)
int g_sw = 1920, g_sh = 1080;

// ─── MEMORY HELPERS ────────────────────────────────────────────────────────
static inline int rpm(uintptr_t addr, void* buf, size_t sz) {
    SIZE_T rd = 0;
    return ReadProcessMemory(g_proc, (LPCVOID)addr, buf, sz, &rd) && rd == sz;
}
static inline uintptr_t rpm_ptr(uintptr_t addr) {
    uintptr_t v = 0; rpm(addr, &v, sizeof(v)); return v;
}
static inline int rpm_i(uintptr_t addr) {
    int v = 0; rpm(addr, &v, sizeof(v)); return v;
}
static inline void wpm(uintptr_t addr, void* buf, size_t sz) {
    WriteProcessMemory(g_proc, (LPVOID)addr, buf, sz, NULL);
}

// ─── PROCESS / MODULE ──────────────────────────────────────────────────────
DWORD get_pid(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { .dwSize = sizeof(pe) };
    DWORD pid = 0;
    if (Process32First(snap, &pe))
        do { if (!_stricmp(pe.szExeFile, name)) { pid = pe.th32ProcessID; break; } }
        while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return pid;
}

uintptr_t get_module_base(DWORD pid, const char* mod_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    MODULEENTRY32 me = { .dwSize = sizeof(me) };
    uintptr_t base = 0;
    if (Module32First(snap, &me))
        do { if (!_stricmp(me.szModule, mod_name)) { base = (uintptr_t)me.modBaseAddr; break; } }
        while (Module32Next(snap, &me));
    CloseHandle(snap);
    return base;
}

// ─── MATH ──────────────────────────────────────────────────────────────────
void calc_angle(Vec3 src, Vec3 dst, Vec3 cur_ang, float* yaw, float* pitch) {
    float dx = dst.x - src.x, dy = dst.y - src.y, dz = dst.z - src.z;
    float dist = sqrtf(dx*dx + dy*dy + dz*dz);
    float t_pitch = -asinf(dz / dist) * (180.f / 3.14159265f);
    float t_yaw   =  atan2f(dy, dx)   * (180.f / 3.14159265f);
    *pitch = t_pitch - cur_ang.x;
    *yaw   = t_yaw   - cur_ang.y;
    while (*pitch >  89.f) *pitch -= 180.f;
    while (*pitch < -89.f) *pitch += 180.f;
    while (*yaw   >  180.f) *yaw  -= 360.f;
    while (*yaw   < -180.f) *yaw  += 360.f;
}

// ─── ENTITY HELPERS ────────────────────────────────────────────────────────
uintptr_t get_entity(uintptr_t ent_list, int idx) {
    uintptr_t list1 = rpm_ptr(ent_list + ((idx >> 9) + 1) * 8);
    if (!list1) return 0;
    return rpm_ptr(list1 + 0x78 * (idx & 0x1FF));
}

Vec3 get_bone_pos(uintptr_t entity, int bone) {
    uintptr_t bone_arr = rpm_ptr(entity + OFF_BONE_MATRIX);
    Vec3 pos = {0};
    if (!bone_arr) return pos;
    rpm(bone_arr + bone * 32, &pos, sizeof(pos));
    return pos;
}

// ─── WALLHACK ──────────────────────────────────────────────────────────────
void wallhack_set(uintptr_t entity, int team_local) {
    int team = rpm_i(entity + OFF_TEAM);
    if (team == team_local) return;
    int glow_idx = rpm_i(entity + OFF_GLOW_INDEX);
    if (glow_idx < 0 || glow_idx > 4096) return;
    GlowObject go = {
        .r = 1.f, .g = 0.f, .b = 0.f, .a = 1.f,
        .render_when_occluded = 1, .render_when_unoccluded = 1
    };
    wpm(g_glow_manager + glow_idx * sizeof(GlowObject), &go, sizeof(go));
}

// ─── NO-RECOIL ─────────────────────────────────────────────────────────────
void norecoil_tick(uintptr_t local) {
    if (!(GetAsyncKeyState(VK_LBUTTON) & 0x8000)) {
        rpm(local + OFF_AIM_PUNCH_ANGLE, &g_prev_punch, sizeof(g_prev_punch));
        return;
    }
    Vec3 cur_punch = {0};
    if (!rpm(local + OFF_AIM_PUNCH_ANGLE, &cur_punch, sizeof(cur_punch))) return;
    float dp = cur_punch.x - g_prev_punch.x;
    float dy = cur_punch.y - g_prev_punch.y;
    if (fabsf(dp) > 0.001f || fabsf(dy) > 0.001f) {
        Vec3 angles = {0};
        if (!rpm(local + OFF_ANGLES, &angles, sizeof(angles))) return;
        angles.x -= dp * RECOIL_SCALE;
        angles.y -= dy * RECOIL_SCALE;
        if (angles.x >  89.f) angles.x =  89.f;
        if (angles.x < -89.f) angles.x = -89.f;
        while (angles.y >  180.f) angles.y -= 360.f;
        while (angles.y < -180.f) angles.y += 360.f;
        wpm(local + OFF_ANGLES, &angles, sizeof(angles));
    }
    g_prev_punch = cur_punch;
}

// ─── AIMBOT ────────────────────────────────────────────────────────────────
void aimbot_tick(uintptr_t local, uintptr_t ent_list, int team_local) {
    if (!(GetAsyncKeyState(VK_RBUTTON) & 0x8000)) return;
    Vec3 local_pos; rpm(local + OFF_VEC_ORIGIN, &local_pos, sizeof(local_pos));
    Vec3 cur_ang;   rpm(local + OFF_ANGLES,     &cur_ang,   sizeof(cur_ang));
    float best_fov = 1e9f, best_dp = 0.f, best_dy = 0.f;
    for (int i = 1; i < MAX_ENTITIES; i++) {
        uintptr_t ent = get_entity(ent_list, i);
        if (!ent || ent == local) continue;
        if (rpm_i(ent + OFF_HEALTH) <= 0) continue;
        if (rpm_i(ent + OFF_TEAM) == team_local) continue;
        Vec3 head = get_bone_pos(ent, BONE_HEAD);
        if (head.x == 0.f && head.y == 0.f) continue;
        float dp, dy;
        calc_angle(local_pos, head, cur_ang, &dp, &dy);
        float fov = sqrtf(dp*dp + dy*dy);
        if (fov < best_fov) { best_fov = fov; best_dp = dp; best_dy = dy; }
    }
    if (best_fov < 10.f) {
        Vec3 new_ang = { cur_ang.x + best_dp / SMOOTH,
                         cur_ang.y + best_dy / SMOOTH, cur_ang.z };
        wpm(local + OFF_ANGLES, &new_ang, sizeof(new_ang));
    }
}

// ─── OVERLAY DRAWING ───────────────────────────────────────────────────────
// Draws a small panel in the top-left corner showing feature states.
// Uses GDI with a layered window so it composites over CS2 fullscreen-windowed.

#define PANEL_X      20
#define PANEL_Y      20
#define PANEL_W      220
#define PANEL_H      120
#define ROW_H        24
#define FONT_SIZE    16

static HFONT   g_font     = NULL;
static COLORREF COL_ON    = RGB(0,   255, 80);   // green
static COLORREF COL_OFF   = RGB(255, 60,  60);   // red
static COLORREF COL_TITLE = RGB(180, 180, 255);  // lavender
static COLORREF COL_BG    = RGB(10,  10,  10);   // near-black

// Draw one feature row: "[KEY] Label    ON/OFF"
static void draw_row(HDC hdc, int row, const char* key,
                     const char* label, BOOL state) {
    int y = PANEL_Y + 30 + row * ROW_H;
    char buf[64];

    // Key hint (grey)
    SetTextColor(hdc, RGB(120, 120, 120));
    snprintf(buf, sizeof(buf), "[%s]", key);
    TextOutA(hdc, PANEL_X + 8, y, buf, (int)strlen(buf));

    // Label (white)
    SetTextColor(hdc, RGB(220, 220, 220));
    TextOutA(hdc, PANEL_X + 52, y, label, (int)strlen(label));

    // State
    SetTextColor(hdc, state ? COL_ON : COL_OFF);
    const char* st = state ? "ON" : "OFF";
    TextOutA(hdc, PANEL_X + 170, y, st, (int)strlen(st));
}

static void overlay_paint(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);

    // ── Background panel ──────────────────────────────────────────────────
    HBRUSH bg_brush = CreateSolidBrush(COL_BG);
    RECT panel = { PANEL_X, PANEL_Y, PANEL_X + PANEL_W, PANEL_Y + PANEL_H };
    FillRect(hdc, &panel, bg_brush);
    DeleteObject(bg_brush);

    // Thin border
    HPEN border_pen = CreatePen(PS_SOLID, 1, RGB(60, 60, 90));
    HPEN old_pen    = SelectObject(hdc, border_pen);
    HBRUSH null_br  = GetStockObject(NULL_BRUSH);
    HBRUSH old_br   = SelectObject(hdc, null_br);
    Rectangle(hdc, PANEL_X, PANEL_Y, PANEL_X + PANEL_W, PANEL_Y + PANEL_H);
    SelectObject(hdc, old_pen);
    SelectObject(hdc, old_br);
    DeleteObject(border_pen);

    // ── Font ──────────────────────────────────────────────────────────────
    if (!g_font)
        g_font = CreateFontA(FONT_SIZE, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Consolas");
    HFONT old_font = SelectObject(hdc, g_font);
    SetBkMode(hdc, TRANSPARENT);

    // ── Title ─────────────────────────────────────────────────────────────
    SetTextColor(hdc, COL_TITLE);
    const char* title = "CS2 Cheat  [F4: hide]";
    TextOutA(hdc, PANEL_X + 8, PANEL_Y + 6, title, (int)strlen(title));

    // Separator line
    HPEN sep = CreatePen(PS_SOLID, 1, RGB(50, 50, 70));
    HPEN osep = SelectObject(hdc, sep);
    MoveToEx(hdc, PANEL_X, PANEL_Y + 28, NULL);
    LineTo(hdc, PANEL_X + PANEL_W, PANEL_Y + 28);
    SelectObject(hdc, osep);
    DeleteObject(sep);

    // ── Feature rows ──────────────────────────────────────────────────────
    draw_row(hdc, 0, "F1", "Aimbot   ", g_feat.aimbot);
    draw_row(hdc, 1, "F2", "Wallhack ", g_feat.wallhack);
    draw_row(hdc, 2, "F3", "No-Recoil", g_feat.norecoil);

    SelectObject(hdc, old_font);
    EndPaint(hwnd, &ps);
}

// Force full overlay repaint (called from cheat thread on toggle)
static void overlay_refresh(void) {
    if (g_overlay_hwnd)
        InvalidateRect(g_overlay_hwnd, NULL, TRUE);
}

// ─── OVERLAY WINDOW PROC ───────────────────────────────────────────────────
LRESULT CALLBACK overlay_wnd_proc(HWND hwnd, UINT msg,
                                   WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_PAINT:
            if (g_feat.overlay_visible)
                overlay_paint(hwnd);
            else {
                // Paint transparent (clear to alpha=0)
                PAINTSTRUCT ps;
                HDC hdc = BeginPaint(hwnd, &ps);
                RECT rc; GetClientRect(hwnd, &rc);
                HBRUSH clr = CreateSolidBrush(RGB(0,0,0));
                FillRect(hdc, &rc, clr);
                DeleteObject(clr);
                EndPaint(hwnd, &ps);
            }
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcA(hwnd, msg, wp, lp);
    }
}

// ─── OVERLAY THREAD ────────────────────────────────────────────────────────
// Runs a dedicated message-pump thread so GDI doesn't block the cheat loop.

DWORD WINAPI overlay_thread(LPVOID param) {
    (void)param;

    // Get primary monitor resolution
    g_sw = GetSystemMetrics(SM_CXSCREEN);
    g_sh = GetSystemMetrics(SM_CYSCREEN);

    // Register window class
    WNDCLASSEXA wc = {
        .cbSize        = sizeof(wc),
        .style         = CS_HREDRAW | CS_VREDRAW,
        .lpfnWndProc   = overlay_wnd_proc,
        .hInstance     = GetModuleHandleA(NULL),
        .hCursor       = LoadCursorA(NULL, IDC_ARROW),
        .hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH),
        .lpszClassName = "CS2CheatOverlay"
    };
    RegisterClassExA(&wc);

    // Create layered, topmost, transparent window
    // WS_EX_LAYERED + WS_EX_TRANSPARENT = click-through
    // WS_EX_TOOLWINDOW = no taskbar entry
    g_overlay_hwnd = CreateWindowExA(
        WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW,
        "CS2CheatOverlay", "",
        WS_POPUP,
        0, 0, g_sw, g_sh,
        NULL, NULL, GetModuleHandleA(NULL), NULL
    );

    // Black = color key (fully transparent), rest composited
    // LWA_COLORKEY punches out black pixels so only our panel shows
    SetLayeredWindowAttributes(g_overlay_hwnd, RGB(0,0,0), 0, LWA_COLORKEY);
    ShowWindow(g_overlay_hwnd, SW_SHOW);
    UpdateWindow(g_overlay_hwnd);

    // Message pump
    MSG msg;
    while (g_running && GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    if (g_font) { DeleteObject(g_font); g_font = NULL; }
    DestroyWindow(g_overlay_hwnd);
    UnregisterClassA("CS2CheatOverlay", GetModuleHandleA(NULL));
    return 0;
}

// ─── HOTKEY HANDLER ────────────────────────────────────────────────────────
// Edge-triggered (fires once per press, not every tick while held)
typedef struct { int vk; BOOL prev; } KeyState;

static BOOL key_pressed(KeyState* k) {
    BOOL cur = (GetAsyncKeyState(k->vk) & 0x8000) != 0;
    BOOL fired = cur && !k->prev;
    k->prev = cur;
    return fired;
}

void handle_hotkeys(void) {
    static KeyState k_aim  = { KEY_TOGGLE_AIMBOT,   FALSE };
    static KeyState k_wh   = { KEY_TOGGLE_WALLHACK,  FALSE };
    static KeyState k_nr   = { KEY_TOGGLE_NORECOIL,  FALSE };
    static KeyState k_ov   = { KEY_TOGGLE_OVERLAY,   FALSE };

    if (key_pressed(&k_aim)) {
        g_feat.aimbot = !g_feat.aimbot;
        overlay_refresh();
        printf("[*] Aimbot    -> %s\n", g_feat.aimbot   ? "ON" : "OFF");
    }
    if (key_pressed(&k_wh)) {
        g_feat.wallhack = !g_feat.wallhack;
        overlay_refresh();
        printf("[*] Wallhack  -> %s\n", g_feat.wallhack ? "ON" : "OFF");
    }
    if (key_pressed(&k_nr)) {
        g_feat.norecoil = !g_feat.norecoil;
        overlay_refresh();
        printf("[*] No-Recoil -> %s\n", g_feat.norecoil ? "ON" : "OFF");
    }
    if (key_pressed(&k_ov)) {
        g_feat.overlay_visible = !g_feat.overlay_visible;
        overlay_refresh();
        printf("[*] Overlay   -> %s\n", g_feat.overlay_visible ? "SHOW" : "HIDE");
    }
}

// ─── MAIN LOOP ─────────────────────────────────────────────────────────────
int main(void) {
    printf("[*] CS2 External Cheat — waiting for cs2.exe...\n");

    while (!(g_pid = get_pid("cs2.exe"))) Sleep(1000);
    printf("[+] cs2.exe PID: %lu\n", g_pid);

    g_proc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE |
                         PROCESS_QUERY_INFORMATION, FALSE, g_pid);
    if (!g_proc) { printf("[-] OpenProcess failed: %lu\n", GetLastError()); return 1; }

    g_base = get_module_base(g_pid, "client.dll");
    if (!g_base) { printf("[-] client.dll not found\n"); return 1; }
    printf("[+] client.dll @ 0x%llX\n", (unsigned long long)g_base);

    g_glow_manager = rpm_ptr(g_base + 0x17A2340);

    // Spawn overlay on separate thread (has its own message pump)
    HANDLE ov_thread = CreateThread(NULL, 0, overlay_thread, NULL, 0, NULL);
    if (!ov_thread) printf("[-] Overlay thread failed, continuing headless\n");

    printf("[+] Running.\n");
    printf("[+]   F1  = toggle Aimbot\n");
    printf("[+]   F2  = toggle Wallhack\n");
    printf("[+]   F3  = toggle No-Recoil\n");
    printf("[+]   F4  = toggle Overlay\n");
    printf("[+]   END = quit\n");

    while (!(GetAsyncKeyState(KEY_QUIT) & 0x8000)) {
        handle_hotkeys();

        uintptr_t local = rpm_ptr(g_base + OFF_LOCAL_PLAYER);
        if (!local) { Sleep(100); continue; }

        uintptr_t ent_list = rpm_ptr(g_base + OFF_ENTITY_LIST);
        if (!ent_list) { Sleep(100); continue; }

        int team_local = rpm_i(local + OFF_TEAM);

        // ── Feature passes ────────────────────────────────────────────────
        if (g_feat.norecoil)
            norecoil_tick(local);

        if (g_feat.wallhack)
            for (int i = 1; i < MAX_ENTITIES; i++) {
                uintptr_t ent = get_entity(ent_list, i);
                if (!ent || ent == local) continue;
                if (rpm_i(ent + OFF_HEALTH) <= 0) continue;
                wallhack_set(ent, team_local);
            }

        if (g_feat.aimbot)
            aimbot_tick(local, ent_list, team_local);

        Sleep(1);
    }

    // Clean shutdown
    g_running = FALSE;
    if (g_overlay_hwnd) PostMessageA(g_overlay_hwnd, WM_QUIT, 0, 0);
    if (ov_thread) { WaitForSingleObject(ov_thread, 2000); CloseHandle(ov_thread); }
    CloseHandle(g_proc);
    printf("[*] Cheat unloaded.\n");
    return 0;
}