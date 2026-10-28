#ifndef DASHBOARD_LAYOUT_H
#define DASHBOARD_LAYOUT_H
#include <stdint.h>
#include <stdio.h>
namespace Dashboard {
struct Rect { int x, y, w, h; };
constexpr Rect header = {0, 0, 320, 24};
constexpr Rect fox = {8, 28, 128, 128};
constexpr Rect stats = {152, 28, 160, 128};
constexpr Rect signal = {8, 164, 304, 16};
constexpr Rect graph = {8, 184, 304, 30};
constexpr Rect footer = {0, 220, 320, 20};
constexpr uint16_t orange = 0xFD20;
constexpr uint16_t grid = 0x18C3;
inline int rssiY(int dbm) { if (dbm < -100) dbm = -100; if (dbm > -30) dbm = -30; return 1 + (-30 - dbm) * (graph.h - 3) / 70; }
inline void count(uint32_t value, char (&out)[6]) { if (value < 10000) snprintf(out, sizeof(out), "%lu", (unsigned long)value); else if (value < 1000000) snprintf(out, sizeof(out), "%luK", (unsigned long)(value / 1000)); else snprintf(out, sizeof(out), "%luM", (unsigned long)(value / 1000000)); }
}
#endif
