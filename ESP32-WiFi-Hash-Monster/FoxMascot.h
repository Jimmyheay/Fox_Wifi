#ifndef FOX_MASCOT_H
#define FOX_MASCOT_H
#include <stdint.h>
// Direct-drawn mascot: no image decoder, heap allocation or full-screen canvas.
template <typename Display>
void drawFoxMascot(Display& display, int x, int y, bool alert, bool sleepy, uint32_t now) {
  const uint16_t orange = 0xFD20, darkOrange = 0xE3A0, cream = 0xFFDF, brown = 0x4180, pink = 0xFBB7, black = 0x0000;
  display.fillRect(x, y, 128, 128, black);
  const bool tailUp = (now / 1000) & 1;
  display.fillCircle(x + 91, y + (tailUp ? 76 : 82), 31, darkOrange);
  display.fillCircle(x + 100, y + (tailUp ? 72 : 78), 21, orange);
  display.fillTriangle(x + 104, y + 47, x + 126, y + 76, x + 102, y + 93, cream);
  display.fillTriangle(x + 23, y + 33, x + 32, y + 1, x + 55, y + 29, brown);
  display.fillTriangle(x + 72, y + 28, x + 94, y + 2, x + 101, y + 39, brown);
  display.fillTriangle(x + 29, y + 27, x + 33, y + 10, x + 46, y + 29, pink);
  display.fillTriangle(x + 79, y + 27, x + 91, y + 10, x + 96, y + 34, pink);
  display.fillCircle(x + 61, y + 62, 43, orange);
  display.fillCircle(x + 43, y + 78, 24, cream); display.fillCircle(x + 76, y + 78, 25, cream);
  display.fillTriangle(x + 45, y + 78, x + 62, y + 104, x + 80, y + 78, cream);
  const bool blink = sleepy || ((now / 200) % 20 == 0);
  if (blink) { display.drawFastHLine(x + 40, y + 62, 12, brown); display.drawFastHLine(x + 72, y + 62, 12, brown); }
  else { display.fillCircle(x + 46, y + 62, 7, brown); display.fillCircle(x + 77, y + 62, 7, brown); display.fillCircle(x + 44, y + 60, 2, cream); display.fillCircle(x + 75, y + 60, 2, cream); }
  display.fillCircle(x + 61, y + 81, 6, black); display.drawLine(x + 61, y + 87, x + 54, y + 91, brown); display.drawLine(x + 61, y + 87, x + 68, y + 91, brown);
  if (alert) { display.drawCircle(x + 61, y + 81, 9, 0xF800); display.drawCircle(x + 61, y + 81, 10, 0xF800); }
}
#endif
