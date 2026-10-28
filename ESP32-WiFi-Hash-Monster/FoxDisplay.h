#ifndef FOX_DISPLAY_H
#define FOX_DISPLAY_H

#include "FoxSprites.h"
#include "FoxAnimation.h"

constexpr int FOX_DISPLAY_SIZE = 128;
constexpr int FOX_STRIPE_ROWS = 8;

// Streams 2x-scaled rows directly to the TFT. Peak scratch memory: 2,176 bytes.
template <typename Display>
void renderLargeFox(Display& display, FoxFrame frame, int x, int y) {
  uint16_t source[FOX_SIZE];
  uint16_t stripe[FOX_DISPLAY_SIZE * FOX_STRIPE_ROWS];
  for (int sy = 0; sy < FOX_SIZE; sy += FOX_STRIPE_ROWS / 2) {
    for (int dy = 0; dy < FOX_STRIPE_ROWS / 2; ++dy) {
      const uint8_t sourceY = uint8_t(sy + dy + frame.lift);
      decodeFoxRow(frame.pose, sourceY, source);
      for (int sx = 0; sx < FOX_SIZE; ++sx) {
        const int at = dy * 2 * FOX_DISPLAY_SIZE + sx * 2;
        stripe[at] = stripe[at + 1] = source[sx];
        stripe[at + FOX_DISPLAY_SIZE] = stripe[at + FOX_DISPLAY_SIZE + 1] = source[sx];
      }
    }
    display.pushImage(x, y + sy * 2, FOX_DISPLAY_SIZE, FOX_STRIPE_ROWS, stripe);
  }
}
#endif
