#include "FoxAnimation.h"

FoxFrame foxFrameFor(uint32_t now, uint32_t packets, uint32_t handshakes, uint32_t pmkids, uint32_t deauths) {
  const uint8_t beat = uint8_t((now / 750) % 4);
  if (deauths) return {uint8_t(beat & 1 ? 9 : 10), 0};
  if (handshakes) return {uint8_t(beat & 1 ? 5 : 8), uint8_t(beat == 2)};
  if (pmkids) return {14, 0};
  if (!packets) return {4, 0};
  if (packets > 500) return {uint8_t(beat & 1 ? 15 : 11), 0};
  return {uint8_t(beat == 0 ? 1 : (beat == 2 ? 2 : 0)), 0};
}
