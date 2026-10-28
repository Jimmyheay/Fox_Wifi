#ifndef FOX_ANIMATION_H
#define FOX_ANIMATION_H
#include <stdint.h>
struct FoxFrame { uint8_t pose; uint8_t lift; };
FoxFrame foxFrameFor(uint32_t now, uint32_t packets, uint32_t handshakes, uint32_t pmkids, uint32_t deauths);
#endif
