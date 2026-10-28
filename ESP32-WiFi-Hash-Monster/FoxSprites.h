#ifndef FOX_SPRITES_H
#define FOX_SPRITES_H
#include <stdint.h>
#ifdef ARDUINO
#include <pgmspace.h>
#define FOX_FLASH PROGMEM
#else
#define FOX_FLASH
#endif
constexpr uint8_t FOX_SIZE=64, FOX_POSES=16;
extern const uint16_t foxPalette[16] FOX_FLASH;
extern const uint8_t foxPixels[32768] FOX_FLASH;
inline void decodeFoxRow(uint8_t pose,uint8_t y,uint16_t* row){ if(pose>=FOX_POSES||y>=FOX_SIZE){for(uint8_t x=0;x<FOX_SIZE;++x)row[x]=0;return;} const uint8_t* source=foxPixels+uint32_t(pose)*2048+uint16_t(y)*32; for(uint8_t x=0;x<FOX_SIZE;x+=2){uint8_t p=source[x/2];row[x]=foxPalette[p>>4];row[x+1]=foxPalette[p&15];}}
#endif
