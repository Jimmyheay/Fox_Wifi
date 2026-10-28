#!/usr/bin/env node
// Converts the editable sprite sheet into the compact 4-bit firmware atlas.
const {execFileSync} = require('child_process');
const {writeFileSync} = require('fs');

const source = 'assets/fox/fox-sheet.png';
const rgba = execFileSync('magick', [source, '-resize', '1024x1024!', '-colors', '16', '-dither', 'None', 'rgba:-'], {maxBuffer: 5 * 1024 * 1024});
const palette = [], pixels = [];
for (let frame = 0; frame < 16; frame++) {
  const cellX = (frame % 4) * 256, cellY = Math.floor(frame / 4) * 256;
  for (let y = 0; y < 64; y++) for (let x = 0; x < 64; x++) {
    const offset = ((cellY + y * 4) * 1024 + cellX + x * 4) * 4;
    const rgbaPixel = rgba.subarray(offset, offset + 4);
    const color = rgbaPixel[3] < 16 ? 0 : (((rgbaPixel[0] >> 3) << 11) | ((rgbaPixel[1] >> 2) << 5) | (rgbaPixel[2] >> 3));
    let index = palette.indexOf(color);
    if (index < 0 && palette.length < 16) { index = palette.length; palette.push(color); }
    if (index < 0) { index = palette.reduce((best, candidate, i) => {
      const dr = ((candidate >> 11) - (color >> 11)), dg = (((candidate >> 5) & 63) - ((color >> 5) & 63)), db = ((candidate & 31) - (color & 31));
      const br = ((palette[best] >> 11) - (color >> 11)), bg = (((palette[best] >> 5) & 63) - ((color >> 5) & 63)), bb = ((palette[best] & 31) - (color & 31));
      return dr*dr + dg*dg + db*db < br*br + bg*bg + bb*bb ? i : best;
    }, 0); }
    pixels.push(index);
  }
}
while (palette.length < 16) palette.push(0);
const packed = [];
for (let i = 0; i < pixels.length; i += 2) packed.push((pixels[i] << 4) | pixels[i + 1]);
const hex = (values, width) => values.map((v, i) => (i % 16 ? '' : '\n  ') + '0x' + v.toString(16).padStart(width, '0')).join(',');
writeFileSync('ESP32-WiFi-Hash-Monster/FoxSprites.h', `#ifndef FOX_SPRITES_H\n#define FOX_SPRITES_H\n#include <stdint.h>\n#ifdef ARDUINO\n#include <pgmspace.h>\n#define FOX_FLASH PROGMEM\n#else\n#define FOX_FLASH\n#endif\nconstexpr uint8_t FOX_SIZE=64, FOX_POSES=16;\nextern const uint16_t foxPalette[16] FOX_FLASH;\nextern const uint8_t foxPixels[32768] FOX_FLASH;\ninline void decodeFoxRow(uint8_t pose,uint8_t y,uint16_t* row){ if(pose>=FOX_POSES||y>=FOX_SIZE){for(uint8_t x=0;x<FOX_SIZE;++x)row[x]=0;return;} const uint8_t* source=foxPixels+uint32_t(pose)*2048+uint16_t(y)*32; for(uint8_t x=0;x<FOX_SIZE;x+=2){uint8_t p=source[x/2];row[x]=foxPalette[p>>4];row[x+1]=foxPalette[p&15];}}\n#endif\n`);
writeFileSync('ESP32-WiFi-Hash-Monster/FoxSprites.cpp', `#include "FoxSprites.h"\nconst uint16_t foxPalette[16] FOX_FLASH = {${hex(palette,4)}\n};\nconst uint8_t foxPixels[32768] FOX_FLASH = {${hex(packed,2)}\n};\n`);
