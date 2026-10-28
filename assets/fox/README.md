# WiFi Fox assets

`fox-sheet.png` is the editable 4×4 source sheet for the sixteen fox poses.
The firmware does not read images from the SD card: `tools/build_fox_assets.js`
converts this sheet into `FoxSprites.cpp`, a 32 KiB 4-bit indexed atlas in flash.

Run the generator after replacing or editing the sheet:

```sh
node tools/build_fox_assets.js
```

The M5Stack renderer scales each 64×64 pose to 128×128 in small strips. It
uses 2,176 bytes of stack scratch space instead of a 32 KiB full-size framebuffer.
