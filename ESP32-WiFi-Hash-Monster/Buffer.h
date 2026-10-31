#ifndef Buffer_h
#define Buffer_h
#include <Arduino.h>
#include <FS.h>
#include "PcapFormat.h"
#define SNAP_LEN 2500
extern bool useSD;

// Single owner: the processing/UI task. Never called by the Wi-Fi callback.
// Three cached handles limit FAT churn; bounded batches avoid per-frame writes.
class Buffer {
 public:
  struct Context { uint32_t generation = 0; char path[96] = {}; };
  bool init() { return true; }
  bool open(fs::FS* fs);
  void close(fs::FS* fs);
  void save(fs::FS* fs);
  bool addPacket(fs::FS* fs, const uint8_t* frame, uint32_t length, uint64_t timestamp,
                 const uint8_t bssid[6], const uint8_t* ssid, uint8_t ssidLength, Context& context);
  uint32_t errors() const { return writeErrors; }
  uint32_t packets() const { return accepted; }
 private:
  struct Target {
    File file;
    char path[96] = {};
    uint8_t data[4096];
    size_t used = 0;
    uint32_t lastUse = 0;
  } targets[3];
  uint32_t generation = 0, session = 0, sequence = 0, writeErrors = 0, accepted = 0, lastFlush = 0;
  bool enabled = false;
  bool flush(Target& target);
  bool fail();
};
#endif
