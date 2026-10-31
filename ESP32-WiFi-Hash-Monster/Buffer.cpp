#include "Buffer.h"
#include "SecurityAnalyzer.h"
#include <string.h>
#include <esp_system.h>

bool Buffer::fail() {
  ++writeErrors;
  enabled = false; useSD = false;
  // Preserve existing captures on any short write. Explicit user action retries SD.
  for (auto& t : targets) { if (t.file) t.file.close(); t.used = 0; }
  Serial.println("SD write/open failed; capture disabled (monitor remains active)");
  return false;
}

bool Buffer::flush(Target& t) {
  if (!t.used) return true;
  if (!t.file || t.file.write(t.data, t.used) != t.used) return fail();
  t.used = 0;
  return true;
}

bool Buffer::open(fs::FS* fs) {
  if (enabled) close(fs);
  if (!fs->exists("/pcap") && !fs->mkdir("/pcap")) return fail();
  if (!session) session = esp_random();
  if (++generation == 0) ++generation;
  enabled = true; useSD = true; lastFlush = millis();
  return true; // Files are created lazily when a validated frame arrives.
}

void Buffer::close(fs::FS*) {
  for (auto& t : targets) {
    if (enabled && !flush(t)) break;
    if (t.file) { t.file.flush(); t.file.close(); }
    t.used = 0;
  }
  enabled = false; useSD = false;
}

void Buffer::save(fs::FS*) {
  if (!enabled || uint32_t(millis() - lastFlush) < 1000) return;
  for (auto& t : targets) {
    if (!flush(t)) return;
    if (t.file) t.file.flush();
  }
  lastFlush = millis();
}

bool Buffer::addPacket(fs::FS* fs, const uint8_t* frame, uint32_t length, uint64_t timestamp,
                       const uint8_t bssid[6], const uint8_t* ssid, uint8_t ssidLength, Context& context) {
  if (!enabled || !frame || length < 24 || length > Pcap::snapLength) return false;
  const bool newFile = context.generation != generation;
  if (newFile) {
    char stem[48]; captureStem(stem, sizeof(stem), ssid, ssidLength, bssid);
    bool available = false;
    for (unsigned tries = 0; tries < 32; ++tries) {
      snprintf(context.path, sizeof(context.path), "/pcap/%s_%08lx_%08lx.pcap", stem, (unsigned long)session, (unsigned long)sequence++);
      if (!fs->exists(context.path)) { available = true; break; }
    }
    if (!available) return fail();
  }
  Target* target = nullptr;
  Target* oldest = &targets[0];
  const uint32_t now = millis();
  for (auto& t : targets) {
    if (t.file && !strcmp(t.path, context.path)) { target = &t; break; }
    if (!t.file || uint32_t(now - t.lastUse) > uint32_t(now - oldest->lastUse)) oldest = &t;
  }
  if (!target) {
    target = oldest;
    if (!flush(*target)) return false;
    if (target->file) target->file.close();
    // Contexts survive handle eviction: reopen the same session file without
    // splitting M1-M4 across files when unrelated APs arrive between messages.
    if (!newFile && !fs->exists(context.path)) return fail();
    target->file = fs->open(context.path, newFile ? FILE_WRITE : FILE_APPEND);
    if (!target->file) return fail();
    snprintf(target->path, sizeof(target->path), "%s", context.path);
    if (newFile) {
      Pcap::globalHeader(target->data); target->used = 24;
      context.generation = generation;
      Serial.printf("PCAP: %s\n", context.path);
    }
  }
  if (target->used + 16 + length > sizeof(target->data) && !flush(*target)) return false;
  Pcap::recordHeader(target->data + target->used, timestamp, length);
  target->used += 16;
  memcpy(target->data + target->used, frame, length); target->used += length;
  target->lastUse = now;
  ++accepted;
  return true;
}
