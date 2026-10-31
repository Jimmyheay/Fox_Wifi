#ifndef CAPTURE_QUEUE_H
#define CAPTURE_QUEUE_H
#include <atomic>
#include <string.h>
#include "PcapFormat.h"

// Single producer (ESP-IDF Wi-Fi task), single consumer (UI/storage task).
// Radio buffers expire on callback return: copy once into internal static RAM.
class CaptureQueue {
 public:
  struct Packet {
    uint64_t timestamp;
    uint16_t length;
    int8_t rssi;
    uint8_t channel;
    uint8_t bytes[Pcap::snapLength];
  };
  bool push(const uint8_t* bytes, size_t length, uint64_t timestamp, int8_t rssi, uint8_t channel, bool priority) {
    if (!bytes || length > Pcap::snapLength) return false;
    const uint32_t head = produced.load(std::memory_order_relaxed);
    const uint32_t count = head - consumed.load(std::memory_order_acquire);
    if (count >= (priority ? capacity : capacity - 4)) return false;
    Packet& p = packets[head % slots];
    p.timestamp = timestamp; p.length = uint16_t(length); p.rssi = rssi; p.channel = channel;
    memcpy(p.bytes, bytes, length);
    produced.store(head + 1, std::memory_order_release);
    return true;
  }
  const Packet* front() const {
    const uint32_t tail = consumed.load(std::memory_order_relaxed);
    return tail == produced.load(std::memory_order_acquire) ? nullptr : &packets[tail % slots];
  }
  void pop() { consumed.store(consumed.load(std::memory_order_relaxed) + 1, std::memory_order_release); }
 private:
  // Power-of-two slots also preserve indexing across uint32_t counter wrap.
  // ESP32 has a smaller link-time DRAM budget than its total RAM/PSRAM.
  // Sixteen full-MPDU slots use ~40 KiB and leave room for the Wi-Fi driver.
  static constexpr uint32_t slots = 16, capacity = slots;
  Packet packets[slots];
  std::atomic<uint32_t> produced{0}, consumed{0};
};
static_assert(ATOMIC_INT_LOCK_FREE == 2, "Queue requires lock-free 32-bit atomics");
#endif
