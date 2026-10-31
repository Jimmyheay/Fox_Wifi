#include "Buffer.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
bool useSD = false;
uint32_t mockMillis = 0;
SerialMock Serial;
static uint32_t read32(const uint8_t* p) { return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24); }
int main() {
  fs::FS sd;
  uint8_t ap[6] = {2,0,0,0,0,1}, frame[2500]; memset(frame, 0xab, sizeof(frame));
  Buffer::Context context;
  Buffer b; assert(b.open(&sd));
  // Two batches and a tail: validate every record boundary and original payload.
  for (unsigned i = 0; i < 5; ++i) assert(b.addPacket(&sd, frame, sizeof(frame), 1000000ULL + i, ap, (const uint8_t*)"Test / WiFi", 11, context));
  b.close(&sd); assert(sd.state.files.size() == 1);
  const auto& bytes = sd.state.files.begin()->second;
  assert(sd.state.files.begin()->first.find("Test_WiFi_020000000001_") != std::string::npos);
  assert(read32(bytes.data()) == 0xa1b2c3d4 && read32(bytes.data() + 20) == 105);
  size_t at = 24;
  for (unsigned i = 0; i < 5; ++i) {
    assert(read32(bytes.data() + at) == 1 && read32(bytes.data() + at + 4) == i);
    assert(read32(bytes.data() + at + 8) == sizeof(frame) && read32(bytes.data() + at + 12) == sizeof(frame));
    assert(!memcmp(bytes.data() + at + 16, frame, sizeof(frame))); at += 16 + sizeof(frame);
  }
  assert(at == bytes.size());
  assert(b.open(&sd)); assert(b.addPacket(&sd, frame, 24, 1, ap, nullptr, 0, context)); b.close(&sd);
  assert(sd.state.files.size() == 2); // no overwrite across reopen
  // Exercise handle eviction: all five BSSIDs retain their separate records.
  Buffer::Context contexts[5];
  fs::FS multi; Buffer many; assert(many.open(&multi));
  for (unsigned i = 0; i < 5; ++i) { ap[5] = i; assert(many.addPacket(&multi, frame, 24, i, ap, nullptr, 0, contexts[i])); }
  // Revisit each evicted handle: append to the original file, no extra header.
  for (unsigned i = 0; i < 5; ++i) { ap[5] = i; assert(many.addPacket(&multi, frame, 24, i, ap, nullptr, 0, contexts[i])); }
  many.close(&multi); assert(multi.state.files.size() == 5);
  for (const auto& file : multi.state.files) assert(file.second.size() == 24 + 2 * (16 + 24));
  context = {};
  fs::FS fail; Buffer bad; assert(bad.open(&fail));
  assert(bad.addPacket(&fail, frame, 24, 1, ap, nullptr, 0, context));
  fail.state.maxWrite = 10; mockMillis = 1001; bad.save(&fail);
  assert(!useSD && bad.errors() == 1); assert(!bad.addPacket(&fail, frame, 24, 2, ap, nullptr, 0, context));
  fail.state.maxWrite = size_t(-1); assert(bad.open(&fail));
  assert(bad.addPacket(&fail, frame, 24, 3, ap, nullptr, 0, context)); bad.close(&fail);
  context = {};
  fs::FS openFail; openFail.state.failOpen = true; Buffer noFile; assert(noFile.open(&openFail));
  assert(!noFile.addPacket(&openFail, frame, 24, 1, ap, nullptr, 0, context)); assert(!useSD && noFile.errors() == 1);
  puts("PCAP bytes, batching, per-BSSID eviction, reopen, short-write and open-error checks passed");
}
