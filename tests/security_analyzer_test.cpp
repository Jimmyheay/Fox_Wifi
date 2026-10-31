#include "SecurityAnalyzer.h"
#include "CaptureQueue.h"
#include "PcapFormat.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <thread>
#include <vector>

static const uint8_t ap[6] = {2, 1, 2, 3, 4, 5}, sta[6] = {4, 5, 6, 7, 8, 9};
static unsigned checks = 0;
#define CHECK(x) do { ++checks; assert(x); } while (0)
static void be16(uint8_t* p, unsigned n) { p[0] = n >> 8; p[1] = n; }
static std::vector<uint8_t> eapol(unsigned message, bool qos = false, bool ht = false, bool pmkid = false) {
  const size_t header = 24 + (qos ? 2 : 0) + (ht ? 4 : 0);
  std::vector<uint8_t> f(header + 8 + 4 + 95 + (pmkid ? 22 : 0), 0);
  f[0] = qos ? 0x88 : 8;
  const bool from = message == 1 || message == 3;
  f[1] = (from ? 2 : 1) | (ht ? 0x80 : 0);
  memcpy(f.data() + 4, from ? sta : ap, 6); memcpy(f.data() + 10, from ? ap : sta, 6);
  memcpy(f.data() + 16, ap, 6);
  const uint8_t llc[] = {0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e};
  memcpy(f.data() + header, llc, 8);
  uint8_t* e = f.data() + header + 8;
  e[0] = 2; e[1] = 3; be16(e + 2, 95 + (pmkid ? 22 : 0));
  uint8_t* k = e + 4; k[0] = 2;
  const unsigned info[] = {0, 0x008a, 0x010a, 0x13ca, 0x030a};
  be16(k + 1, info[message]); k[12] = message < 3 ? 1 : 2;
  if (message != 4) memset(k + 13, message == 2 ? 0x22 : 0x11, 32);
  if (message != 1) memset(k + 77, 0x55, 16);
  if (pmkid) {
    be16(k + 93, 22);
    const uint8_t prefix[] = {0xdd, 20, 0, 15, 172, 4}; memcpy(k + 95, prefix, 6); memset(k + 101, 0x33, 16);
  }
  return f;
}
static void parserTests() {
  EapolKeyFrame key{};
  for (unsigned m = 1; m <= 4; ++m) for (unsigned layout = 0; layout < 3; ++layout) {
    auto f = eapol(m, layout != 0, layout == 2, m == 1);
    CHECK(parseEapolKeyFrame(f.data(), f.size(), &key)); CHECK(key.message == m);
    CHECK(key.pmkidCount == (m == 1 ? 1 : 0));
    for (size_t n = 0; n < f.size(); ++n) CHECK(!parseEapolKeyFrame(f.data(), n, &key));
    uint8_t a[6], s[6]; CHECK(getInfrastructurePeers(f.data(), f.size(), a, s)); CHECK(!memcmp(a, ap, 6) && !memcmp(s, sta, 6));
  }
  auto f = eapol(1, false, false, true);
  f[24] = 0; CHECK(!parseEapolKeyFrame(f.data(), f.size(), &key)); f[24] = 0xaa;
  f[1] |= 0x40; CHECK(!parseEapolKeyFrame(f.data(), f.size(), &key)); f[1] &= ~0x40;
  f[1] |= 4; CHECK(!parseEapolKeyFrame(f.data(), f.size(), &key)); f[1] &= ~4;
  f[22] = 1; CHECK(!parseEapolKeyFrame(f.data(), f.size(), &key)); f[22] = 0;
  f[36 + 2] &= ~8; CHECK(!parseEapolKeyFrame(f.data(), f.size(), &key)); f = eapol(1, false, false, true);
  f[36 + 94] = 21; CHECK(!parseEapolKeyFrame(f.data(), f.size(), &key)); f = eapol(1, false, false, true);
  f[36 + 96] = 21; CHECK(!parseEapolKeyFrame(f.data(), f.size(), &key));
  f = eapol(2, true); f[24] = 0x80; CHECK(!parseEapolKeyFrame(f.data(), f.size(), &key));
  f = eapol(3); memset(f.data() + 36 + 77, 0, 16); CHECK(!parseEapolKeyFrame(f.data(), f.size(), &key));
  // RSN IE: PSK+SAE, PMF capable, one real PMKID (not a byte-pattern search).
  uint8_t rsn[] = {48, 42, 1,0, 0,15,172,4, 1,0, 0,15,172,4, 2,0, 0,15,172,2, 0,15,172,8, 128,0, 1,0,
                   1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
  RsnInfo info{}; CHECK(parseRsnInformationElements(rsn, sizeof(rsn), &info));
  CHECK(info.wpa3 && info.transition && info.pmfCapable && !info.pmfRequired && info.pmkidCount == 1);
  rsn[26] = 2; CHECK(!parseRsnInformationElements(rsn, sizeof(rsn), &info)); rsn[26] = 1;
  std::vector<uint8_t> management(28, 0); memcpy(management.data() + 16, ap, 6);
  const uint8_t ssid[] = {0, 4, 'A', '/', 0, 0xff};
  management.insert(management.end(), ssid, ssid + sizeof(ssid));
  management.insert(management.end(), rsn, rsn + sizeof(rsn));
  ManagementInfo mg{}; CHECK(parseManagementFrame(management.data(), management.size(), &mg));
  CHECK(mg.hasSsid && mg.ssidLength == 4 && mg.ssid[2] == 0 && mg.rsn.pmkidCount == 1);
  management[29] = 33; CHECK(!parseManagementFrame(management.data(), management.size(), &mg));
  uint8_t sae[32] = {}; sae[0] = 0xb0; sae[24] = 3; sae[26] = 1; sae[30] = 19;
  CHECK(parseSaeAuthentication(sae, sizeof(sae)).group == 19);
  sae[26] = 2; sae[30] = 1; CHECK(parseSaeAuthentication(sae, sizeof(sae)).group == 0);
  char stem[64]; const uint8_t name[] = {'A','/',' ','B','.',0,0xff};
  captureStem(stem, sizeof(stem), name, sizeof(name), ap); CHECK(!strcmp(stem, "A_B_020102030405"));
  captureStem(stem, sizeof(stem), nullptr, 0, ap); CHECK(!strcmp(stem, "hidden_020102030405"));
}
static EapolKeyFrame parsed(unsigned m) { auto f = eapol(m); EapolKeyFrame k{}; CHECK(parseEapolKeyFrame(f.data(), f.size(), &k)); return k; }
static void trackerTests() {
  HandshakeTracker tracker;
  auto a = parsed(1), b = parsed(2), c = parsed(3), d = parsed(4);
  CHECK(!tracker.observe(ap, sta, a, 10)); CHECK(!tracker.observe(ap, sta, a, 11));
  CHECK(!tracker.observe(ap, sta, b, 12)); CHECK(!tracker.observe(ap, sta, c, 13));
  CHECK(tracker.observe(ap, sta, d, 14)); CHECK(!tracker.observe(ap, sta, d, 15));
  b.replay[7] = 9; CHECK(!tracker.observe(ap, sta, a, 20)); CHECK(!tracker.observe(ap, sta, b, 21));
  CHECK(!tracker.observe(ap, sta, c, 22)); CHECK(!tracker.observe(ap, sta, d, 23));
  HandshakeTracker peers; uint8_t otherSta[6] = {6, 1, 2, 3, 4, 5};
  b = parsed(2);
  CHECK(!peers.observe(ap, sta, a, 1)); CHECK(!peers.observe(ap, otherSta, b, 2));
  CHECK(!peers.observe(ap, sta, c, 3)); CHECK(!peers.observe(ap, sta, d, 4));
  HandshakeTracker timed;
  CHECK(!timed.observe(ap, sta, a, 1)); b = parsed(2);
  CHECK(!timed.observe(ap, sta, b, 10002)); CHECK(!timed.observe(ap, sta, c, 10003)); CHECK(!timed.observe(ap, sta, d, 10004));
  HandshakeTracker nonce;
  CHECK(!nonce.observe(ap, sta, a, 1)); CHECK(!nonce.observe(ap, sta, b, 2)); c.nonce[0] ^= 1;
  CHECK(!nonce.observe(ap, sta, c, 3)); CHECK(!nonce.observe(ap, sta, d, 4));
}
static void queueTests() {
  CaptureQueue queue; uint8_t bytes[24] = {};
  for (unsigned i = 0; i < 12; ++i) CHECK(queue.push(bytes, sizeof(bytes), i, -42, 6, false));
  CHECK(!queue.push(bytes, sizeof(bytes), 0, -42, 6, false));
  for (unsigned i = 12; i < 16; ++i) CHECK(queue.push(bytes, sizeof(bytes), i, -42, 6, true));
  CHECK(!queue.push(bytes, sizeof(bytes), 0, -42, 6, true));
  for (unsigned i = 0; i < 16; ++i) { CHECK(queue.front() && queue.front()->timestamp == i); queue.pop(); }
  CHECK(!queue.front());
  CHECK(!queue.push(bytes, Pcap::snapLength + 1, 0, 0, 1, true));
  CHECK(!queue.push(nullptr, 24, 0, 0, 1, true));
  // Cross-thread stress checks that publication never exposes partially copied data.
  std::thread producer([&]() {
    for (uint32_t i = 0; i < 50000; ++i) {
      memcpy(bytes, &i, 4);
      while (!queue.push(bytes, sizeof(bytes), i, -50, 1, true)) std::this_thread::yield();
    }
  });
  for (uint32_t i = 0; i < 50000; ++i) {
    const CaptureQueue::Packet* p;
    while (!(p = queue.front())) std::this_thread::yield();
    uint32_t value; memcpy(&value, p->bytes, 4);
    CHECK(value == i && p->timestamp == i && p->length == sizeof(bytes)); queue.pop();
  }
  producer.join();
}
static void fuzzBounds() {
  uint32_t seed = 1; uint8_t f[512];
  for (unsigned i = 0; i < 20000; ++i) {
    for (auto& byte : f) { seed = seed * 1664525 + 1013904223; byte = seed >> 24; }
    const size_t n = seed % sizeof(f); EapolKeyFrame k{}; RsnInfo r{}; ManagementInfo m{};
    parseEapolKeyFrame(f, n, &k); parseRsnInformationElements(f, n, &r); parseManagementFrame(f, n, &m); parseSaeAuthentication(f, n);
  }
}
int main() {
  parserTests(); trackerTests(); queueTests(); fuzzBounds();
  uint8_t h[24]; Pcap::globalHeader(h);
  CHECK(h[0] == 0xd4 && h[4] == 2 && h[20] == 105);
  Pcap::recordHeader(h, 4294967297ULL, 123);
  const uint8_t expected[] = {0xc6, 0x10, 0, 0, 0x81, 0xc2, 0x0e, 0, 123, 0, 0, 0, 123, 0, 0, 0};
  CHECK(!memcmp(h, expected, 16));
  printf("%u checks passed; 20,000 malformed-input probes; 50,000 queued packets\n", checks);
}
