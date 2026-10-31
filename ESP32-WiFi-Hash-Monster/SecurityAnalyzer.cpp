#include "SecurityAnalyzer.h"
#include <stdio.h>
#include <string.h>

static uint16_t le16(const uint8_t* p) { return uint16_t(p[0]) | (uint16_t(p[1]) << 8); }
static uint16_t be16(const uint8_t* p) { return (uint16_t(p[0]) << 8) | p[1]; }
static bool suite(const uint8_t* p, uint8_t type) { return p[0] == 0 && p[1] == 15 && p[2] == 172 && p[3] == type; }
static bool nonzero(const uint8_t* p, size_t n) { uint8_t v = 0; while (n--) v |= *p++; return v != 0; }

static size_t eapolOffset(const uint8_t* f, size_t n) {
  if (!f || n < 24 || (f[0] & 0x0f) != 8 || (f[0] & 0x40) ||
      (f[1] & 0x44) || (f[22] & 15)) return 0; // null, encrypted or fragmented
  const bool to = f[1] & 1, from = f[1] & 2;
  if (to == from) return 0; // no IBSS/WDS support
  size_t h = 24;
  if (f[0] & 0x80) {
    if (n < h + 2 || (f[h] & 0x80)) return 0; // A-MSDU needs subframe decoding
    h += 2;
    if (f[1] & 0x80) h += 4; // HT Control, only with QoS + Order
  }
  static const uint8_t llc[] = {0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e};
  return n >= h + sizeof(llc) && !memcmp(f + h, llc, sizeof(llc)) ? h + 8 : 0;
}
bool isEapolData(const uint8_t* f, size_t n) { return eapolOffset(f, n) != 0; }

bool parseEapolKeyFrame(const uint8_t* f, size_t n, EapolKeyFrame* out) {
  if (!out) return false;
  *out = {};
  const size_t offset = eapolOffset(f, n);
  if (!offset || n - offset < 4) return false;
  const uint8_t* e = f + offset;
  const size_t body = be16(e + 2);
  if (e[0] < 1 || e[0] > 3 || e[1] != 3 || body < 95 || body > n - offset - 4) return false;
  const uint8_t* k = e + 4;
  const uint16_t info = be16(k + 1);
  const size_t dataLength = be16(k + 93);
  if (k[0] != 2 || dataLength != body - 95 || !(info & 8) ||
      (info & 0x0c00) || (info & 7) < 1 || (info & 7) > 3) return false;
  const bool ack = info & 0x80, mic = info & 0x100, install = info & 0x40;
  const bool secure = info & 0x200, encrypted = info & 0x1000;
  if (ack != bool(f[1] & 2)) return false;
  uint8_t message = 0;
  if (ack && !mic && !install && !secure && !encrypted) message = 1;
  else if (!ack && mic && !install && !secure && !encrypted) message = 2;
  else if (ack && mic && install) message = 3;
  else if (!ack && mic && !install && secure && !encrypted && !dataLength) message = 4;
  if (!message || (message != 4 && !nonzero(k + 13, 32)) || (mic && !nonzero(k + 77, 16))) return false;
  uint8_t pmkids = 0;
  if (!encrypted) {
    for (size_t at = 0; at < dataLength;) {
      // RSN padding may use a terminal vendor byte followed by zeros.
      if (k[95 + at] == 0xdd) {
        if (at + 1 == dataLength) break;
        if (k[96 + at] == 0) {
          if (nonzero(k + 97 + at, dataLength - at - 2)) return false;
          break;
        }
      }
      if (dataLength - at < 2) return false;
      const uint8_t* ie = k + 95 + at;
      const size_t size = ie[1];
      if (size > dataLength - at - 2) return false;
      if (ie[0] == 0xdd && size == 20 && suite(ie + 2, 4) && nonzero(ie + 6, 16)) ++pmkids;
      at += size + 2;
    }
  }
  out->message = message;
  out->pmkidCount = pmkids;
  memcpy(out->replay, k + 5, 8);
  memcpy(out->nonce, k + 13, 32);
  return true;
}

static bool parseRsn(const uint8_t* p, size_t n, RsnInfo* out) {
  *out = {};
  if (n < 8 || le16(p) != 1) return false;
  size_t at = 6;
  const size_t pairs = le16(p + at); at += 2;
  if (!pairs || pairs > (n - at) / 4) return false;
  at += pairs * 4;
  if (n - at < 2) return false;
  const size_t akms = le16(p + at); at += 2;
  if (!akms || akms > (n - at) / 4) return false;
  bool sae = false, psk = false;
  for (size_t i = 0; i < akms; ++i) {
    sae |= suite(p + at + i * 4, 8) || suite(p + at + i * 4, 9);
    psk |= suite(p + at + i * 4, 2) || suite(p + at + i * 4, 4);
  }
  at += akms * 4;
  out->wpa3 = sae; out->transition = sae && psk;
  if (at == n) return true;
  if (n - at < 2) return false;
  const uint16_t caps = le16(p + at); at += 2;
  out->pmfCapable = caps & 0x80; out->pmfRequired = caps & 0x40;
  if (at == n) return true;
  if (n - at < 2) return false;
  const size_t count = le16(p + at); at += 2;
  if (count > (n - at) / 16) return false;
  for (size_t i = 0; i < count; ++i) out->pmkidCount += nonzero(p + at + i * 16, 16);
  at += count * 16;
  return at == n || n - at == 4; // optional group management cipher
}

bool parseRsnInformationElements(const uint8_t* ies, size_t n, RsnInfo* out) {
  if (!ies || !out) return false;
  *out = {};
  bool found = false;
  for (size_t at = 0; at < n;) {
    if (n - at < 2 || ies[at + 1] > n - at - 2) return false;
    const size_t size = ies[at + 1];
    if (ies[at] == 48) {
      if (found || !parseRsn(ies + at + 2, size, out)) return false;
      found = true;
    }
    at += size + 2;
  }
  return found;
}

bool parseManagementFrame(const uint8_t* f, size_t n, ManagementInfo* out) {
  if (!f || !out || n < 24 || (f[0] & 15) || (f[1] & 0x47) || (f[22] & 15)) return false;
  *out = {};
  size_t start;
  switch (f[0] >> 4) {
    case 8: case 5: start = 36; break; // beacon / probe response
    case 0: start = 28; break; // association request
    case 2: start = 34; break; // reassociation request
    case 1: case 3:
      start = 30;
      if (n < start || le16(f + 26)) return false; // unsuccessful response
      break;
    default: return false;
  }
  if (n < start) return false;
  for (size_t at = start; at < n;) {
    if (n - at < 2 || f[at + 1] > n - at - 2) return false;
    const size_t size = f[at + 1];
    if (f[at] == 0) {
      if (out->hasSsid || size > 32) return false;
      out->hasSsid = true; out->ssid = f + at + 2; out->ssidLength = size;
    } else if (f[at] == 48) {
      if (out->hasRsn || !parseRsn(f + at + 2, size, &out->rsn)) return false;
      out->hasRsn = true;
    }
    at += size + 2;
  }
  return true;
}

SaeAuthentication parseSaeAuthentication(const uint8_t* f, size_t n) {
  if (!f || n < 30 || f[0] != 0xb0 || (f[1] & 0x47) || (f[22] & 15) || le16(f + 24) != 3 || le16(f + 28)) return {0, 0};
  const uint16_t sequence = le16(f + 26);
  if (sequence != 1 && sequence != 2) return {0, 0};
  if (sequence == 1 && n < 32) return {0, 0};
  return {uint8_t(sequence), uint16_t(sequence == 1 ? le16(f + 30) : 0)};
}

bool getInfrastructurePeers(const uint8_t* f, size_t n, uint8_t ap[6], uint8_t station[6]) {
  if (!f || !ap || !station || n < 24 || (f[0] & 15) != 8) return false;
  const bool to = f[1] & 1, from = f[1] & 2;
  if (to == from) return false;
  memcpy(ap, f + (from ? 10 : 4), 6);
  memcpy(station, f + (from ? 4 : 10), 6);
  return !(ap[0] & 1) && !(station[0] & 1);
}

bool HandshakeTracker::observe(const uint8_t ap[6], const uint8_t sta[6], const EapolKeyFrame& k, uint32_t now) {
  State* s = nullptr;
  State* oldest = &states[0];
  for (auto& candidate : states) {
    if (candidate.phase && !memcmp(candidate.ap, ap, 6) && !memcmp(candidate.station, sta, 6)) { s = &candidate; break; }
    if (!candidate.phase || uint32_t(now - candidate.lastSeen) > uint32_t(now - oldest->lastSeen)) oldest = &candidate;
  }
  if (!s) {
    if (k.message != 1) return false;
    s = oldest; *s = {};
    memcpy(s->ap, ap, 6); memcpy(s->station, sta, 6);
  }
  if (uint32_t(now - s->lastSeen) > 10000) s->phase = 0;
  if (k.message == 1) {
    if (s->phase && !memcmp(s->replay1, k.replay, 8) && !memcmp(s->anonce, k.nonce, 32)) return false; // retry
    s->phase = 1;
    memcpy(s->replay1, k.replay, 8); memcpy(s->anonce, k.nonce, 32);
  } else if (k.message == 2 && s->phase == 1 && !memcmp(s->replay1, k.replay, 8)) s->phase = 2;
  else if (k.message == 3 && s->phase == 2 && memcmp(k.replay, s->replay1, 8) > 0 && !memcmp(s->anonce, k.nonce, 32)) {
    s->phase = 3; memcpy(s->replay3, k.replay, 8);
  } else if (k.message == 4 && s->phase == 3 && !memcmp(s->replay3, k.replay, 8)) {
    s->phase = 4; s->lastSeen = now; return true;
  } else return false;
  s->lastSeen = now;
  return false;
}

void captureStem(char* out, size_t cap, const uint8_t* ssid, size_t n, const uint8_t bssid[6]) {
  char name[33]; size_t used = 0;
  for (size_t i = 0; ssid && i < n && i < 32; ++i) {
    const uint8_t c = ssid[i];
    const char safe = ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') ? char(c) : '_';
    if (safe != '_' || (used && name[used - 1] != '_')) name[used++] = safe;
  }
  while (used && name[used - 1] == '_') --used;
  name[used] = 0;
  snprintf(out, cap, "%s_%02x%02x%02x%02x%02x%02x", used ? name : "hidden", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
}
