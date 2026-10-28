#include "SecurityAnalyzer.h"
#include <string.h>

static uint16_t le16(const uint8_t* p) { return uint16_t(p[0]) | (uint16_t(p[1]) << 8); }
static bool suite(const uint8_t* p, uint8_t type) { return p[0] == 0x00 && p[1] == 0x0f && p[2] == 0xac && p[3] == type; }

bool parseEapolKeyFrame(const uint8_t* frame, size_t length, EapolKeyFrame* out) {
  if (!frame || !out || length < 36) return false;
  size_t llc = SIZE_MAX;
  // Data headers are normally 24 bytes, or 26 with QoS. Look in both safe locations.
  const size_t candidates[] = {30, 32};
  for (size_t candidate : candidates)
    if (candidate + 4 <= length && frame[candidate] == 0x88 && frame[candidate + 1] == 0x8e) { llc = candidate + 2; break; }
  if (llc == SIZE_MAX || llc + 7 > length || frame[llc + 1] != 3) return false;
  const size_t eapolLength = (size_t(frame[llc + 2]) << 8) | frame[llc + 3];
  if (llc + 4 + eapolLength > length || eapolLength < 95 || frame[llc + 4] != 2) return false;
  const uint16_t keyInfo = (uint16_t(frame[llc + 5]) << 8) | frame[llc + 6];
  const bool ack = keyInfo & 0x0080, mic = keyInfo & 0x0100, install = keyInfo & 0x0040, secure = keyInfo & 0x0200;
  uint8_t message = 0;
  if (ack && !mic) message = 1;
  else if (!ack && mic && !secure) message = 2;
  else if (ack && mic && install) message = 3;
  else if (!ack && mic && secure) message = 4;
  if (!message) return false;
  out->message = message;
  out->pmkidCount = 0;
  // Key data length is after descriptor, info, key length, replay counter, nonce,
  // IV, RSC, key ID and MIC: 93 bytes from descriptor start.
  const size_t descriptor = llc + 4;
  const size_t keyDataLengthOffset = descriptor + 93;
  if (keyDataLengthOffset + 2 > length) return true;
  const size_t keyDataLength = (size_t(frame[keyDataLengthOffset]) << 8) | frame[keyDataLengthOffset + 1];
  const size_t keyData = keyDataLengthOffset + 2;
  if (keyData + keyDataLength > length) return true;
  for (size_t i = 0; i + 20 <= keyDataLength; ++i)
    if (frame[keyData + i] == 0xdd && frame[keyData + i + 1] == 20 &&
        frame[keyData + i + 2] == 0x00 && frame[keyData + i + 3] == 0x0f &&
        frame[keyData + i + 4] == 0xac && frame[keyData + i + 5] == 4) ++out->pmkidCount;
  return true;
}

bool parseRsnInformationElements(const uint8_t* ies, size_t length, RsnInfo* out) {
  if (!ies || !out) return false;
  *out = {false, false, false, false};
  for (size_t at = 0; at + 2 <= length;) {
    const uint8_t id = ies[at], size = ies[at + 1]; at += 2;
    if (at + size > length) return false;
    if (id != 48 || size < 20) { at += size; continue; }
    const uint8_t* p = ies + at; size_t left = size;
    if (le16(p) != 1) { at += size; continue; }
    p += 2; left -= 2; // version
    if (left < 4 + 2) { at += size; continue; }
    p += 4; left -= 4; // group cipher
    const uint16_t pairs = le16(p); p += 2; left -= 2;
    if (left < size_t(pairs) * 4 + 2) { at += size; continue; }
    p += size_t(pairs) * 4; left -= size_t(pairs) * 4;
    const uint16_t akms = le16(p); p += 2; left -= 2;
    if (left < size_t(akms) * 4) { at += size; continue; }
    bool sae = false, psk = false;
    for (uint16_t i = 0; i < akms; ++i) { sae |= suite(p + i * 4, 8); psk |= suite(p + i * 4, 2); }
    p += size_t(akms) * 4; left -= size_t(akms) * 4;
    out->wpa3 = sae; out->transition = sae && psk;
    if (left >= 2) { const uint16_t caps = le16(p); out->pmfCapable = caps & 0x0080; out->pmfRequired = caps & 0x0040; }
    return true;
  }
  return false;
}

SaeAuthentication parseSaeAuthentication(const uint8_t* frame, size_t length) {
  if (!frame || length < 30 || frame[0] != 0xb0 || le16(frame + 24) != 3) return {0, 0};
  const uint16_t sequence = le16(frame + 26);
  if (sequence != 1 && sequence != 2) return {0, 0};
  return {uint8_t(sequence), uint16_t(length >= 32 ? le16(frame + 30) : 0)};
}

bool getInfrastructurePeers(const uint8_t* frame, size_t length, uint8_t ap[6], uint8_t station[6]) {
  if (!frame || !ap || !station || length < 24) return false;
  const bool toDS = frame[1] & 1, fromDS = frame[1] & 2;
  if (toDS == fromDS) return false;
  if (fromDS) { memcpy(ap, frame + 10, 6); memcpy(station, frame + 4, 6); }
  else { memcpy(ap, frame + 4, 6); memcpy(station, frame + 10, 6); }
  return true;
}
