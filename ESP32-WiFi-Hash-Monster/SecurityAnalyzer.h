#ifndef SECURITY_ANALYZER_H
#define SECURITY_ANALYZER_H

#include <stddef.h>
#include <stdint.h>

// Passive 802.11 observations only. This code never injects frames or derives keys.
struct EapolKeyFrame {
  uint8_t message;
  uint8_t pmkidCount;
};

struct RsnInfo {
  bool wpa3;
  bool transition;
  bool pmfCapable;
  bool pmfRequired;
};

struct SaeAuthentication {
  uint8_t sequence; // 1 commit, 2 confirm, 0 not SAE
  uint16_t group;
};

bool parseEapolKeyFrame(const uint8_t* frame, size_t length, EapolKeyFrame* out);
bool parseRsnInformationElements(const uint8_t* ies, size_t length, RsnInfo* out);
SaeAuthentication parseSaeAuthentication(const uint8_t* frame, size_t length);
bool getInfrastructurePeers(const uint8_t* frame, size_t length, uint8_t ap[6], uint8_t station[6]);
#endif
