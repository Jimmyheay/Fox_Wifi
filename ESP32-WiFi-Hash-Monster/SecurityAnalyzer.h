#ifndef SECURITY_ANALYZER_H
#define SECURITY_ANALYZER_H
#include <stddef.h>
#include <stdint.h>

// All lengths exclude FCS. No packed structs or unaligned loads from radio data.
struct EapolKeyFrame {
  uint8_t message;
  uint8_t pmkidCount;
  uint8_t replay[8];
  uint8_t nonce[32];
};
struct RsnInfo {
  bool wpa3, transition, pmfCapable, pmfRequired;
  uint8_t pmkidCount;
};
struct ManagementInfo {
  const uint8_t* ssid;
  uint8_t ssidLength;
  bool hasSsid, hasRsn;
  RsnInfo rsn;
};
struct SaeAuthentication { uint8_t sequence; uint16_t group; };

// Cheap classification for the Wi-Fi task; full validation happens in the consumer.
bool isEapolData(const uint8_t* frame, size_t length);
bool parseEapolKeyFrame(const uint8_t* frame, size_t length, EapolKeyFrame* out);
bool parseRsnInformationElements(const uint8_t* ies, size_t length, RsnInfo* out);
bool parseManagementFrame(const uint8_t* frame, size_t length, ManagementInfo* out);
SaeAuthentication parseSaeAuthentication(const uint8_t* frame, size_t length);
bool getInfrastructurePeers(const uint8_t* frame, size_t length, uint8_t ap[6], uint8_t station[6]);

// A coherent M1->M4 observation, not cryptographic MIC verification.
class HandshakeTracker {
 public:
  bool observe(const uint8_t ap[6], const uint8_t station[6], const EapolKeyFrame& key, uint32_t now);
 private:
  struct State {
    uint8_t ap[6], station[6], replay1[8], replay3[8], anonce[32], phase;
    uint32_t lastSeen;
  } states[8] = {};
};
// Stable ASCII filename stem; SSIDs are arbitrary octets, not C strings.
void captureStem(char* out, size_t capacity, const uint8_t* ssid, size_t length, const uint8_t bssid[6]);
#endif
