#ifndef PCAP_FORMAT_H
#define PCAP_FORMAT_H
#include <stdint.h>
namespace Pcap {
constexpr uint32_t snapLength = 2500;
inline void le32(uint8_t* p, uint32_t v) { for (unsigned i = 0; i < 4; ++i) p[i] = uint8_t(v >> (8 * i)); }
inline void globalHeader(uint8_t* p) {
  const uint8_t header[24] = {0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 105, 0, 0, 0};
  for (unsigned i = 0; i < 24; ++i) p[i] = header[i];
  le32(p + 16, snapLength); // DLT_IEEE802_11, without FCS/radiotap
}
inline void recordHeader(uint8_t* p, uint64_t microseconds, uint32_t length) {
  le32(p, uint32_t(microseconds / 1000000)); le32(p + 4, uint32_t(microseconds % 1000000));
  le32(p + 8, length); le32(p + 12, length);
}
}
#endif
