#include "SecurityAnalyzer.h"
#include <assert.h>
#include <string.h>

int main() {
  uint8_t e[160] = {}; e[30] = 0x88; e[31] = 0x8e; e[33] = 3; e[34] = 0; e[35] = 120; e[36] = 2; e[37] = 0; e[38] = 0x80;
  e[129] = 0; e[130] = 20; e[131] = 0xdd; e[132] = 20; e[133] = 0; e[134] = 15; e[135] = 172; e[136] = 4;
  EapolKeyFrame key{}; assert(parseEapolKeyFrame(e, sizeof(e), &key) && key.message == 1 && key.pmkidCount == 1);
  uint8_t rsn[] = {48, 24, 1,0, 0,15,172,4, 1,0, 0,15,172,4, 2,0, 0,15,172,2, 0,15,172,8, 128,0};
  RsnInfo info{}; assert(parseRsnInformationElements(rsn, sizeof(rsn), &info) && info.wpa3 && info.transition && info.pmfCapable);
  uint8_t sae[32] = {}; sae[0]=0xb0; sae[24]=3; sae[26]=1; sae[30]=19;
  const SaeAuthentication auth = parseSaeAuthentication(sae, sizeof(sae)); assert(auth.sequence == 1 && auth.group == 19);
}
