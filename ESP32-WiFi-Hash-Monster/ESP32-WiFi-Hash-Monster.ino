// ESP32-WiFi-Hash-Monster
// 90% based on PacketMonitor32 from spacehuhn //  https://github.com/spacehuhn/PacketMonitor32/
// ported to M5stack by 2018.01.11 macsbug  //    https://macsbug.wordpress.com/2018/01/11/packetmonitor32-with-m5stack/
// modify to capture eapol/handshake with new GUI with the Purple Monster by G4lile0  6/oct/2019
// improvements by tobozo 18/nov/2019:
//   - more compliance with M5 Core functions and TFT_eSprite
//   - SD-loadable support with M5Stack-SD-Updater (requires https://github.com/tobozo/M5Stack-SD-Updater/)
//   - now stable when PSRAM enabled
//   - smoother display rendering using 1-bit sprites for UI
//   - conditional RGB led support, enabled only for M5Fire
//   - buttons reassignment:
//     * SD Activation => BtnA (A for Activation)
//     * Brightness => BtnB (B for Brightness)
//     * Channel => BtnC (C for Channel)
//   - seamless Odroid-GO support (if using https://github.com/tobozo/ESP32-Chimera-Core instead of M5Stack Core)
//  added channel auto-switching (configurable) and reduce the amount of drawing by scriptguru  10/April/2020
//
//
//  more info https://miloserdov.org/?p=1047
//  more info https://www.evilsocket.net/2019/02/13/Pwning-WiFi-networks-with-bettercap-and-the-PMKID-client-less-attack/
// DISPLAY: Channel,RSSI,Packet per Second,eapol,deauth packets,SD Card enabled
// Red NeoPixels deauth  -- Green Neopixel eapol
// Button : click to change channel hold to dis/enable SD
// SD : GPIO4=CS(CD/D3), 23=MOSI(CMD), 18=CLK, 19=MISO(D0)
//--------------------------------------------------------------------

#include <ESP32-Chimera-Core.h>        // https://github.com/tobozo/ESP32-Chimera-Core/
#define tft M5.Lcd
#if !defined USE_M5STACK_UPDATER
  // comment this out to disable SD-Updater
  #define USE_M5STACK_UPDATER
#endif

#ifdef USE_M5STACK_UPDATER
  #ifdef ARDUINO_M5STACK_Core2
    #define M5STACK_UPDATER_MENUDELAY 5000 // how long (millis) the SDUpdater lobby is visible at boot
  #else
    #define M5STACK_UPDATER_MENUDELAY 0 // M5Stack Classic/Fire don't need to see the menu
  #endif
  #define SDU_APP_NAME "WiFi Hash Monster" // title for SD-Updater UI
  #include <M5StackUpdater.h> // https://github.com/tobozo/M5Stack-SD-Updater/
#endif

#if defined ESP_IDF_VERSION_MAJOR && ESP_IDF_VERSION_MAJOR >= 4
  // Use LWIP stack
  #include "esp_wifi.h"
#else
  // Use legacy stack
  #include <SPI.h>
  #include "freertos/FreeRTOS.h"
  #include "esp_wifi.h"
  #include "esp_wifi_types.h"
  #include "esp_system.h"
  #include "esp_event.h"
  #include "esp_event_loop.h"
  #include "nvs_flash.h"
  #include <stdio.h>
  #include <string>
  #include <cstddef>
  esp_err_t event_handler(void* ctx,system_event_t* event){return ESP_OK;}
#endif

#include <Preferences.h>
#include "Buffer.h"
#include "DashboardLayout.h"
#include "FoxAnimation.h"
#include "FoxDisplay.h"
#include "SecurityAnalyzer.h"
#include "FS.h"
#include "SD.h"

#ifdef ARDUINO_M5STACK_FIRE
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wcpp"
  #include <FastLED.h>
  #pragma diagnostic pop
  #define M5STACK_FIRE_NEO_NUM_LEDS 10
  #define M5STACK_FIRE_NEO_DATA_PIN 15
  // Define the array of leds
  CRGB leds[M5STACK_FIRE_NEO_NUM_LEDS];
#endif

#define MAX_CH 13     // 1-14ch(1-11 US,1-13 EU and 1-14 Japan)
#define AUTO_CHANNEL_INTERVAL 15000 // how often to switch channels automatically, in milliseconds
#define USE_SD_BY_DEFAULT true

#define DRAW_DELAY 1000 // redraw graphs every second
#define BUTTON_DEBOUNCE 150 // check button every n millis
#define MAX_SSIDs 1792 // buffer cache size (*32bits) for Beacon information, reduce this in case of memory problems

#if CONFIG_FREERTOS_UNICORE
  #define RUNNING_CORE 0
#else
  #define RUNNING_CORE 1
#endif


/* ===== run-time variables ===== */
Buffer sdBuffer;
Preferences preferences;

bool useSD = USE_SD_BY_DEFAULT;
static bool SDSetupDone = false;
static bool SDReady = false;
static bool UIReady = false;
static bool WelComeTaskReady = false;

uint32_t lastDrawTime = 0;
uint32_t lastButtonTime = millis();
uint32_t lastAutoSwitchChTime = 0;

int autoChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}; // customize this
int AUTO_CH_COUNT = sizeof(autoChannels) / sizeof(int);
int autoChIndex = 0;
int smartCh_old_stuff = 0;
uint8_t autoChMode = 0 ; // 0 No auto -  1 Switch channels automatically   - Smart Switch
const char* authChmodeStr[3] = {"[C]hannel Fixed", "[A]utomatic switching", "[S]mart switching" };
uint32_t tmpPacketCounter;
uint32_t deauths = 0; // deauth frames per second
uint32_t total_deauths = 0; // deauth total frames

uint32_t eapol = 0;         // eapol frames per second
uint32_t total_eapol = 0;   // eapol total frames
volatile uint32_t eapol_messages[4] = {0, 0, 0, 0};
volatile uint32_t complete_handshakes = 0;
volatile uint32_t pmkids_observed = 0;
volatile uint32_t sae_commits = 0;
volatile uint32_t sae_confirms = 0;
volatile uint32_t sae_legacy_groups = 0;
uint32_t wpa3_aps = 0;
uint32_t transition_aps = 0;
uint32_t resilience_findings = 0;
volatile uint32_t lastHandshakeEvent = 0;
volatile uint32_t lastPmkidEvent = 0;
volatile uint32_t lastDeauthEvent = 0;

unsigned int ch = 1;  // current 802.11 channel
unsigned int bright = 100;  // default
unsigned int bright_leds = 100;  // default
unsigned int led_status = 0;
unsigned int ledPacketCounter = 0;

int rssiSum;
int graph_RSSI = 0;
bool rssiValid = false;
int previousRssiY = -1;
unsigned int previousRssiChannel = 0;
uint8_t graphGrid = 0;

int8_t last_rssi;
char   last_ssid[33] = { '[', 'n', 'o', 'n', 'e', ']', '\0' };
char   last_ssid_mac[18] = {0};
char   last_eapol_ssid[33] = { '[', 'n', 'o', 'n', 'e', ']', '\0' };
char   last_eapol_mac[18] = {0};

TFT_eSprite header = TFT_eSprite(&tft); // 1bit   color sprite for header
TFT_eSprite footer = TFT_eSprite(&tft); // 1bit   color sprite for footer
TFT_eSprite stats = TFT_eSprite(&tft);       // compact black/white metrics panel
TFT_eSprite signalGraph = TFT_eSprite(&tft); // the only graph: yellow RSSI history


/*
 * Convert Ethernet address to standard hex-digits-and-colons printable form.
 * Re-entrant version (GNU extensions).
 * Inspired from https://android.googlesource.com/platform/bionic/+/master/libc/bionic/ether_ntoa.c
 */
char *ether_ntoa_r( const uint8_t *addr, char * buf )
{
  snprintf( buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
    addr[0], addr[1],
    addr[2], addr[3],
    addr[4], addr[5]
  );
  return buf;
}
/*
 * Convert Ethernet address to standard hex-digits-and-colons printable form.
 * Inspired from https://android.googlesource.com/platform/bionic/+/master/libc/bionic/ether_ntoa.c
 */
char *ether_ntoa( const uint8_t *addr )
{
  static char buf[18];
  return ether_ntoa_r( addr, buf );
}


/*
 * Format numbers to 4 chars when possible
 * using M/K units, may overflow over 999M
 */
static char unitOutput[16] = {'\0'};
static char *formatUnit( int64_t number )
{
  *unitOutput = {'\0'};
  if( number > 999999 ) {
    sprintf(unitOutput, "%lldM", number/1000000);
  } else if( number > 999 ) {
    sprintf(unitOutput, "%lldK", number/1000);
  } else {
    sprintf(unitOutput, "%lld", number);
  }
  return unitOutput;
}



/*
 * Data structure for beacon information
 */
struct ssid_info
{
  uint8_t mac[6];
  uint8_t ssid[33];
  uint8_t ssid_len;
  bool    ssid_eapol;     // to mark if we already have the eapol.
};


/*
 * Global variables for storing beacons and clients
 */
ssid_info ssid_known[MAX_SSIDs];
uint32_t ssid_count = 0;  //
uint32_t ssid_eapol_count= 0;       // eapol frames per second

struct HandshakeState {
  uint8_t ap[6];
  uint8_t station[6];
  uint8_t messages;
  uint32_t lastSeen;
};
static HandshakeState handshakeStates[8] = {};

static void trackHandshake(const uint8_t* frame, uint32_t length, uint8_t message)
{
  uint8_t ap[6], station[6];
  if (!getInfrastructurePeers(frame, length, ap, station) || message < 1 || message > 4) return;
  const uint32_t now = millis();
  HandshakeState* state = &handshakeStates[0];
  for (auto& candidate : handshakeStates) {
    if (!memcmp(candidate.ap, ap, 6) && !memcmp(candidate.station, station, 6)) { state = &candidate; break; }
    if (!candidate.lastSeen || uint32_t(now - candidate.lastSeen) > 10000) state = &candidate;
  }
  if (memcmp(state->ap, ap, 6) || memcmp(state->station, station, 6) || uint32_t(now - state->lastSeen) > 10000) {
    memcpy(state->ap, ap, 6); memcpy(state->station, station, 6); state->messages = 0;
  }
  state->messages |= uint8_t(1u << (message - 1));
  state->lastSeen = now;
  if (state->messages == 0x0f) { ++complete_handshakes; lastHandshakeEvent = now; state->messages = 0; }
}


void setupWiFiPromisc()
{
  Serial.println("NVS Flash init");
  nvs_flash_init();
  #if defined ESP_IDF_VERSION_MAJOR && ESP_IDF_VERSION_MAJOR >= 4
    // esp-idf 4.4 uses LWIP
    Serial.println("LWIP init");
    esp_netif_init();
  #else
    Serial.println("TCP adapter init");
    tcpip_adapter_init();
  #endif
  //  wificfg.wifi_task_core_id = 0;
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  #if defined ESP_IDF_VERSION_MAJOR && ESP_IDF_VERSION_MAJOR >= 4
    // esp_event_loop_init is deprecated in esp-idf 4.4
    Serial.println("[1] Skipping event loop init");
  #else
    Serial.println("[1] Attaching NULL event handler");
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
  #endif
  Serial.println("[2] Initing WiFi with config defaults");
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  //ESP_ERROR_CHECK(esp_wifi_set_country(WIFI_COUNTRY_EU));
  Serial.println("[3] Setting wifi storage to ram");
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  Serial.println("[4] Setting wifi mode to NULL");
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
  Serial.println("[5] Starting WiFi");
  ESP_ERROR_CHECK(esp_wifi_start());
  Serial.println("[6] Attaching promiscuous receiver callback");
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous));
  Serial.println("[7] Enabling promiscuous mode");
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
  Serial.printf("[8] Setting WiFi Channel to: %d\n", ch);
  // now switch on monitor mode
  ESP_ERROR_CHECK(esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE));
  Serial.println("[9] WiFi setup done");
}






// ===== main program ================================================
void setup()
{
  #ifdef ARDUINO_M5STACK_FIRE
    // load these before M5.begin() so they can eventually be turned off
    FastLED.addLeds<WS2812B, M5STACK_FIRE_NEO_DATA_PIN, GRB>(leds, M5STACK_FIRE_NEO_NUM_LEDS);
    FastLED.clear();
    FastLED.show();
  #endif
  M5.begin(); // this will fire Serial.begin()

  #ifdef ARDUINO_M5STACK_Core2
    // Core2 is normally held portrait by its touch UI. The dashboard is 320x240.
    tft.setRotation(1);
    tft.setBrightness(bright);
  #endif

  #ifdef USE_M5STACK_UPDATER
    // New SD Updater support, requires the latest version of https://github.com/tobozo/M5Stack-SD-Updater/
    #if defined M5_SD_UPDATER_VERSION_INT
      SDUCfg.setLabelMenu("<< Menu");
      SDUCfg.setLabelSkip("Launch");
    #endif
    checkSDUpdater( SD, MENU_BIN, M5STACK_UPDATER_MENUDELAY, TFCARD_CS_PIN ); // Filesystem, Launcher bin path, Wait delay
  #endif
  // SD card ---------------------------------------------------------
  tft.fillScreen(TFT_BLACK);
  #ifdef ARDUINO_M5STACK_Core2
  // The Core2 remains a live monitor without a card. Do not power it off merely
  // because optional PCAP storage is unavailable at boot.
  uint8_t core2SdAttempts = 20;
  while (!M5.sd_begin() && --core2SdAttempts) {
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setTextDatum(MC_DATUM);
    tft.setTextSize(1);
    tft.drawString("SD optional: monitoring without capture", tft.width()/2, tft.height()/2);
    tft.setTextDatum(TL_DATUM);
    delay(100);
  }
  if (!core2SdAttempts) {
    useSD = false;
    SDSetupDone = false;
  } else {
    SDSetupDone = true;
  }
  #else
  bool toggle = false;
  unsigned long lastcheck = millis();
  while( !M5.sd_begin() ) {
    toggle = !toggle;
    tft.setTextColor( toggle ? TFT_BLACK : TFT_WHITE );
    tft.setTextDatum( MC_DATUM );
    tft.setTextSize( 2 );
    tft.drawString( "INSERT SD", tft.width()/2, tft.height()/2);
    tft.setTextDatum( TL_DATUM );
    delay( toggle ? 300 : 500 );
    // go to sleep after a minute, no need to hammer the SD Card reader
    if( lastcheck + 60000 < millis() ) {
      //Serial.println( GOTOSLEEP_MESSAGE );
      #ifdef ARDUINO_M5STACK_Core2
        M5.sd_end();
        M5.Axp.SetLcdVoltage(2500);
        M5.Axp.PowerOff();
      #elif defined(ARDUINO_M5STACK_FIRE) || defined(ARDUINO_M5Stack_Core_ESP32)
        M5.setWakeupButton( BUTTON_B_PIN );
        M5.powerOFF();
      #endif
    }
  }

  SDSetupDone = true;
  #endif
  preferences.begin("packetmonitor32", false);
  ch         = preferences.getUInt("channel",    1);
  autoChMode = preferences.getUInt("autoChMode", 0);
  preferences.end();

  #ifdef ARDUINO_M5STACK_Core2
    // specific M5Core2 tweaks go here
  #else // M5Classic / M5Fire turn buzzer off
    M5.Speaker.write(0);
  #endif

  xTaskCreatePinnedToCore( bootAnimationTask, "bootAnimationTask", 8192, NULL, 16, NULL, RUNNING_CORE);
  xTaskCreatePinnedToCore( initSpritesTask,   "initSpritesTask",   8192, NULL, 16, NULL, RUNNING_CORE);
  xTaskCreatePinnedToCore( coreTask,          "coreTask",          8192, NULL, 16, NULL, RUNNING_CORE);

  #ifdef ARDUINO_M5STACK_FIRE
  xTaskCreatePinnedToCore( &blinky,           "blinky",            2500, NULL, 1,  NULL, 1);
  #endif

}


// ===== main program ================================================
void loop()
{
  // no need to waste a cycle for an empty loop
  vTaskSuspend(NULL);
}


static bool initTextSprite(TFT_eSprite& sprite, const Dashboard::Rect& rect)
{
  sprite.setColorDepth(1);
  if (!sprite.createSprite(rect.w, rect.h)) return false;
  sprite.setFont(&fonts::AsciiFont8x16);
  sprite.setTextSize(1);
  sprite.setTextDatum(TL_DATUM);
  sprite.setTextColor(TFT_WHITE, TFT_BLACK);
  sprite.setBitmapColor(TFT_WHITE, TFT_BLACK);
  sprite.fillSprite(TFT_BLACK);
  return true;
}

static void initSpritesTask(void* param)
{
  const bool headerOk = initTextSprite(header, Dashboard::header);
  const bool footerOk = initTextSprite(footer, Dashboard::footer);
  const bool statsOk = initTextSprite(stats, Dashboard::stats);
  signalGraph.setColorDepth(8);
  const bool graphOk = signalGraph.createSprite(Dashboard::graph.w, Dashboard::graph.h) != nullptr;
  if (graphOk) signalGraph.fillSprite(TFT_BLACK);
  if (!headerOk || !footerOk || !statsOk || !graphOk) log_e("Dashboard sprite allocation failed");
  UIReady = true;
  vTaskDelete(NULL);
}

static void bootAnimationTask(void* param)
{
  tft.clear();
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setFont(&fonts::FreeMono12pt7b);
  tft.drawString("WiFi Fox", 8, 28);
  tft.setFont(&fonts::Font2);
  tft.drawString("Passive packet monitor", 8, 56);
  tft.setSwapBytes(true);
  renderLargeFox(tft, foxFrameFor(millis(), 1, 0, 0, 0), 176, 86);
  while (!UIReady) vTaskDelay(1);
  vTaskDelay(pdMS_TO_TICKS(700));
  tft.clear();
  tft.drawString("Checking SD...", 8, 74);
  if (!sdBuffer.init()) {
    Serial.println("Error, not enough memory for buffer");
    while (1) vTaskDelay(1);
  }
  if (setupSD()) {
    sdBuffer.checkFS(&SD);
    sdBuffer.pruneZeroFiles(&SD);
    if (!sdBuffer.open(&SD)) { Serial.println("SD ERROR, Can't create file"); useSD = false; }
  } else Serial.println("SD Setup failed");
  tft.drawString("Setting up WiFi...", 8, 44);
  setupWiFiPromisc();
  WelComeTaskReady = true;
  vTaskDelete(NULL);
}



// ===== functions ===================================================
void setChannel(int newChannel)
{
  log_d("Setting new channel to : %d", newChannel );
  ch = newChannel;
  if (ch > MAX_CH || ch < 1) ch = 1;
  // avoid to write too much on the flash in auto-switching mode
  if (autoChMode == 0) {
    preferences.begin("packetmonitor32", false);
    preferences.putUInt("channel", ch);
    preferences.end();
  }
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous);
}


void autoSwitchChannel(uint32_t currentTime)
{
  autoChIndex = (autoChIndex + 1) % AUTO_CH_COUNT;
  setChannel(autoChannels[autoChIndex]);
  Serial.printf("[A]uto-switching to channel %d\n", ch);
  lastAutoSwitchChTime = currentTime;
}


void smartSwitchChannel(uint32_t currentTime)
{
  lastAutoSwitchChTime = currentTime;

  if (smartCh_old_stuff < ssid_count+total_eapol+total_deauths) {
    smartCh_old_stuff = ssid_count+total_eapol+total_deauths;
    Serial.printf("[S]mart-switching: Channel #%d is interesting, collected %d packets so far :)\n", ch, smartCh_old_stuff);
  } else {
    unsigned int oldchannel = ch;
    smartCh_old_stuff = ssid_count+total_eapol+total_deauths;
    ch = (ch + 1) % (MAX_CH + 1);
    Serial.printf("[S]mart-switching: Channel #%d is boring, smart-switching to #%d\n", oldchannel, ch);
    setChannel(ch);
  }
}



// ===== functions ===================================================



bool setupSD()
{
  if( SDSetupDone ) return true;
  M5.sd_end();
  int attempts = 20;
  do {
    SDSetupDone = M5.sd_begin(); // SD.begin( TFCARD_CS_PIN );
  } while( --attempts > 0 && ! SDSetupDone );

  if (!SDSetupDone ) {
    Serial.println("Card Mount Failed"); return false;
  }
  uint8_t cardType = SD.cardType();
  if (cardType == CARD_NONE) {
    SDSetupDone = false;
    Serial.println("No SD_MMC card attached"); return false;
  }
  Serial.print("SD_MMC Card Type: ");
  if (cardType == CARD_MMC) {
    Serial.println("MMC");
  } else if (cardType == CARD_SD) {
    Serial.println("SDSC");
  } else if (cardType == CARD_SDHC) {
    Serial.println("SDHC");
  } else {
    Serial.println("UNKNOWN");
  }
  uint64_t cardSize = SD.cardSize() / (1024 * 1024);
  Serial.printf("SD_MMC Card Size: %lluMB\n", cardSize);
  SDSetupDone = true;
  return true;
}

// ===== functions ===================================================

#define DATA_LENGTH           112
#define TYPE_MANAGEMENT       0x00
#define TYPE_CONTROL          0x01
#define TYPE_DATA             0x02
#define SUBTYPE_PROBE_REQUEST 0x04
#define SUBTYPE_PROBE_RESPONSE 0x05
#define SUBTYPE_BEACONS        0x08


struct RxControl
{
  signed rssi:8; // signal intensity of packet
  unsigned rate:4;
  unsigned is_group:1;
  unsigned:1;
  unsigned sig_mode:2; // 0:is 11n packet; 1:is not 11n packet;
  unsigned legacy_length:12; // if not 11n packet, shows length of packet.
  unsigned damatch0:1;
  unsigned damatch1:1;
  unsigned bssidmatch0:1;
  unsigned bssidmatch1:1;
  unsigned MCS:7; // if is 11n packet, shows the modulation and code used (range from 0 to 76)
  unsigned CWB:1; // if is 11n packet, shows if is HT40 packet or not
  unsigned HT_length:16;// if is 11n packet, shows length of packet.
  unsigned Smoothing:1;
  unsigned Not_Sounding:1;
  unsigned:1;
  unsigned Aggregation:1;
  unsigned STBC:2;
  unsigned FEC_CODING:1; // if is 11n packet, shows if is LDPC packet or not.
  unsigned SGI:1;
  unsigned rxend_state:8;
  unsigned ampdu_cnt:8;
  unsigned channel:4; //which channel this packet in.
  unsigned:12;
};


struct SnifferPacket
{
  struct RxControl rx_ctrl;
  uint8_t data[DATA_LENGTH];
  uint16_t cnt;
  uint16_t len;
};


char * wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
  switch(type) {
    case WIFI_PKT_MGMT: return (char*)"MGMT";
    case WIFI_PKT_DATA: return (char*)"DATA";
    default:
    case WIFI_PKT_MISC: return (char*)"MISC";
  }
}


static void setLastSSID(uint16_t start, uint16_t size, uint8_t* data)
{
  int u=0;
  for(uint16_t i = start; i < DATA_LENGTH && i < start+size; i++) {
    //Serial.write(data[i]);
    last_ssid[u]=data[i];
    u++;
  }
  last_ssid[u]=0;
}


void wifi_promiscuous(void* buf, wifi_promiscuous_pkt_type_t type)
{
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;

  if (type == WIFI_PKT_MISC) return;   // wrong packet type
  if (ctrl.sig_len < 24 || ctrl.sig_len > SNAP_LEN) return;
  uint32_t packetLength = ctrl.sig_len;
  if (type == WIFI_PKT_MGMT) {
    if (packetLength < 4) return;
    packetLength -= 4;
  }
  // fix for known bug in the IDF
  // https://github.com/espressif/esp-idf/issues/886
  //Serial.print(".");
  tmpPacketCounter++;
  rssiSum += ctrl.rssi;
  unsigned int u;

  if (type == WIFI_PKT_MGMT &&  (pkt->payload[0] == 0xA0 || pkt->payload[0] == 0xC0 )) {
    deauths++;
    lastDeauthEvent = millis();
    //      if (useSD) sdBuffer.addPacket(pkt->payload, packetLength);
    // deauth
    #ifdef ARDUINO_M5STACK_FIRE
      for (int pixelNumber = 5; pixelNumber < 10; pixelNumber++){
        leds[pixelNumber].setRGB( bright_leds, 0, 0);;
      }
      FastLED.show();
    #endif
  }

  EapolKeyFrame keyFrame{};
  if (parseEapolKeyFrame(pkt->payload, packetLength, &keyFrame)) {
    eapol++;  // new eapol packets :)
    ++eapol_messages[keyFrame.message - 1];
    pmkids_observed += keyFrame.pmkidCount;
    if (keyFrame.pmkidCount) lastPmkidEvent = millis();
    trackHandshake(pkt->payload, packetLength, keyFrame.message);

    #ifdef ARDUINO_M5STACK_FIRE
      // turn right led in green
      for (int pixelNumber = 0; pixelNumber <= 4; pixelNumber++){
        leds[pixelNumber].setRGB(  0,bright_leds, 0);
      }
      FastLED.show();
    #endif

    log_d("Got EAPOL ...");

    memcpy( &ssid_known[MAX_SSIDs-1].mac, pkt->payload+16, 6 );   // MAC source HW address

    for (u = 0; u < ssid_count; u++) {
      if (!memcmp(ssid_known[u].mac, ssid_known[MAX_SSIDs-1].mac, 6))  {
        // only if is new print it
        if (!ssid_known[u].ssid_eapol) {
          ssid_eapol_count++;
          ssid_known[u].ssid_eapol = true;
          const uint8_t knownLength = ssid_known[u].ssid_len > 32 ? 32 : ssid_known[u].ssid_len;
          for(int i = 0; i < knownLength; i++) {
            last_eapol_ssid[i] = ssid_known[u].ssid[i];
          }
          last_eapol_ssid[knownLength] = 0;
          snprintf( last_eapol_mac, 18, "%s", ether_ntoa(ssid_known[u].mac) );

          Serial.printf("[EAPOL] Found new MAC: %s (SSID: %s)\n",
            ether_ntoa(ssid_known[u].mac),
            last_eapol_ssid
          );
        }
        break;
      }
    }
    //  uint8_t SSID_length = pkt->payload[25];
    //  Serial.println(" SSID: ");
    //  setLastSSID(26, SSID_length, pkt->payload);
    if (useSD) {
      sdBuffer.addPacket(pkt->payload, packetLength);
    }
  }

  //  if (type != WIFI_PKT_MGMT )  return;
  // We add the packets only for prove

  unsigned int frameControl = ((unsigned int)pkt->payload[1] << 8) + pkt->payload[0];

  uint8_t version      = (frameControl & 0b0000000000000011) >> 0;
  uint8_t frameType    = (frameControl & 0b0000000000001100) >> 2;
  uint8_t frameSubType = (frameControl & 0b0000000011110000) >> 4;
  uint8_t toDS         = (frameControl & 0b0000000100000000) >> 8;
  uint8_t fromDS       = (frameControl & 0b0000001000000000) >> 9;

  /*
  // Only look for probe request packets
  if (frameType != TYPE_MANAGEMENT ||
  //  frameSubType != SUBTYPE_PROBE_REQUEST ||
    frameSubType != SUBTYPE_PROBE_RESPONSE ||
    frameSubType != SUBTYPE_BEACONS ||
    frameSubType != 0x0028  // QoS Data
    ) return;
  //if  (!((frameSubType == SUBTYPE_PROBE_RESPONSE) || (frameSubType == SUBTYPE_BEACONS ) || (frameSubType == 0x0028))) return;
  //if  ((frameSubType == SUBTYPE_PROBE_RESPONSE) || (frameSubType == SUBTYPE_BEACONS )) {
  */

  if ((frameSubType == SUBTYPE_BEACONS) && (version == 0) ) {
    RsnInfo rsn{};
    const bool hasRsn = packetLength > 36 && parseRsnInformationElements(pkt->payload + 36, packetLength - 36, &rsn);
    if (packetLength < 38) return;
    uint8_t SSID_length = pkt->payload[37];
    if (SSID_length>32) return;

    bool ascii_error = false;
    for (u =0; u<SSID_length;u++) {
      if (!isprint(pkt->payload[38+u])) {
        log_d("NO IMPRI %02d - %02d", u , SSID_length );
        ascii_error = true;
      }
      if (!isAscii(pkt->payload[38+u])) {
        log_d("NO ASCII %02d - %02d", u , SSID_length );
        ascii_error = true;
      }
    }

    if (ascii_error) return;

    memcpy(&ssid_known[MAX_SSIDs-1].mac,pkt->payload+16,6);

    bool known = false;
    for (u = 0; u < ssid_count; u++) {
      if (!memcmp(ssid_known[u].mac, ssid_known[MAX_SSIDs-1].mac, 6))  {
        known = true;
        break;
      }
    }

    if (!known) {
      if (ssid_count >= MAX_SSIDs - 1) return; // last entry is the comparison scratch slot
      // Count AP capabilities once, when the BSSID is first observed.
      wpa3_aps += hasRsn && rsn.wpa3;
      transition_aps += hasRsn && rsn.transition;
      resilience_findings += hasRsn && rsn.wpa3 && !rsn.pmfRequired;
      // only write the beacon packet the first time that we see it, to reduce writing on the SD-CARD.
      if (useSD) sdBuffer.addPacket(pkt->payload, packetLength);

      memcpy( &ssid_known[ssid_count].mac,  &ssid_known[MAX_SSIDs-1].mac ,6);
      memcpy( &ssid_known[ssid_count].ssid, pkt->payload+38, SSID_length);
      snprintf( last_ssid_mac, 18, "%s", ether_ntoa(ssid_known[ssid_count].mac) );
      ssid_known[ssid_count].ssid_len = SSID_length;
      ssid_count++;
      setLastSSID( 38, SSID_length, pkt->payload );

      last_rssi = pkt->rx_ctrl.rssi;

      Serial.printf("SSID count: %4d | Pack length: %4d  | SSID: %32s | RSSI: %4d\n",
        ssid_count,
        packetLength,
        last_ssid,
        last_rssi
      );
    }
  }

  const SaeAuthentication sae = parseSaeAuthentication(pkt->payload, packetLength);
  if (sae.sequence) {
    if (sae.sequence == 1) ++sae_commits; else ++sae_confirms;
    if (sae.group && sae.group < 19) ++sae_legacy_groups;
  }

  //#define SUBTYPE_PROBE_REQUEST 0x04
  //#define SUBTYPE_PROBE_RESPONSE 0x05
  //#define SUBTYPE_BEACONS        0x08

  if (frameType != TYPE_MANAGEMENT )  return;

  // Only look for probe request packets
  // if (frameType != TYPE_MANAGEMENT ||
  // frameSubType != SUBTYPE_PROBE_REQUEST
  //  )
  //        return;

  //  Serial.print(ctrl.rssi, DEC);
  //Serial.print(".");
  //Serial.println("");
  //Serial.printf("PACKET TYPE=%s CHAN=%02d, RSSI=%02d ",wifi_sniffer_packet_type2str(type),ctrl.channel,ctrl.rssi);
  //Serial.printf("PACKET TYPE=%s CHAN=%02d, RSSI=%02d ",wifi_sniffer_packet_type2str(type),pkt->rx_ctrl.channel,pkt->rx_ctrl.rssi);

  // Deprecated :
  // char addr[] = "00:00:00:00:00:00";
  // getMAC(addr, pkt->payload, 10);

  // log_d("MAC: %s", ether_ntoa( pkt->payload+10 ) );

  //  Serial.print(" Peer MAC: ");
  //  Serial.print(addr);

  //  uint8_t SSID_length = pkt->payload[25];
  //  Serial.print(" SSID: ");
  //  setLastSSID(26, SSID_length, pkt->payload);
}




// ===== UI functions ===================================================

static void drawMetric(const char* label, uint32_t value, int y)
{
  char number[6];
  Dashboard::count(value, number);
  stats.setTextDatum(TL_DATUM);
  stats.drawString(label, 0, y);
  stats.setTextDatum(TR_DATUM);
  stats.drawString(number, Dashboard::stats.w, y);
}

static void drawMetricPair(const char* label, uint32_t first, uint32_t second, int y)
{
  char a[6], b[6], value[12];
  Dashboard::count(first, a);
  Dashboard::count(second, b);
  snprintf(value, sizeof(value), "%s/%s", a, b);
  stats.setTextDatum(TL_DATUM);
  stats.drawString(label, 0, y);
  stats.setTextDatum(TR_DATUM);
  stats.drawString(value, Dashboard::stats.w, y);
}

static void sampleSignal()
{
  const uint32_t packets = tmpPacketCounter;
  rssiValid = packets != 0;
  graph_RSSI = rssiValid ? rssiSum / int(packets) : 0;
  total_eapol += eapol;
  total_deauths += deauths;
  ledPacketCounter = packets;
  tmpPacketCounter = 0;
  rssiSum = 0;
  eapol = 0;
  deauths = 0;

  signalGraph.scroll(-1, 0);
  const int right = Dashboard::graph.w - 1;
  signalGraph.drawFastVLine(right, 0, Dashboard::graph.h, TFT_BLACK);
  graphGrid = (graphGrid + 1) % 10;
  if (!graphGrid) signalGraph.drawFastVLine(right, 0, Dashboard::graph.h, Dashboard::grid);
  else for (int y = 0; y < Dashboard::graph.h; y += 10) signalGraph.drawPixel(right, y, Dashboard::grid);
  if (rssiValid) {
    const int nextY = Dashboard::rssiY(graph_RSSI);
    if (previousRssiY >= 0 && previousRssiChannel == ch) signalGraph.drawLine(right - 1, previousRssiY, right, nextY, TFT_YELLOW);
    else signalGraph.drawPixel(right, nextY, TFT_YELLOW);
    previousRssiY = nextY;
  } else previousRssiY = -1;
  previousRssiChannel = ch;
}

void draw()
{
  if (!bright) return;
  char line[42];
  const char mode = autoChMode == 1 ? 'A' : (autoChMode == 2 ? 'S' : 'C');

  header.fillSprite(TFT_BLACK);
  snprintf(line, sizeof(line), "WiFi FOX  CH %02u %c  SD %s", ch, mode, useSD && SDSetupDone ? "ON" : "OFF");
  header.drawString(line, 8, 4);
  header.drawFastHLine(8, Dashboard::header.h - 1, 304, Dashboard::orange);
  header.pushSprite(Dashboard::header.x, Dashboard::header.y);

  stats.fillSprite(TFT_BLACK);
  drawMetric("HANDSHAKE", complete_handshakes, 0);
  drawMetric("PMKID", pmkids_observed, 18);
  stats.drawFastHLine(0, 36, Dashboard::stats.w, TFT_WHITE);
  drawMetricPair("AP/PKT", ssid_count, ledPacketCounter, 42);
  drawMetric("EAPOL", total_eapol, 60);
  drawMetric("WPA3", wpa3_aps, 78);
  drawMetric("TRANS", transition_aps, 96);
  stats.setTextDatum(TL_DATUM);
  stats.drawString(ssid_eapol_count ? "CAPTURA PASSIVA" : "MONITOR PASSIVO", 0, 112);
  stats.pushSprite(Dashboard::stats.x, Dashboard::stats.y);

  const uint32_t foxNow = millis();
  tft.setSwapBytes(true);
  renderLargeFox(tft, foxFrameFor(foxNow, ledPacketCounter,
                                  lastHandshakeEvent && uint32_t(foxNow - lastHandshakeEvent) < 3500,
                                  lastPmkidEvent && uint32_t(foxNow - lastPmkidEvent) < 3000,
                                  lastDeauthEvent && uint32_t(foxNow - lastDeauthEvent) < 2500),
                 Dashboard::fox.x, Dashboard::fox.y);

  tft.setFont(&fonts::AsciiFont8x16);
  tft.setTextDatum(TL_DATUM);
  tft.fillRect(Dashboard::signal.x, Dashboard::signal.y, Dashboard::signal.w, Dashboard::signal.h, TFT_BLACK);
  tft.setTextColor(TFT_YELLOW, TFT_BLACK);
  if (rssiValid) snprintf(line, sizeof(line), "RSSI %4d dBm     SINAL / 1s", graph_RSSI);
  else snprintf(line, sizeof(line), "RSSI   -- dBm     SEM TRAFEGO");
  tft.drawString(line, Dashboard::signal.x, Dashboard::signal.y);
  signalGraph.pushSprite(Dashboard::graph.x, Dashboard::graph.y);

  footer.fillSprite(TFT_BLACK);
  snprintf(line, sizeof(line), "AP: %.32s", last_ssid[0] ? last_ssid : "[hidden]");
  footer.drawString(line, 8, 2);
  footer.pushSprite(Dashboard::footer.x, Dashboard::footer.y);
}




// ====== Core task ===================================================
void coreTask( void * p )
{
  while( !UIReady ) vTaskDelay(1); // wait for sprites to init
  while( !WelComeTaskReady ) vTaskDelay(1); // wait for animation to terminate

  uint32_t currentTime;
  setChannel(ch);
  Serial.printf("[C]urrent channel: %d\n", ch);
  tmpPacketCounter = 0; // reset to avoid overflow on first render

  tft.clear();

  lastButtonTime = millis();
  M5.update();

  while (true) {
    bool needDraw = false;
    currentTime = millis();

    if (autoChMode==1) {
      if ( currentTime - lastAutoSwitchChTime > AUTO_CHANNEL_INTERVAL ) {
        autoSwitchChannel(currentTime);
        needDraw = true;
      }
    }

    if (autoChMode==2) {
      if ( currentTime - lastAutoSwitchChTime > AUTO_CHANNEL_INTERVAL ) {
        smartSwitchChannel(currentTime);
        needDraw = true;
      }
    }

    if ( currentTime - lastButtonTime > BUTTON_DEBOUNCE ) {
      M5.update();
      // buttons assignment :
      //  - Incognito mode => BtnA short press (toggles display)
      //  - SD Activation  => BtnA long press (enable/disable SD)
      //  - Brightness     => BtnB short press (cycle through values)
      //  - Channel hop    => BtnC long press for mode change, short press for manual change
      if( M5.BtnA.wasReleased() ) {
        if (bright>1) {
          Serial.println("Incognito Mode");
          bright=0;
          bright_leds=0;
          tft.setBrightness(bright);
        } else {
          bright=100;
          bright_leds=100;
          tft.setBrightness(bright);
        }
      } else if (M5.BtnA.wasReleasefor(700)) {
        // toggle SD use
        if ( useSD ) { // in use, disable
          sdBuffer.close(&SD); // flush current buffer
          useSD = false;
          SDSetupDone = false;
          M5.sd_end();
        } else { // not in use, try to enable
          if ( setupSD() ) {
            if( !sdBuffer.open(&SD) ) {
              Serial.println(" SD ERROR, Can't create file, disabling SD");
              useSD = false;
              SDSetupDone = false;
              M5.sd_end();
            }
          }
        }
        needDraw = true;
      }

      if( M5.BtnB.wasReleased() ) {
        bright+=50;
        if (bright>251) bright=0;
        tft.setBrightness(bright);
      } else if (M5.BtnB.wasReleasefor(700)) {
        bright_leds+=100;
        if (bright_leds>251) bright_leds=0;
        Serial.println(bright_leds);
      }

      if( M5.BtnC.wasReleased() ) {
        setChannel(ch + 1);
        needDraw = true;
      } else if (M5.BtnC.wasReleasefor(700)) {
        autoChMode++;
        if (autoChMode>2) autoChMode=0;
        Serial.printf("Channel hop mode is now set to: %s\n", authChmodeStr[autoChMode] );
        preferences.begin("packetmonitor32", false);
        preferences.putUInt("autoChMode", autoChMode);
        preferences.end();
      }

      lastButtonTime = currentTime;
      if (needDraw) draw();
    }

    // maintain buffer and save to SD if necessary
    if (useSD) sdBuffer.save(&SD);
    // draw Display
    if ( currentTime - lastDrawTime > DRAW_DELAY ) {
      lastDrawTime = currentTime;
      // Serial.printf("\nFree RAM %u %u\n",
      // heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT),
      // heap_caps_get_minimum_free_size(MALLOC_CAP_32BIT));
      sampleSignal();
      draw();
    }
    // Serial input
    if (Serial.available()) {
      ch = Serial.readString().toInt();
      if (ch < 1 || ch > 14) ch = 1;
      setChannel(ch);
    }
  }
  vTaskDelete(NULL);
}


#ifdef ARDUINO_M5STACK_FIRE
void blinky( void * p )
{
  while(1) {
    if ((eapol== 0) && (deauths == 0)) {
      for (int pixelNumber = 0; pixelNumber < M5STACK_FIRE_NEO_NUM_LEDS ; pixelNumber++){
        leds[pixelNumber].setRGB(  0, 0, 0);
        if (led_status==pixelNumber)
         leds[pixelNumber].setRGB(  0, 0, bright_leds);
      }
      led_status++;
      if (led_status>M5STACK_FIRE_NEO_NUM_LEDS)
        led_status=0;
      FastLED.show();
    }
    int led_delay =1000;
    if (ledPacketCounter == 0) led_delay = 2000;
    if (ledPacketCounter > 10) led_delay = 1000;
    if (ledPacketCounter > 100) led_delay = 500;
    if (ledPacketCounter > 400) led_delay = 300;
    if (ledPacketCounter > 1000) led_delay = 150;

    vTaskDelay(led_delay / portTICK_RATE_MS);
  }
}
#endif
