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
  #define SDU_APP_NAME "WiFi Fox" // title for SD-Updater UI
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
#include "CaptureQueue.h"
#include <esp_timer.h>
#include <esp_task_wdt.h>
#include <nvs_flash.h>
#include <esp_netif.h>
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
#define MAX_SSIDs 128 // bounded BSSID/SSID cache

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
static bool UIReady = false;

uint32_t lastDrawTime = 0;
uint32_t lastButtonTime = millis();
uint32_t lastAutoSwitchChTime = 0;

uint8_t autoChMode = 0 ; // 0 No auto -  1 Switch channels automatically   - Smart Switch
const char* authChmodeStr[3] = {"[C]hannel Fixed", "[A]utomatic switching", "[S]mart switching" };
uint32_t deauths = 0; // deauth frames per second
uint32_t total_deauths = 0; // deauth total frames

uint32_t eapol = 0;         // eapol frames per second
uint32_t total_eapol = 0;   // eapol total frames
uint32_t eapol_messages[4] = {0, 0, 0, 0};
uint32_t complete_handshakes = 0;
uint32_t pmkids_observed = 0;
uint32_t sae_commits = 0;
uint32_t sae_confirms = 0;
uint32_t sae_legacy_groups = 0;
uint32_t wpa3_aps = 0;
uint32_t transition_aps = 0;
uint32_t resilience_findings = 0;
uint32_t lastHandshakeEvent = 0;
uint32_t lastPmkidEvent = 0;
uint32_t lastDeauthEvent = 0;

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
 * Data structure for beacon information
 */
struct ssid_info
{
  uint8_t mac[6];
  uint8_t ssid[33];
  uint8_t ssid_len;
  bool ssid_eapol, used, rsnCounted, beaconSaved;
  uint32_t lastBeacon;
  Buffer::Context capture;
};


/*
 * Global variables for storing beacons and clients
 */
ssid_info ssid_known[MAX_SSIDs];
uint32_t ssid_count = 0;  //
uint32_t ssid_eapol_count= 0;       // eapol frames per second

static HandshakeTracker handshakeTracker;
static CaptureQueue captureQueue;
static portMUX_TYPE rxStatsMux = portMUX_INITIALIZER_UNLOCKED;
static uint32_t rxPackets = 0;
static int32_t rxRssi = 0;
static std::atomic<uint32_t> queueDrops{0};
static uint32_t rejectedFrames = 0;
static uint32_t lastEapolActivity = 0;
static bool eapolActivity = false;
static uint32_t lastDiscoveryEvent = 0;
static bool discoveryActivity = false;
static bool wifiReady = false;
static void initSprites();
static void initializeCapture();
void coreTask(void* param);
bool setupSD();
static uint8_t allowedFirst = 1, allowedLast = 11;

// Called in the driver task, never an ISR. No SD, display, serial, allocation,
// AP searches or blocking queue operations are permitted here.
void wifi_promiscuous(void* buffer, wifi_promiscuous_pkt_type_t type);

static bool wifiCheck(esp_err_t error, const char* operation) {
  if (error == ESP_OK) return true;
  Serial.printf("WiFi %s: %s\n", operation, esp_err_to_name(error));
  return false;
}

bool setupWiFiPromisc()
{
  // Do not erase NVS on initialization errors: preserve user settings.
  if (!wifiCheck(nvs_flash_init(), "NVS")) return false;
  if (!wifiCheck(esp_netif_init(), "netif")) return false;
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  cfg.wifi_task_core_id = 0; // Keep driver work away from UI/SD on dual-core ESP32.
  if (!wifiCheck(esp_wifi_init(&cfg), "init") ||
      !wifiCheck(esp_wifi_set_storage(WIFI_STORAGE_RAM), "storage") ||
      !wifiCheck(esp_wifi_set_mode(WIFI_MODE_NULL), "mode") ||
      !wifiCheck(esp_wifi_start(), "start")) return false;
  wifi_country_t country{};
  if (esp_wifi_get_country(&country) == ESP_OK && country.nchan) {
    allowedFirst = country.schan;
    allowedLast = min(uint8_t(MAX_CH), uint8_t(country.schan + country.nchan - 1));
  }
  if (ch < allowedFirst || ch > allowedLast) ch = allowedFirst;
  wifi_promiscuous_filter_t filter{};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  return wifiCheck(esp_wifi_set_promiscuous_filter(&filter), "filter") &&
         wifiCheck(esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE), "channel") &&
         wifiCheck(esp_wifi_set_promiscuous_rx_cb(wifi_promiscuous), "callback") &&
         wifiCheck(esp_wifi_set_promiscuous(true), "promiscuous");
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
      // SD-Updater 1.2.x uses an explicit configuration object. Supplying the
      // filesystem and card-select pin keeps the updater portable across the
      // Core2 and older M5Stack boards.
      SDUCfg.setAppName(SDU_APP_NAME);
      SDUCfg.setFS(&SD);
      SDUCfg.setCSPin(TFCARD_CS_PIN);
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
  if (autoChMode > 2) autoChMode = 0;
  preferences.end();

  #ifdef ARDUINO_M5STACK_Core2
    // specific M5Core2 tweaks go here
  #else // M5Classic / M5Fire turn buzzer off
    M5.Speaker.write(0);
  #endif

  // Initialize UI and SD synchronously: no concurrent access to TFT/SD SPI.
  initSprites();
  initializeCapture();
  if (xTaskCreatePinnedToCore(coreTask, "capture-ui-sd", 8192, nullptr, 2, nullptr, RUNNING_CORE) != pdPASS) {
    esp_wifi_set_promiscuous(false);
    sdBuffer.close(&SD);
    useSD = false;
    Serial.println("Task creation failed; capture stopped");
  }

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

static void initSprites()
{
  const bool headerOk = initTextSprite(header, Dashboard::header);
  const bool footerOk = initTextSprite(footer, Dashboard::footer);
  const bool statsOk = initTextSprite(stats, Dashboard::stats);
  signalGraph.setColorDepth(8);
  const bool graphOk = signalGraph.createSprite(Dashboard::graph.w, Dashboard::graph.h) != nullptr;
  if (graphOk) signalGraph.fillSprite(TFT_BLACK);
  if (!headerOk || !footerOk || !statsOk || !graphOk) log_e("Dashboard sprite allocation failed");
  UIReady = headerOk && footerOk && statsOk && graphOk;
}

static void initializeCapture()
{
  tft.clear();
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setFont(&fonts::FreeMono12pt7b);
  tft.drawString("WiFi Fox", 8, 28);
  tft.setFont(&fonts::Font2);
  tft.drawString("Passive packet monitor", 8, 56);
  tft.setSwapBytes(true);
  renderLargeFox(tft, foxFrameFor(millis(), 1, 0, 0, 0), 176, 86);
  if (!UIReady) Serial.println("UI unavailable; serial monitoring remains active");
  vTaskDelay(pdMS_TO_TICKS(700));
  tft.clear();
  tft.drawString("Checking SD...", 8, 74);
  if (!sdBuffer.init()) {
    Serial.println("Error, not enough memory for buffer");
    useSD = false;
  }
  if (setupSD()) {
    if (!sdBuffer.open(&SD)) { Serial.println("SD ERROR, Can't create file"); useSD = false; }
  } else Serial.println("SD Setup failed");
  tft.drawString("Setting up WiFi...", 8, 44);
  wifiReady = setupWiFiPromisc();
  lastAutoSwitchChTime = millis();
}



// ===== functions ===================================================
void setChannel(int newChannel)
{
  if (!wifiReady) return;
  if (newChannel > allowedLast || newChannel < allowedFirst) newChannel = allowedFirst;
  if (!wifiCheck(esp_wifi_set_channel(newChannel, WIFI_SECOND_CHAN_NONE), "change channel")) return;
  ch = newChannel;
  lastAutoSwitchChTime = millis();
  eapolActivity = false; discoveryActivity = false;
  if (autoChMode == 0) {
    preferences.begin("packetmonitor32", false);
    preferences.putUInt("channel", ch);
    preferences.end();
  }
}

void autoSwitchChannel(uint32_t currentTime)
{
  // Hold for a bounded five seconds after EAPOL, rather than hopping mid-exchange.
  if (eapolActivity && uint32_t(currentTime - lastEapolActivity) < 5000 &&
      uint32_t(currentTime - lastAutoSwitchChTime) < AUTO_CHANNEL_INTERVAL + 5000) return;
  setChannel(ch + 1);
}

void smartSwitchChannel(uint32_t currentTime)
{
  // Smart mode additionally gives newly discovered SSIDs a bounded dwell.
  // Repeated beacons and deauth storms do not refresh this discovery timer.
  if (discoveryActivity && uint32_t(currentTime - lastDiscoveryEvent) < 5000 &&
      uint32_t(currentTime - lastAutoSwitchChTime) < AUTO_CHANNEL_INTERVAL + 5000) return;
  autoSwitchChannel(currentTime);
}

bool setupSD()
{
  if( SDSetupDone ) return true;
  M5.sd_end();
  int attempts = 20;
  do {
    SDSetupDone = M5.sd_begin(); // SD.begin( TFCARD_CS_PIN );
    if (!SDSetupDone) delay(50);
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

void wifi_promiscuous(void* buffer, wifi_promiscuous_pkt_type_t type)
{
  if (!buffer || (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA)) return;
  const auto* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buffer);
  // ESP-IDF ESP32 sig_len includes the four FCS octets for both frame types.
  // Reject receive errors, oversized MPDUs and truncation; never write partial frames.
  if (pkt->rx_ctrl.rx_state || pkt->rx_ctrl.sig_len < 28 || pkt->rx_ctrl.sig_len > SNAP_LEN + 4) return;
  const size_t length = pkt->rx_ctrl.sig_len - 4;
  const uint8_t* f = pkt->payload;
  if (f[0] & 3) return;
  portENTER_CRITICAL(&rxStatsMux);
  ++rxPackets; rxRssi += pkt->rx_ctrl.rssi;
  portEXIT_CRITICAL(&rxStatsMux);
  const bool priority = (type == WIFI_PKT_DATA && isEapolData(f, length)) ||
                        (type == WIFI_PKT_MGMT && (f[0] & 0x0c) == 0 && (f[0] >> 4) <= 3);
  if (!priority) {
    if (type != WIFI_PKT_MGMT) return;
    switch (f[0] >> 4) {
      case 0: case 1: case 2: case 3: case 5: case 8: case 10: case 11: case 12: break;
      default: return;
    }
  }
  if (!captureQueue.push(f, length, uint64_t(esp_timer_get_time()), pkt->rx_ctrl.rssi, pkt->rx_ctrl.channel, priority))
    queueDrops.fetch_add(1, std::memory_order_relaxed);
}

// A bounded, open-addressed BSSID cache. No heap allocation or full 1792-AP scan.
static ssid_info* networkFor(const uint8_t* ap) {
  uint32_t hash = 2166136261u;
  for (unsigned i = 0; i < 6; ++i) hash = (hash ^ ap[i]) * 16777619u;
  const size_t start = hash % MAX_SSIDs;
  for (size_t i = 0; i < MAX_SSIDs; ++i) {
    ssid_info& entry = ssid_known[(start + i) % MAX_SSIDs];
    if (entry.used && !memcmp(entry.mac, ap, 6)) return &entry;
    if (!entry.used) {
      entry = {}; entry.used = true; memcpy(entry.mac, ap, 6); ++ssid_count;
      return &entry;
    }
  }
  // Full cache: replace the hashed slot. Cumulative AP counters can include revisits.
  ssid_info& entry = ssid_known[start];
  entry = {}; entry.used = true; memcpy(entry.mac, ap, 6);
  return &entry;
}

static void storePacket(const CaptureQueue::Packet& p, ssid_info& network) {
  if (useSD) sdBuffer.addPacket(&SD, p.bytes, p.length, p.timestamp, network.mac, network.ssid, network.ssid_len, network.capture);
}

static void processPacket(const CaptureQueue::Packet& p) {
  const uint8_t* f = p.bytes;
  const uint32_t now = uint32_t(p.timestamp / 1000);
  if ((f[0] & 0x0c) == 8) {
    EapolKeyFrame key{};
    uint8_t ap[6], station[6];
    if (!parseEapolKeyFrame(f, p.length, &key) || !getInfrastructurePeers(f, p.length, ap, station)) {
      ++rejectedFrames; return;
    }
    ++eapol; ++eapol_messages[key.message - 1];
    pmkids_observed += key.pmkidCount;
    if (key.pmkidCount) lastPmkidEvent = now;
    if (handshakeTracker.observe(ap, station, key, now)) { ++complete_handshakes; lastHandshakeEvent = now; }
    if (p.channel == ch) { lastEapolActivity = now; eapolActivity = true; }
    ssid_info* network = networkFor(ap);
    if (!network->ssid_eapol) { network->ssid_eapol = true; ++ssid_eapol_count; }
    storePacket(p, *network);
    return;
  }
  if (f[0] == 0xa0 || f[0] == 0xc0) {
    if (p.length >= 26) { ++deauths; lastDeauthEvent = now; }
    return;
  }
  const SaeAuthentication sae = parseSaeAuthentication(f, p.length);
  if (sae.sequence) {
    if (sae.sequence == 1) { ++sae_commits; if (sae.group < 19) ++sae_legacy_groups; }
    else ++sae_confirms;
    return;
  }
  ManagementInfo info{};
  if (!parseManagementFrame(f, p.length, &info) || (f[16] & 1)) { ++rejectedFrames; return; }
  ssid_info* network = networkFor(f + 16);
  bool nameChanged = false;
  if (info.hasSsid && info.ssidLength &&
      (info.ssidLength != network->ssid_len || memcmp(info.ssid, network->ssid, info.ssidLength))) {
    memcpy(network->ssid, info.ssid, info.ssidLength); network->ssid_len = info.ssidLength;
    network->ssid[info.ssidLength] = 0; nameChanged = true;
  }
  if (nameChanged && p.channel == ch) { lastDiscoveryEvent = now; discoveryActivity = true; }
  // AP capabilities are learned from AP advertisements/responses, not a client's RSN.
  if ((f[0] == 0x80 || f[0] == 0x50) && info.hasRsn && !network->rsnCounted) {
    wpa3_aps += info.rsn.wpa3; transition_aps += info.rsn.transition;
    resilience_findings += info.rsn.wpa3 && !info.rsn.pmfRequired;
    network->rsnCounted = true;
  }
  if (info.hasRsn && info.rsn.pmkidCount) { pmkids_observed += info.rsn.pmkidCount; lastPmkidEvent = now; }
  // Escape non-printable SSID bytes only for display; retain the exact raw octets.
  for (unsigned i = 0; i < network->ssid_len; ++i) last_ssid[i] = network->ssid[i] >= 32 && network->ssid[i] < 127 ? char(network->ssid[i]) : '?';
  last_ssid[network->ssid_len] = 0;
  last_rssi = p.rssi;
  const bool advertisement = f[0] == 0x80 || f[0] == 0x50;
  if (!advertisement || !network->beaconSaved || nameChanged || uint32_t(now - network->lastBeacon) >= 15000) {
    storePacket(p, *network);
    network->beaconSaved = useSD; network->lastBeacon = now;
  }
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
  portENTER_CRITICAL(&rxStatsMux);
  const uint32_t packets = rxPackets;
  rssiSum = rxRssi; rxPackets = 0; rxRssi = 0;
  portEXIT_CRITICAL(&rxStatsMux);
  rssiValid = packets != 0;
  graph_RSSI = rssiValid ? rssiSum / int(packets) : 0;
  total_eapol += eapol;
  total_deauths += deauths;
  ledPacketCounter = packets;
  rssiSum = 0;
  eapol = 0;
  deauths = 0;

  if (!UIReady) return;
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
  if (!bright || !UIReady) return;
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

  uint32_t currentTime;
  // Respect an existing task-WDT policy; initialize only if the system has none.
  if (esp_task_wdt_status(NULL) == ESP_ERR_INVALID_STATE)
    wifiCheck(esp_task_wdt_init(8, true), "task WDT init");
  const bool watchTask = esp_task_wdt_status(NULL) == ESP_OK || esp_task_wdt_add(NULL) == ESP_OK;
  if (!watchTask) Serial.println("Task WDT subscription unavailable; idle WDT policy unchanged");
  Serial.printf("[C]urrent channel: %d\n", ch);

  tft.clear();

  lastButtonTime = millis();
  M5.update();

  while (true) {
    bool needDraw = false;
    // Bounded work per tick; UI and SD share one owner and the same SPI bus.
    for (unsigned budget = 0; budget < 8; ++budget) {
      const CaptureQueue::Packet* packet = captureQueue.front();
      if (!packet) break;
      processPacket(*packet);
      captureQueue.pop();
    }
    currentTime = millis();

    if (autoChMode==1) {
      if ( currentTime - lastAutoSwitchChTime > AUTO_CHANNEL_INTERVAL ) {
        autoSwitchChannel(currentTime);
      }
    }

    if (autoChMode==2) {
      if ( currentTime - lastAutoSwitchChTime > AUTO_CHANNEL_INTERVAL ) {
        smartSwitchChannel(currentTime);
      }
    }

    if ( currentTime - lastButtonTime > BUTTON_DEBOUNCE ) {
      M5.update();
      // buttons assignment :
      //  - Incognito mode => BtnA short press (toggles display)
      //  - SD Activation  => BtnA long press (enable/disable SD)
      //  - Brightness     => BtnB short press (cycle through values)
      //  - Channel hop    => BtnC long press for mode change, short press for manual change
      if( M5.BtnA.wasReleased() && !M5.BtnA.wasReleasefor(700) ) {
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
          // Keep the mounted SPI bus intact for the display.

        } else { // not in use, try to enable
          if ( setupSD() ) {
            for (auto& network : ssid_known) network.beaconSaved = false;
            if( !sdBuffer.open(&SD) ) {
              Serial.println(" SD ERROR, Can't create file, disabling SD");
              useSD = false;
              SDSetupDone = false;

            }
          }
        }
        needDraw = true;
      }

      if( M5.BtnB.wasReleased() && !M5.BtnB.wasReleasefor(700) ) {
        bright+=50;
        if (bright>251) bright=0;
        tft.setBrightness(bright);
      } else if (M5.BtnB.wasReleasefor(700)) {
        bright_leds+=100;
        if (bright_leds>251) bright_leds=0;
        Serial.println(bright_leds);
      }

      if( M5.BtnC.wasReleased() && !M5.BtnC.wasReleasefor(700) ) {
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
      Serial.printf("RX/s=%lu queue_drop=%lu rejected=%lu sd_packets=%lu sd_errors=%lu M1/2/3/4=%lu/%lu/%lu/%lu\n",
        (unsigned long)ledPacketCounter, (unsigned long)queueDrops.load(), (unsigned long)rejectedFrames,
        (unsigned long)sdBuffer.packets(), (unsigned long)sdBuffer.errors(),
        (unsigned long)eapol_messages[0], (unsigned long)eapol_messages[1],
        (unsigned long)eapol_messages[2], (unsigned long)eapol_messages[3]);
    }
    // Fixed-size nonblocking serial channel entry, terminated by newline.
    static char serialChannel[4]; static uint8_t serialUsed = 0;
    for (unsigned i = 0; i < 16 && Serial.available(); ++i) {
      const char c = char(Serial.read());
      if (c == '\n' || c == '\r') {
        serialChannel[serialUsed] = 0;
        if (serialUsed) setChannel(atoi(serialChannel));
        serialUsed = 0;
      } else if (c >= '0' && c <= '9' && serialUsed < sizeof(serialChannel) - 1) serialChannel[serialUsed++] = c;
      else serialUsed = 0;
    }
    if (watchTask) esp_task_wdt_reset();
    vTaskDelay(1); // Let idle tasks service the watchdog; never disable it.

  }
  vTaskDelete(NULL);
}
