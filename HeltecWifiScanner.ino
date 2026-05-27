// ============================================================================
//  WiFi Security Scanner
//
// - Wifi Scan
// - Probe Sniffer
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

#include <LittleFS.h>
#define FS LittleFS

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
  MODE_PROBE
};
Mode mode = MODE_MENU;

static int         menuSelected                    = 0;
static const int   MENU_ITEMS                      = 4;
static const char* menuLabels[MENU_ITEMS]          = { "WiFi Scan", "Probe Sniffer", "Scan Sessions", "Web Report" };

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

static void clearButtonQueue() {
  noInterrupts(); btnQHead = btnQTail = 0; interrupts();
}

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

struct ChannelStat {
  uint8_t  channel;
  uint32_t score;
};
static ChannelStat g_channelStats[13];
static uint8_t     g_channelOrder[13];

// ============================================================================
//  Session storage
//
//  Each scan session is saved as a CSV file in /sessions/
//  An index file /sessions/index.bin tracks metadata for all sessions.
//  Maximum 50 sessions, ring buffer - oldest overwritten when full.
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
static int          g_sessionCursor      = 0;

// Active session tracking
static bool     g_sessionActive          = false;
static uint16_t g_sessionSlot            = 0;
static uint8_t  g_scansSinceSessionSave  = 0;
static const uint8_t SESSION_SAVE_EVERY  = 5;

// ============================================================================
//  Scan result
//
//  Stores everything needed for the summary row and detail view.
//  MB (link rate) is inferred from auth mode, the ESP32 scan API
//  does not expose raw 802.11 information elements.
// ============================================================================
struct ScanResult {
  char    essid[33];  // network name
  uint8_t bssid[6];  // access point MAC
  int     rssi;       // signal strength (dBm)
  int     channel;    // WiFi channel
  int     maxRate;    // estimated link rate (Mbps)
  bool    rateIsN;    // true = append 'n' suffix (802.11n)
  uint8_t authMode;   // raw wifi_auth_mode_t
  uint8_t riskLevel;  // 0=LOW 1=MEDIUM 2=HIGH 3=CRITICAL
    // New features
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

// Historical database — persists across scans, keyed by BSSID
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
static const int UI_MARGIN_X    = 6;
static const int UI_HEADER_Y    = 12;
static const int UI_HEADER_LINE = 16;
static const int UI_FOOTER_LINE = SCREEN_H - 11;
static const int UI_FOOTER_TEXT = SCREEN_H - 2;
static const int MENU_TOP       = 28;
static const int MENU_ROW_H     = 18;
static const int SUMMARY_TOP    = 25;
static const int SUMMARY_ROW_H  = 9;
static const int SUMMARY_ROWS   = 10;

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
  for (int i = 0; i < MENU_ITEMS; i++) {
    int y = MENU_TOP + (i * MENU_ROW_H);
    gfx.fillRect(UI_MARGIN_X, y, SCREEN_W - (UI_MARGIN_X * 2), MENU_ROW_H, 0);
    drawMenuRow(y, i == menuSelected, menuLabels[i]);
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
  static int cursorMoves = 0;
  cursorMoves++;
  if (cursorMoves >= 5) {
    cursorMoves = 0;
    drawMenu();
    return;
  }
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
//  Runs in promiscuous mode — no connection to any network.
// ============================================================================
static void IRAM_ATTR probeCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;

  const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  const uint8_t* payload = pkt->payload;
  int8_t rssi = pkt->rx_ctrl.rssi;

  if (pkt->rx_ctrl.sig_len < 28) return;

  uint8_t subtype = (payload[0] >> 4) & 0x0F;
  uint8_t ftype   = (payload[0] >> 2) & 0x03;
  if (ftype != 0 || subtype != 4) return;

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

  // Count everything including <any>
  g_probeTotalSeen++;

  // Only store named probes
  if (!ssid[0]) return;

  // Find existing entry
  for (int i = 0; i < g_probeCount; i++) {
    if (memcmp(g_probes[i].mac, mac, 6) == 0 &&
        strcmp(g_probes[i].ssid, ssid) == 0) {
      g_probes[i].lastSeen = millis();
      g_probes[i].count++;
      if (rssi > g_probes[i].rssi) g_probes[i].rssi = rssi;
      return;
    }
  }

  // New entry — ring buffer overwrites oldest when full
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
  g_probes[slot].ssid[32] = '\0';
  g_probes[slot].rssi = rssi;
  g_probes[slot].firstSeen = millis();
  g_probes[slot].lastSeen = millis();
  g_probes[slot].count = 1;
  g_probes[slot].randomized = randomized;
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
  f.read((uint8_t*)&g_probeNext,  sizeof(g_probeNext));
  f.read((uint8_t*)&g_probeTotal, sizeof(g_probeTotal));
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
    f.print(","); f.print(p.ssid[0] ? p.ssid : "<any>");
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

static void startProbeSniffer() {
  g_probeCount = 0;
  g_probeTotalSeen = 0;
  memset(g_probes, 0, sizeof(g_probes));

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
  const int DY = 13;

  // WiFi sessions count
  char line[48];
  snprintf(line, sizeof(line), "WiFi:  %d / %d sessions", g_sessionIndex.count, MAX_SESSIONS);
  u8g2.setCursor(X, Y);
  u8g2.print(line);

  snprintf(line, sizeof(line), "Probe: %d / %d sessions", g_probeTotal, MAX_PROBE_SESSIONS);

  u8g2.setCursor(X, Y + DY);
  u8g2.print(line);

  // Flash usage
  size_t total = fsTotalBytesSafe();
  size_t used  = fsUsedBytesSafe();
  int pct = total > 0 ? (int)((used * 100UL) / total) : 0;
  snprintf(line, sizeof(line), "Flash: %d%% used", pct);
  u8g2.setCursor(X, Y + DY * 2);
  u8g2.print(line);

  // Last WiFi scan info
  if (g_sessionIndex.count > 0) {
    int lastSlot = (g_sessionIndex.next - 1 + MAX_SESSIONS) % MAX_SESSIONS;
    const SessionMeta& last = g_sessionIndex.sessions[lastSlot];
    snprintf(line, sizeof(line), "Last:  #%lu  %d APs", 
             (unsigned long)last.scanNumber, last.apCount);
    u8g2.setCursor(X, Y + DY * 3);
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

  // Count named probes
  int namedCount = 0;
  for (int i = 0; i < g_probeCount; i++) {
    if (g_probes[i].ssid[0]) namedCount++;
  }

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
  snprintf(footer, sizeof(footer), "%d named/%d seen ch%d hold=menu",
           g_probeCount, g_probeTotalSeen, curCh);
  drawFooter(footer);
  endFrame();
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

    html += F("<div class='tbl-wrap'>");
    html += F("<table><tr><th>ESSID</th><th>BSSID</th><th>PWR</th><th>CH</th>");
    html += F("<th>MB</th><th>ENC</th><th>CIPHER</th><th>AUTH</th><th>RISK</th></tr>");

    for (int i = 0; i < g_seenCount; i++) {
      const ScanResult& r = g_seen[i];
      char bf[18], mb[8];
      bssidFull(r.bssid, bf, sizeof(bf));
      mbStr(r.maxRate, r.rateIsN, mb, sizeof(mb));

      html += F("<tr><td>");
      html += (r.essid[0] ? r.essid : "<i>hidden</i>");
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
        html += (r.essid[0] ? r.essid : "<i>hidden</i>");
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

  // Probe requests section
  if (g_probeCount > 0) {
    html += F("<h2>Probe Requests</h2>");

    // Count unique devices
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

    // Summary stats
    char probeSummary[128];
    snprintf(probeSummary, sizeof(probeSummary),
      "<p class='sub'>%d unique devices &nbsp;|&nbsp; %d named probes &nbsp;|&nbsp; %lu total seen</p>",
      uniqueDevices, g_probeCount, (unsigned long)g_probeTotalSeen);
    html += probeSummary;

    html += F("<div class='tbl-wrap'>");
    html += F("<table>");
    html += F("<tr><th>#</th><th>MAC</th><th>Type</th><th>Networks</th><th>SSIDs</th></tr>");

    // Build sorted index — devices with most SSIDs first
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

      html += F("<tr><td>Client ");
      html += clientNum++;
      html += F("</td><td class='mac'>");
      html += bf;
      html += F("</td><td>");
      html += g_probes[i].randomized ? F("<span class='muted'>Rand</span>") : F("<span>Real</span>");
      html += F("</td><td>");
      html += ssidCount;
      if (isCorporate) html += F(" <span class='danger'>corp?</span>");
      html += F("</td><td>");

      // First SSID
      html += F("&rarr; ");
      html += g_probes[i].ssid;

      // Remaining SSIDs for this MAC
      for (int j = i + 1; j < g_probeCount; j++) {
        if (memcmp(g_probes[i].mac, g_probes[j].mac, 6) == 0) {
          html += F("<br>&rarr; ");
          html += g_probes[j].ssid;
        }
      }

      html += F("</td></tr>");
    }

    html += F("</table></div>");
    html += F("<p><a href='/probes'>View Saved Probe Sessions &rarr;</a></p>");
  }

  html += F("<div class='card'>");
  html += F("<h2>Scan Sessions</h2>");

  char sessionBuf[128];
  size_t total = fsTotalBytesSafe();
  size_t used  = fsUsedBytesSafe();
  int pct = total > 0 ? (int)((used * 100UL) / total) : 0;

  snprintf(sessionBuf, sizeof(sessionBuf),
    "<p class='muted'>%d sessions stored &nbsp;|&nbsp; %d%% flash used</p>",
    g_sessionIndex.count, pct);
  html += sessionBuf;

  if (g_sessionIndex.count > 0) {
    html += F("<p><a href='/sessions'>View All Sessions &rarr;</a></p>");
  } else {
    html += F("<p class='muted'>No sessions saved yet. Run a scan first.</p>");
  }
  html += F("</div>");

  html += F("<p class='footer'><a href='/export'>Download last scan CSV</a></p>");

  html += F("</body></html>");
  server.send(200, "text/html", html);
}

static void handleSessions() {
  String html;
  html.reserve(2048);
  html  = F("<!DOCTYPE html><html><head>");
  html += F("<meta name='viewport' content='width=device-width,initial-scale=1'>");
  html += F("<title>Scan Sessions</title><style>");
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
  html += F("<h1>Scan Sessions</h1>");
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
  if (filename.length() > 10 || !filename.startsWith("s") || !filename.endsWith(".csv")) {
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

  for (int i = 0; i < g_seenCount; i++) {
    const ScanResult& r = g_seen[i];
    char bf[18], mb[8];
    bssidFull(r.bssid, bf, sizeof(bf));
    mbStr(r.maxRate, r.rateIsN, mb, sizeof(mb));

    csv += (r.essid[0] ? r.essid : "(hidden)");
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
      csv += ","; csv += (p.ssid[0] ? p.ssid : "<any>");
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

static void handleProbeDownload() {
  if (!server.hasArg("f")) {
    server.send(400, "text/plain", "Missing file parameter");
    return;
  }
  String filename = server.arg("f");

  // Safety check
  if (filename.length() > 10 || !filename.startsWith("p") || !filename.endsWith(".csv")) {
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

static void startWebReport() {
  setCpuFrequencyMhz(240);
  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASS);
  delay(200);
  server.on("/", handleWebReport);
  server.on("/export", handleCsvExport);
  server.on("/sessions", handleSessions);
  server.on("/session", handleSessionDownload);
  server.on("/probes", handleProbes);
  server.on("/probe", handleProbeDownload); 
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
  drawMenu();
}

// ============================================================================
//  Storage helpers
// ============================================================================
static bool fsBegin() {
  return FS.begin(true);
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
  f.read((uint8_t*)&g_sessionIndex, sizeof(g_sessionIndex));
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
  for (int i = 0; i < g_seenCount; i++) {
    const ScanResult& r = g_seen[i];
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

    f.print(r.essid[0] ? r.essid : "(hidden)");
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
  // Fresh environment for new session
  memset(g_seen, 0, sizeof(g_seen));
  g_seenCount = 0;
  g_scansSinceSessionSave = 0;

  // Write initial file and save index
  writeSessionFile(g_sessionSlot);
  saveSessionIndex();
}

static void updateSession() {
  if (!g_sessionActive) return;

  // Update metadata
  uint16_t anomalyCount = 0;
  for (int i = 0; i < g_seenCount; i++) {
    if (g_seen[i].anomalyFlags) anomalyCount++;
  }
  SessionMeta& meta     = g_sessionIndex.sessions[g_sessionSlot];
  meta.apCount          = (uint16_t)g_seenCount;
  meta.anomalyCount     = anomalyCount;

  // Overwrite session file with latest g_seen[]
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

// ============================================================================
//  WiFi scan
//
//  Passive beacon scan using the ESP32 WiFi scan API.
//  Results sorted by risk descending, then RSSI descending.
//  Each result merged into the persistent g_seen[] historical database.
//
//  showUi=true  -> manual scan, shows scanning screen first
//  showUi=false -> background scan, silent
//
//  Anomaly detection runs after each scan:
//    - Duplicate SSID / Evil Twin: flags networks that differ from the
//      dominant auth mode among networks sharing the same ESSID
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

        // Update last known values
        g_seen[seenIdx].lastAuthMode = g_results[i].authMode;
        g_seen[seenIdx].lastChannel  = g_results[i].channel;

        // Keep strongest signal
        if (g_results[i].rssi > g_seen[seenIdx].rssi) {
          g_seen[seenIdx].rssi = g_results[i].rssi;
        }
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
    if (!FS.exists("/sessions")) FS.mkdir("/sessions");
    if (!FS.exists("/probes"))   FS.mkdir("/probes");
    loadSessionIndex();
    loadProbeIndex();
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
        g_sessionCursor = 0;
        mode = MODE_SESSIONS;
        drawSessions();
      } else if (menuSelected == 3) {
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
    static uint32_t lastProbeDrawMs = 0;
    static int lastDrawCount = -1;
    if (g_probeCount != lastDrawCount &&
        (uint32_t)(millis() - lastProbeDrawMs) > 5000) {
      lastProbeDrawMs = millis();
      lastDrawCount = g_probeCount;
      drawProbe();
    }
    if (btns.longClick) {
      stopProbeSniffer();
      mode = MODE_MENU; menuSelected = 0;
      drawMenu(); resetInputFrontend(); return;
    }
  }
  
  delay(5);
}
