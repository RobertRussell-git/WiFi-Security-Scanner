// ============================================================================
//  WiFi Security Scanner
//  Hardware: Heltec Wireless Paper V1.2 (ESP32-S3 + SX1262)
//  Author: Robert Russell
//
//  Features:
//    - Passive WiFi reconnaissance and telemetry
//    - Beacon analysis (ESSID, BSSID, RSSI, CH, ENC, AUTH)
//    - Risk classification and anomaly detection
//    - Historical network intelligence database
//    - Evil Twin / auth mismatch detection
//    - Background roaming scans with persistent tracking
//    - E-Ink UI + web report + CSV export
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
static const uint32_t DOUBLE_MS         = 350;
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
  MODE_MENU,      // main menu
  MODE_RESULTS,   // scan results summary list
  MODE_DETAIL,    // single network detail view
  MODE_WEBREPORT  // WiFi AP active, serving web report
};
Mode mode = MODE_MENU;

static int         menuSelected                    = 0;
static const int   MENU_ITEMS                      = 2;
static const char* menuLabels[MENU_ITEMS]          = { "WiFi Scan", "Web Report" };
static const char* menuDesc[MENU_ITEMS]            = { "Scan nearby networks", "View results in browser" };

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
  while (digitalRead(BTN) == LOW) delay(5);
  delay(DEBOUNCE_MS + 8);
  clearButtonQueue();
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

static int batteryPercent() {
  uint32_t mv = readAdcMilliVoltsStable();
  float    v  = (mv / 1000.0f) * 2.0f;
  if (v < 3.0f) return 0;
  if (v > 4.2f) return 100;
  return (int)((v - 3.0f) / 1.2f * 100.0f);
}

static void drawBattery() {
  int pct = batteryPercent();
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
static const int MENU_ROW_H     = 36;
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
static void drawMenuRow(int y, bool selected, const char* title, const char* subtitle) {
  if (selected) gfx.fillCircle(UI_MARGIN_X + 3, y + 4, 3, 1);
  u8g2.setFont(selected ? BOLD_FONT : MAIN_FONT);
  u8g2.setCursor(UI_MARGIN_X + 12, y + 9);
  u8g2.print(title);
  u8g2.setFont(u8g2_font_5x8_tf);
  u8g2.setCursor(UI_MARGIN_X + 12, y + 20);
  u8g2.print(subtitle);
}

static void drawMenuItems() {
  for (int i = 0; i < MENU_ITEMS; i++) {
    int y = MENU_TOP + (i * MENU_ROW_H);
    gfx.fillRect(UI_MARGIN_X, y, SCREEN_W - (UI_MARGIN_X * 2), MENU_ROW_H, 0);
    drawMenuRow(y, i == menuSelected, menuLabels[i], menuDesc[i]);
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
    drawFooter("1x=scan again  hold=menu");
    endFrame();
    return;
  }

  int shown = 0;
  for (int i = g_scrollOffset; i < g_resultCount && shown < SUMMARY_ROWS; i++, shown++) {
    drawSummaryRow(shown, i);
  }

  char footer[48];
  if (g_resultCount > SUMMARY_ROWS) snprintf(footer, sizeof(footer), "1x=cur  2x=page  3x=detail");
  else                              snprintf(footer, sizeof(footer), "1x=cursor  3x=detail  hold=menu ");
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
  html += F("body{font-family:monospace;background:#1a1a2e;color:#eee;padding:20px;max-width:800px;margin:0 auto}");
  html += F("h1{color:#e94560}p.sub{color:#aaa;font-size:13px;margin-top:0}");
  html += F("table{width:100%;border-collapse:collapse;margin-top:16px;font-size:13px}");
  html += F("th{background:#16213e;padding:8px;text-align:left;color:#aaa}");
  html += F("td{padding:7px 8px;border-bottom:1px solid #2a2a4a}");
  html += F(".badge{display:inline-block;padding:2px 7px;border-radius:4px;font-weight:bold;font-size:11px;color:#fff}");
  html += F("</style></head><body>");
  html += F("<h1>WiFi Security Report</h1>");

  if (!g_hasScanned) {
    html += F("<p>No scan data. Run a scan first.</p>");
  } else {
    char buf[64];
    snprintf(buf, sizeof(buf), "<p class='sub'>%d networks discovered</p>", g_seenCount);
    html += buf;
    html += F("<table><tr><th>ESSID</th><th>BSSID</th><th>PWR</th><th>CH</th>");
    html += F("<th>MB</th><th>ENC</th><th>CIPHER</th><th>AUTH</th><th>RISK</th></tr>");

    for (int i = 0; i < g_seenCount; i++) {
      const ScanResult& r = g_seen[i];
      char bf[18], mb[8];
      bssidFull(r.bssid, bf, sizeof(bf));
      mbStr(r.maxRate, r.rateIsN, mb, sizeof(mb));

      html += F("<tr><td>");
      html += (r.essid[0] ? r.essid : "<i>hidden</i>");
      html += F("</td><td>"); html += bf;
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
    html += F("</table>");
    html += F("<p style='margin-top:20px;color:#555;font-size:11px'>");
    html += F("LOW=WPA3 &nbsp; MEDIUM=WPA2 &nbsp; HIGH=WPA1 &nbsp; CRITICAL=OPEN/WEP</p>");

    bool anyAnomalies = false;
    for (int i = 0; i < g_seenCount; i++) {
      if (g_seen[i].anomalyFlags) { anyAnomalies = true; break; }
    }

    if (anyAnomalies) {
      html += F("<h2 style='color:#e94560;margin-top:30px'>&#9888; Anomalies Detected</h2>");
      html += F("<table><tr><th>ESSID</th><th>BSSID</th><th>Warning</th></tr>");

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
        html += F("</td><td>");
        html += bf;
        html += F("</td><td style='color:#e94560;font-weight:bold'>");
        html += warning;
        html += F("</td></tr>");
      }
      html += F("</table>");
    }
  }
  // Download CSV
  html += F("<p><a href='/export' style='color:#e94560'>Download CSV</a></p>");

  html += F("</body></html>");
  server.send(200, "text/html", html);
}

// ============================================================================
//  Export to CSV for documentation
// ============================================================================
static void handleCsvExport() {
  String csv;
  csv.reserve(4096);
  csv = F("ESSID,BSSID,PWR,CH,MB,ENC,CIPHER,AUTH,RISK,FIRST_SEEN_S,LAST_SEEN_S,SIGHTINGS,FLAGS\r\n");

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

  server.sendHeader("Content-Disposition", "attachment; filename=wifi_scan.csv");
  server.send(200, "text/csv", csv);
}

static void startWebReport() {
  setCpuFrequencyMhz(240);
  WiFi.mode(WIFI_AP);
  WiFi.softAP(AP_SSID, AP_PASS);
  delay(200);
  server.on("/", handleWebReport);
  server.on("/export", handleCsvExport);
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
      resetInputFrontend(); return;
    }
    if (btns.doubleClick) {
      if (menuSelected == 0) doScan(true);
      else                   startWebReport();
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
      g_cursorIndex++;
      if (g_cursorIndex >= g_resultCount) g_cursorIndex = 0;
      const int MAX_ROWS = 10;
      if (g_cursorIndex >= g_scrollOffset + MAX_ROWS) g_scrollOffset = g_cursorIndex;
      if (g_cursorIndex < g_scrollOffset)             g_scrollOffset = g_cursorIndex;
      updateSummaryCursor();
      resetInputFrontend(); return;
    }
    if (btns.doubleClick) {
      const int MAX_ROWS = 10;
      g_scrollOffset += MAX_ROWS;
      if (g_scrollOffset >= g_resultCount) g_scrollOffset = 0;
      g_cursorIndex = g_scrollOffset;
      drawSummary();
      resetInputFrontend(); return;
    }
    if (btns.tripleClick) {
      mode = MODE_DETAIL;
      drawDetail(g_cursorIndex);
      resetInputFrontend(); return;
    }
    if (btns.longClick) {
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
      mode = MODE_MENU; menuSelected = 0;
      drawMenu(); resetInputFrontend(); return;
    }
  }

  delay(5);
}
