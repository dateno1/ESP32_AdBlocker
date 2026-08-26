// AdBlocker specific functions
//
// dateno1 2026
// s60sc 2020, 2023, 2026

#include "appGlobals.h"

const size_t prvtkey_len = 0;
const size_t cacert_len = 0;
const char* prvtkey_pem = "";
const char* cacert_pem = "";
static size_t maxDomains; // for reserving ptrs memory
static size_t minMemory; // min free memory after vector populated
static const uint16_t maxLineLen = 1024; // max length of line processed in downloaded blocklists
static uint8_t maxDomLen; // max length of domain name in blocklist
static char fileURL[IN_FILE_NAME_LEN] = {0};
static char fmtStorageSize[FILE_NAME_LEN];
static int timeoutVal = 10000; // 10 secs on download stream data being available
static size_t blocklistSize = 0;
static uint8_t domainLine[maxLineLen];
static uint32_t blockCnt = 0, allowCnt = 0, itemsLoaded = 0, duplicates = 0;
static bool stopLoad = false;
static bool downloading = false;
static bool adBlockOn = true; // whether app is set to block or not by user
size_t storageSize;
uint32_t* ptrs; // ordered pointers to domain names
char* storage; // linear domain name storage
static uint32_t lastLoadMs = 0; // millis() of last successful blocklist download

//static SemaphoreHandle_t blMutex = nullptr;  // create in appSetup()

#include <esp_crt_bundle.h>          // Arduino core certificate bundle
extern const uint8_t x509_certificate_bundle_start[] __asm__("_binary_x509_crt_bundle_start");
extern const uint8_t x509_certificate_bundle_end[]   __asm__("_binary_x509_crt_bundle_end");
/* ================= TLS trust sources =================
 * Strategy: layered verification, tried best-first.
 *   1) /data/CA.pem  – private/internal roots (loaded into PSRAM when large)
 *   2) Arduino core bundle – public Mozilla roots
 * First source whose TCP+TLS handshake succeeds performs the download.
 * NOTE: mbedTLS accepts either a PEM chain OR the binary bundle per
 * connection - hence sequential attempts rather than one merged store. */

/* Custom CA cache - kept for process lifetime, lives in PSRAM when
 * possible so even a multi-KB CA.pem never squeezes internal SRAM. */
static char*  g_caBuf = nullptr;  // NUL-terminated PEM text
static size_t g_caLen = 0;
static bool   g_caTried = false;  // load-once flag

//It for prevent crash with 5k PING_STACK_SIZE
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
///////////////////////////////////////////////////
static uint32_t binarySearch(const char* searchStr, bool doUpdate) {
  // binary split search
  // for an update, return 0 if found (duplicate) else return ptr
  // for a check, return ptr if found else return 0
  int first = 0, ptr = 0;
  int last = itemsLoaded - 1;
  while (first <= last) {
    ptr = (first + last) / 2;
    int diff = strcmp(storage + ptrs[ptr], searchStr);
    if (diff < 0) first = ptr + 1;
    else if (diff > 0) last = ptr - 1;
    else return doUpdate ? 0 : ptr; // found (diff = 0)
  }
  // not found
  return doUpdate ? ptr : 0;
}

static void addDomain(uint32_t ptr, const char* domainStr, size_t domLen) {
  // central capacity guard - protects storage and ptrs[] bounds for ALL callers
  if (blocklistSize + domLen + 1 > storageSize || itemsLoaded >= maxDomains) {
    LOG_VRB("Ignored '%s', blocklist storage/limit reached", domainStr);
    return;
  }
  // check what is already at location
  int diff = strcmp(storage + ptrs[ptr], domainStr);
  // append domain name to storage
  memcpy(storage + blocklistSize, domainStr, domLen);
  // make space for new domain pointer at identified location by shifting following locations
  if (diff < 0) ptr++; // to insert after
  memmove(&ptrs[ptr + 1], &ptrs[ptr], (itemsLoaded - ptr) * sizeof(uint32_t));
  // insert new domain pointer
  ptrs[ptr] = blocklistSize; // points to latest domain name in 'storage'
  blocklistSize += domLen + 1; // add terminator
  itemsLoaded++;
}

static size_t formatDomain(char* domName) {
  // format input domain name by removing whitespace, www. prefix and converting to lowercase
  trim(domName);
  toCase(domName);
  size_t domLen = strlen(domName);
  int wwwOffset = (strncmp(domName, "www.", 4) == 0) ? 4 : 0;  // remove any leading "www."
  memmove(domName, domName + wwwOffset,  domLen + 1 - wwwOffset);
  return domLen - wwwOffset;
}

static bool updateCustomFile(char* domainName, bool doDelete) {
  // user supplied domain to add to or delete from blocklist
  File file = STORAGE.open(CUSTOM_FILE_PATH, FILE_APPEND);
  if (file) {
    if (doDelete) file.print("#"); // mark as deleted
    file.println(domainName);
    file.close();
    return true;
  } else LOG_ERR("Failed to open %s", CUSTOM_FILE_PATH);
  return false;
}

DnsResult checkBlocklist(const char* domainName, IPAddress& retIP) {
  // called from externalDNS.cpp
  // normalise the query, test blocklist, return response type + answer IP
  // normalize: strip single trailing root dot, force lowercase
  // (DNS names are case-insensitive; blocklist storage is lowercase)

  // use IN_FILE_NAME_LEN (128) so names up to maxDomLen (100) + dot fit
  char normName[IN_FILE_NAME_LEN];
  size_t n = strlen(domainName);
  if (n == 0 || n >= IN_FILE_NAME_LEN) {
    retIP = IPAddress(0, 0, 0, 0);
    return DNS_SERVFAIL;
  }

  if (domainName[n - 1] == '.') n--; // tolerate "example.com."
  for (size_t i = 0; i < n; i++)
    normName[i] = (char)tolower((unsigned char)domainName[i]);
  normName[n] = 0;

  // RFC 6761: localhost is always loopback, never blocklisted
  if (!strcmp(normName, "localhost")) {
    retIP = IPAddress(127, 0, 0, 1);
    ++allowCnt;
    LOG_VRB("%s -> loopback (fixed)", normName);
    return DNS_RESOLVED;
  }

  bool blocked = false;
  if (adBlockOn) {
    static char blockedDomain[IN_FILE_NAME_LEN] = {0};
    uint64_t usElapsed = micros();
    // check if received domain name same as previous blocked domain to skip search
    blocked = !strcmp(normName, blockedDomain) ? true : (bool)binarySearch(normName, false);
    if (blocked) strcpy(blockedDomain, normName);
    blocked ? ++blockCnt : ++allowCnt;
    uint64_t checkTime = micros() - usElapsed;
    LOG_VRB("Check %s %s in %lluus", normName, (blocked) ? "*Blocked*" : "Allowed", checkTime);
  }
  if (blocked) {
    retIP = IPAddress(0, 0, 0, 0); // sinkhole only for blocklist hits
    return DNS_BLOCKED;
  }
  // not in blocklist -> query forwarder, distinguishing NXDOMAIN from SERVFAIL
  return resolveDomainStatus(normName, retIP);
}

static void checkDomain(const char* inName, bool doUpdate, bool doDelete) {
  // check if user supplied domain name is present or update user supplied name
  char domName[IN_FILE_NAME_LEN];
  //strcpy(domName, inName);
  strncpy(domName, inName, sizeof(domName) - 1);   // was strcpy - length-safe now
  domName[sizeof(domName) - 1] = 0;

  if (size_t domLen = formatDomain(domName); domLen > 0) {
    if (domLen >= maxDomLen) LOG_ALT("Domain name %s is too long to process", domName);
    else {
      uint32_t blPtr = binarySearch(domName, doUpdate);
      if (doUpdate) { // addition
        if (blPtr) {
          // not found, so insert domain if resolves at blPtr location
          if (resolveDomain(domName) != IPAddress(0, 0, 0, 0)) {
            // resolved
            addDomain(blPtr, domName, domLen);
            if (updateCustomFile(domName, false)) LOG_ALT("Domain name %s IS added to blocklist", domName);
          } else LOG_ALT("Domain name %s NOT added to blocklist as not resolved", domName);
        } else LOG_ALT("Domain name %s NOT added to blocklist as duplicate", domName);
      } else {
        // delete or just check
        if (doDelete) { // deletion
          if (blPtr) {
            // found, so delete
            *(storage + ptrs[blPtr]) = 0; // set domain name empty
            if (updateCustomFile(domName, true)) LOG_ALT("Domain name %s IS deleted", domName);
          } else LOG_ALT("Domain name %s NOT deleted as not in blocklist", domName);
        } else LOG_ALT("Domain name %s %s in blocklist", domName, blPtr ? "IS" : "NOT"); // check only
      }
    }
  } else LOG_ALT("No domain name entered");
}

static void extractBlocklist() {
  // extract domain names from downloaded blocklist file
  char* saveItem = NULL;
  char* tokenItem;
  char* domStr = (char*)domainLine;
  // for each line
  if (strncmp(domStr, "127.0.0.1", 9) == 0 || strncmp(domStr, "0.0.0.0", 7) == 0) {
    // HOSTS file format matched, extract domain name
    tokenItem = strtok_r(domStr, " \t", &saveItem); // skip over first token
    if (tokenItem != NULL) tokenItem = strtok_r(NULL, " \t", &saveItem); // domain in second token
  } else {
    if (strncmp(domStr, "||", 2) == 0) tokenItem = strtok_r(domStr, "|^", &saveItem); // Adblock format - domain in first token
    else tokenItem = NULL; // no match
  }
  if (tokenItem != NULL) {
    // write processed domain to storage
    size_t domLen = formatDomain(tokenItem);
    if (domLen && (domLen < maxDomLen)) {
      // never store loopback names from hosts file headers
      if (!strcasecmp(tokenItem, "localhost") ||
          !strcasecmp(tokenItem, "localhost.localdomain") ||
          !strcasecmp(tokenItem, "local")) return;
      uint32_t ptr = binarySearch(tokenItem, true);
      if (ptr) addDomain(ptr, tokenItem, domLen);
      else duplicates++;
    }
  }
}

static bool fetchBlockList(WiFiClient& wclient) {
  // GET + stream-parse the blocklist over an established connection
  HTTPClient https;
  size_t downloadSize = 0;
  char progStr[10];
  bool res = false;
  downloading = true;
  if (!https.begin(wclient, fileURL)) {
    LOG_ERR("Could not open %s", fileURL);
    downloading = false;
    return false;
  }
  LOG_INF("Downloading %s\n", fileURL);
  int httpCode = https.GET();
  if (httpCode > 0) {
    uint32_t loadTime = millis();
    if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_MOVED_PERMANENTLY) {
      int left = https.getSize();
      if (left > 0) LOG_INF("File size: %s", fmtSize(left));
      else LOG_WRN("File size unknown");
      LOG_INF("%s memory available for download", fmtStorageSize);
      WiFiClient* stream = https.getStreamPtr();
      uint32_t lastRead = millis();
      size_t lineCnt = 0;
      while (https.connected() && (left > 0 || left == -1)) {
        if (stopLoad) break;
        if (stream->available()) {
          size_t lineSize = stream->readBytesUntil('\n', domainLine, maxLineLen - 1);
          domainLine[lineSize] = 0;
          lineSize++;
          downloadSize += lineSize;
          if (left > 0) left -= lineSize;
          if (blocklistSize + maxDomLen + 2 > storageSize || itemsLoaded >= maxDomains) {
            LOG_ALT("Blocklist truncated at %lu domains, %s of %s used",
                    itemsLoaded, fmtSize(blocklistSize), fmtStorageSize);
            break;
          }
          extractBlocklist();
          if (++lineCnt % 1000 == 0 && left > 0) {
            float loadProg = (float)(downloadSize * 100.0 / (downloadSize + left));
            LOG_SEND("%0.1f%%\n", loadProg);
            sprintf(progStr, "%0.1f%%", loadProg);
            updateConfigVect("loadProg", progStr);
			// Warning or PSRAM Space
			if (blocklistSize > storageSize - storageSize / 5) {
		        LOG_WRN("Blocklist past 80%% of storage - consider larger maxDomains or shorter list");
			}
          }
          lastRead = millis();
        } else if (millis() - lastRead > timeoutVal) {
          if (left > 0) LOG_WRN("Timeout on download, %s unread", fmtSize(left));
          break;
        }
      }
      ptrs[itemsLoaded] = blocklistSize;
      LOG_INF("Download complete, processed %s in %lu secs", fmtSize(downloadSize), (millis() - loadTime) / 1000);
      LOG_ALT("Loaded %lu blocked domains excluding %lu duplicates, using %s of %s", itemsLoaded - 2, duplicates, fmtSize(blocklistSize), fmtStorageSize);
      res = true;
    } else LOG_WRN("Unexpected result code %u %s", httpCode, https.errorToString(httpCode).c_str());
  } else LOG_ERR("Connection failed with error: %s", https.errorToString(httpCode).c_str());
  https.end();
  downloading = false;
  return res;
}

static bool loadCustomCAs() {
  if (g_caTried) return g_caLen > 0;   // cached verdict
  g_caTried = true;
  File f = STORAGE.open(CA_PEM_PATH, FILE_READ);
  if (!f) { LOG_INF("No %s - core bundle only", CA_PEM_PATH); return false; }
  size_t sz = f.size();
  if (sz == 0 || sz > CA_PEM_MAX) {    // reject empty / absurd sizes
    LOG_WRN("%s skipped (size %u)", CA_PEM_PATH, (unsigned)sz);
    f.close(); return false;
  }
  /* PSRAM first; SRAM only as tiny-file fallback */
  char* buf = (char*)ps_malloc(sz + 1);
  bool inPsram = true;
  if (!buf) { buf = (char*)malloc(sz + 1); inPsram = false; }
  if (!buf) { f.close(); return false; }
  size_t rd = f.readBytes(buf, sz);
  f.close();
  buf[rd] = 0;                          // setCACert expects C string
  g_caBuf = buf; g_caLen = rd;
  LOG_INF("CA store ready: %u bytes in %s", (unsigned)rd, inPsram ? "PSRAM" : "SRAM");
  return true;
}

static bool fetchBlockListSecure(const char* dlHost, uint16_t dlPort) {
  // Certificate date checks require a valid system clock (notBefore/notAfter),
  // so refuse politely before NTP has ever answered.
  if (time(nullptr) < 1704067200UL) { // < 2024-01-01 => unsynced
    LOG_WRN("Clock not synced yet - skipping TLS load until time sync");
    return false;
  }

  loadCustomCAs();                     // fills g_caBuf/g_caLen once

  // Phase 1: plain TCP probe - separates "network problem" from "TLS problem"
  {
    NetworkClient tcp;
    uint32_t t0 = millis();
    bool ok = tcp.connect(dlHost, dlPort);
    LOG_INF("TCP %s:%u -> %s (%lu ms)", dlHost, dlPort, ok ? "OPEN" : "FAIL", millis() - t0);
    tcp.stop();
    if (!ok) return false;             // no point trying any trust source
  }

  // Phase 2: trust sources in priority order
  bool res = false;
  for (int attempt = 0; attempt < 2 && !res; attempt++) {
    NetworkClientSecure wclient;
    const char* srcName;
    if (attempt == 0 && g_caLen) {                 // private roots win ties
      wclient.setCACert(g_caBuf);                  // buffer stays valid: caller scope
      srcName = "/data/CA.pem";
    } else if (attempt == 1 || !g_caLen) {
      if (attempt == 0) continue;                  // nothing custom configured
      wclient.setCACertBundle(                     // public roots embedded in flash
          x509_certificate_bundle_start,
          (size_t)(x509_certificate_bundle_end - x509_certificate_bundle_start));
      srcName = "Arduino core bundle";
    } else continue;

    LOG_INF("TLS trust source: %s", srcName);
    uint32_t t0 = millis();
    if (wclient.connect(dlHost, dlPort)) {         // TCP + handshake
      LOG_INF("TLS handshake OK with %s in %lu ms", srcName, millis() - t0);
      res = fetchBlockList(wclient);               // buffer lifetime covers fetch
    } else {
      char errBuf[160] = {0};
      wclient.lastError(errBuf, sizeof(errBuf));   // mbedTLS verdict (may be generic)
      LOG_WRN("TLS handshake FAILED with %s after %lu ms: %s",
              srcName, millis() - t0, errBuf);
    }
    wclient.stop();
  }

  if (!res) LOG_ERR("All TLS trust sources failed for %s:%u", dlHost, dlPort);
  return res;
}

static bool downloadBlockList() {
  bool res = false;
  bool isSecure = strncmp(fileURL, "https://", 8) == 0;

  // extract host (+ optional :port) from fileURL
  char dlHost[128] = {0};
  uint16_t dlPort = isSecure ? HTTPS_PORT : 80;
  const char* hp = strstr(fileURL, "://");
  if (!hp) hp = fileURL; else hp += 3;
  const char* sp = strchr(hp, '/');
  size_t hl = sp ? (size_t)(sp - hp) : strlen(hp);
  if (hl >= sizeof(dlHost)) hl = sizeof(dlHost) - 1;
  memcpy(dlHost, hp, hl);
  dlHost[hl] = 0;
  char* colon = strchr(dlHost, ':');
  if (colon) { *colon = 0; dlPort = (uint16_t)atoi(colon + 1); }

  if (isSecure) {
    // ── rule 1: https → CA verification (/data/CA.pem → core bundle) ──
    res = fetchBlockListSecure(dlHost, dlPort);
  } else {
    // ── rule 2: http → no certificate handling (insecure by definition) ──
    NetworkClient wclient;
    if (wclient.connect(dlHost, dlPort)) {
      res = fetchBlockList(wclient);
    } else LOG_ERR("Could not connect to %s:%u", dlHost, dlPort);
    wclient.stop();
  }

  if (stopLoad) {
    LOG_ALT("Blocklist load stopped by user request");
    updateConfigVect("loadProg", "Stopped");
    res = true;
  } else if (res) updateConfigVect("loadProg", "Complete");
  else updateConfigVect("loadProg", "Failed");
  return res;
}

static void loadCustom() {
  // process custom blocklist file entries
  File file;
  static uint32_t customAdded = 0, customDeleted = 0;
  if (!STORAGE.exists(CUSTOM_FILE_PATH)) {
    // create file on first call
    file = STORAGE.open(CUSTOM_FILE_PATH, FILE_WRITE);
    if (file) file.close();
    else LOG_WRN("Failed to create file %s", CUSTOM_FILE_PATH);
  } else {
    // read in entries
    file = STORAGE.open(CUSTOM_FILE_PATH, FILE_READ);
    char domName[IN_FILE_NAME_LEN];
    while (file.available()) {
      bool doAdd = true;
      String customLineStr = file.readStringUntil('\n');
      customLineStr.trim();
      if (customLineStr.length()) {
        if (customLineStr.charAt(0) == '#') {
          doAdd = false;  // deletion
          strcpy(domName, customLineStr.substring(1).c_str());
        } else strcpy(domName, customLineStr.c_str()); // addition
        uint32_t blPtr = binarySearch(domName, doAdd);
        if (blPtr) {
          if (doAdd) {
            addDomain(blPtr, domName, strlen(domName));
            customAdded++;
          } else {
            *(storage + ptrs[blPtr]) = 0; // set domain name empty
            customDeleted++;
          }
        } else LOG_WRN("Ignored custom %s of %s", doAdd ? "addition" : "deletion", domName);
      }
    }
    file.close();
  }
  LOG_ALT("Loaded %lu custom blocked domains, unblocked %lu domains", customAdded, customDeleted);
}

/* Reset storage to the primed ("!" + "#") state so a retry never inherits
 * partial data from an interrupted download (dedupe counts, truncation). */
static void resetBlocklistStorage() {
  memset(ptrs, 0, (maxDomains + 2) * sizeof(uint32_t));
  memset(storage, 0, maxDomLen + 8);
  memcpy(storage, "!", 1);      // sentinel: guarantees ptrs[0] != real entry
  blocklistSize = 2;
  itemsLoaded = 1;
  addDomain(0, "#", 1);         // second sentinel, also sorts before domains
}

/* Block until WiFi is up AND system time is sane (post-NTP).
 * Certificate validation is meaningless before the clock is set,
 * so downloads must never start earlier than this. */
static bool waitForNetworkAndTime(uint32_t timeoutMs) {
  uint32_t waited = 0;
  while (waited < timeoutMs) {
    if (netIsConnected() && time(nullptr) >= 1704067200UL) return true; // >= 2024
    delay(250);
    waited += 250;
  }
  return netIsConnected() && time(nullptr) >= 1704067200UL;
}

static bool loadBlockList(const char* reason) {
  bool res = false;
  if (!downloading) {
    downloading = true;                       // claim immediately
    duplicates = 0;
    updateConfigVect("loadProg", "0.0%");
    LOG_INF("%s load of latest blocklist", reason);

    if (waitForNetworkAndTime(15000)) {
      for (int tries = 1; tries <= 3 && !res; tries++) {
        res = downloadBlockList();
        if (!res && tries < 3) {
          LOG_WRN("Attempt %d failed - resetting and retrying", tries);
          resetBlocklistStorage();
          delay(2000);
        }
      }
      if (res) { lastLoadMs = millis(); startupFailure[0] = 0; }
      else if (!lastLoadMs) {
        snprintf(startupFailure, SF_LEN, STARTUP_FAIL "Blocklist URL %s failed to load", fileURL);
        LOG_WRN("%s", startupFailure);
      } else {
        LOG_WRN("%s load failed - keeping existing %lu-domain blocklist", reason, itemsLoaded - 2);
      }
      loadCustom();
    } else {
      LOG_WRN("Network/time not ready within 15 s (%s)", netIsConnected() ? "clock" : "wifi");
    }

    downloading = false;                      // ALWAYS released, any path
  } else LOG_WRN("Ignore request as download in progress");
  return res;
}

static QueueHandle_t blQueue = nullptr;
typedef struct { char reason[16]; } BlReq_t;

static void blTask(void *parameter) {
  BlReq_t req;
  for (;;) {
    if (xQueueReceive(blQueue, &req, portMAX_DELAY) == pdTRUE) {
      loadBlockList(req.reason);   // heavy work happens HERE, not in ping task
    }
  }
}
///////////////////////////////////////////////////

void appSetup() {
  
  while (!strlen(fileURL)) {
    LOG_ALT("Enter blocklist URL on web page ...");
    delay(30000); // wait for file URL to be entered
  }
  ptrs = (uint32_t*)ps_calloc((maxDomains + 2), sizeof(uint32_t)); // sorted pointers
  storageSize = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
  if (!ptrs || storageSize < minMemory + 1024) {
    snprintf(startupFailure, SF_LEN, STARTUP_FAIL "Insufficient PSRAM for blocklist");
    LOG_ERR("%s", startupFailure);
    return;
  }
  storageSize -= minMemory;
  if (storageSize < 1024 * 1024){ LOG_WRN("PSRAM looks absent/tiny - do a FULL power cycle (warm resets can skip OPI RAM init)"); }
  strcpy(fmtStorageSize, fmtSize(storageSize));
  storage = (char*)ps_calloc(storageSize, sizeof(char));
  if (!storage) {
    snprintf(startupFailure, SF_LEN, STARTUP_FAIL "Failed to allocate %s domain storage", fmtStorageSize);
    LOG_ERR("%s", startupFailure);
    return;
  }
  // ~28 bytes consumed per domain incl. pointer
  LOG_INF("Blocklist capacity: %s storage, approx %lu domains, limit %u",
          fmtStorageSize, (uint32_t)(storageSize / 28), maxDomains);
  // prime domain storage for binary search to prevent pointer 0 being returned
  memcpy(storage, "!", 1); // always first so ptrs[0] = 0
  blocklistSize = 2;
  itemsLoaded = 1;
  addDomain(0, "#", 1);

  updateConfigVect("blockCnt", "0");
  updateConfigVect("allowCnt", "0");

  loadBlockList("Initial"); // best effort - DNS starts regardless
  prepDNS();

  blQueue = xQueueCreate(4, sizeof(BlReq_t));
  if (blQueue) xTaskCreatePinnedToCore(blTask, "blTask", 1024 * 10, NULL, 2, NULL, 1);
}


/************************ webServer callbacks *************************/
bool updateAppStatus(const char* variable, const char* value, bool fromUser) {
  // update vars from configs and browser input
  bool res = true;
  int intVal = atoi(value);
  if (!strcmp(variable, "custom")) {
    // update config for latest stats to return on next main page call
    char cntStr[20];
    sprintf(cntStr, "%lu", blockCnt);
    updateConfigVect("blockCnt", cntStr);
    sprintf(cntStr, "%lu", allowCnt);
    updateConfigVect("allowCnt", cntStr);
  }
  else if (!strcmp(variable, "fileURLc")) strncpy(fileURL, value, IN_FILE_NAME_LEN - 1);
  else if (!strcmp(variable, "maxDomains")) maxDomains = intVal * 1000;
  else if (!strcmp(variable, "minMemory")) minMemory = intVal * 1024;
  else if (!strcmp(variable, "maxDomLen")) maxDomLen = intVal;
  //else if (!strcmp(variable, "showBL")) showBlockList(intVal); // not on web page
  else if (fromUser && !strcmp(variable, "xStop")) {
    stopLoad = true;
    LOG_ALT("Blocklist load being stopped");
  }
  // add user supplied domain name to blocklist unless a duplicate or invalid
  else if (fromUser && !strcmp(variable, "uLoad")) checkDomain(value, true, false);
  // delete user supplied domain name from blocklist if present
  else if (fromUser && !strcmp(variable, "vLoad")) checkDomain(value, false, true);
  // check if user supplied domain name in blocklist
  else if (fromUser && !strcmp(variable, "wLoad")) checkDomain(value, false, false);
    else if (fromUser && !strcmp(variable, "zLoad")) {
    stopLoad = false;
    if (strlen(value)) {
      if (strcmp(value, fileURL) != 0) {
        /* genuinely new source: persist + controlled restart */
        strncpy(fileURL, value, IN_FILE_NAME_LEN - 1);
        fileURL[IN_FILE_NAME_LEN - 1] = 0;         // force NUL (hardening)
        updateConfigVect("fileURLc", value);
        updateStatus("save", "0");
        doRestart("Reload blocklist request");
      } else {
        /* same URL: hot reload through blTask, NO restart */
        BlReq_t req; memset(&req, 0, sizeof(req));
        strncpy(req.reason, "Manual", sizeof(req.reason) - 1);
        xQueueSend(blQueue, &req, 0);
        LOG_INF("Same URL - hot reload queued (no restart)");
      }
    } else {
      BlReq_t req; memset(&req, 0, sizeof(req));   // empty value = plain reload
      strncpy(req.reason, "Manual", sizeof(req.reason) - 1);
      xQueueSend(blQueue, &req, 0);
    }
  }
  else if (fromUser && !strcmp(variable, "zzCustom")) {
    STORAGE.remove(CUSTOM_FILE_PATH);
    LOG_ALT("Deleted custom blocklist file");
  }
  else if (!strcmp(variable, "zzzAdblockOn")) {
    adBlockOn = (bool)intVal;
    if (adBlockOn) LOG_ALT("Ad blocking enabled");
    else LOG_WRN("Ad blocking disabled");
  }
  return res;
}

void appSpecificWsBinHandler(uint8_t* wsMsg, size_t wsMsgLen) {
  LOG_ERR("Unexpected websocket binary frame");
}

void appSpecificWsHandler(const char* wsMsg) {
  // message from web socket
  int wsLen = strlen(wsMsg) - 1;
  switch ((char)wsMsg[0]) {
    case 'X':
    break;
    case 'H':
      // keepalive heartbeat, return status
    break;
    case 'S':
      // status request
      buildJsonString(wsLen); // required config number
      LOG_SEND("%s\n", jsonBuff);
    break;
    case 'U':
      // update or control request
      memcpy(jsonBuff, wsMsg + 1, wsLen); // remove 'U'
      parseJson(wsLen);
    break;
    case 'K':
      // kill websocket connection
      killSocket();
    break;
    default:
      LOG_WRN("unknown command %c", (char)wsMsg[0]);
    break;
  }
}

char* buildAppJsonString(bool filter) {
  // build app specific part of json string
  char* p = jsonBuff + 1;
  return p;
}

esp_err_t appSpecificWebHandler(httpd_req_t *req, const char* variable, const char* value) {
  return ESP_FAIL;
}

esp_err_t appSpecificSustainHandler(httpd_req_t* req) {
  return ESP_OK;
}


void externalAlert(const char* subject, const char* message) {
  // alert any configured external servers
}


bool appDataFiles() {
  // callback from setupAssist.cpp, for any app specific files
  return true;
}

void doAppPing(bool timeSynced) {
  static bool timeSyncRetryDone = false;
  if (!blQueue) return;

  if (timeSynced && !timeSyncRetryDone) {
    timeSyncRetryDone = true;
    if (!lastLoadMs) {                        // initial load never succeeded
      BlReq_t req; strncpy(req.reason, "TimeSynced", sizeof(req.reason) - 1); req.reason[15] = 0;
      xQueueSend(blQueue, &req, 0);
    }
    return;
  }

  const uint32_t MIN_RELOAD_INTERVAL = 3600000UL;
  if (checkAlarm() && strlen(fileURL) &&
      (millis() - lastLoadMs > MIN_RELOAD_INTERVAL)) {
    BlReq_t req; strncpy(req.reason, "Scheduled", sizeof(req.reason) - 1); req.reason[15] = 0;
    xQueueSend(blQueue, &req, 0);
  }
}

void OTAprereq() {
  stopPing();
}

/************** default app configuration **************/
const char* appConfig = R"~(
restart~~99~T~na
ST_SSID~~0~T~Wifi SSID name
ST_Pass~~0~T~Wifi SSID password
ST_ip~~0~T~Static IP address
ST_gw~~0~T~Router IP address
ST_sn~255.255.255.0~0~T~Router subnet
ST_ns1~1.1.1.1~0~T~DNS server
ST_ns2~8.8.8.8~0~T~Alt DNS server
AP_Pass~~0~T~AP Password
AP_ip~~0~T~AP IP Address if not 192.168.4.1
AP_sn~~0~T~AP subnet
AP_gw~~0~T~AP gateway
useHttps~0~0~C~Enable HTTPS connection to app
allowAP~0~0~C~Allow simultaneous AP
timezone~KST-9~1~T~Timezone string: tinyurl.com/TZstring
logType~0~99~N~Output log selection
Auth_Name~~0~T~Optional user name for web page login
Auth_Pass~~0~T~Optional web page password
formatIfMountFailed~0~1~C~Format file system on failure
wifiTimeoutSecs~30~0~N~WiFi connect timeout (secs)
alarmHour~4~1~N~Hour of day for blocklist update
usePing~1~0~C~Use ping
maxDomains~250~1~N~Max number of domains (* 1000)
minMemory~128~1~N~Minimum free memory (KB)
maxDomLen~100~1~N~Max length of domain name
allowCnt~0~2~D~Allowed domains
blockCnt~0~2~D~Blocked domains
fileURLc~https://dns.dateno1.com/hosts~2~D~Current URL for blocklist file
fileURLn~~2~X~Enter new URL for blocklist file or domain
loadProg~0~2~D~Blocklist download progress
netMode~0~3~S:WiFi:Ethernet:Eth+AP~Network interface selection
wLoad~Check Domain~2~A~Check if domain name is blocked
uLoad~Add Domain~2~A~Add to blocklist
vLoad~Del Domain~2~A~Delete from blocklist
zLoad~Reload~2~A~Reload Blocklist
xStop~Stop Load~2~A~Stop Blocklist Load
zzCustom~Clear~2~A~Clear custom blocklist
zzzAdblockOn~1~2~C~Enable AdBlocker
ethCS~-1~3~N~Ethernet CS pin
ethInt~-1~3~N~Ethernet Interrupt pin
ethRst~-1~3~N~Ethernet Reset pin
ethSclk~-1~3~N~Ethernet SPI clock pin
ethMiso~-1~3~N~Ethernet SPI MISO pin
ethMosi~-1~3~N~Ethernet SPI MOSI pin
)~";
