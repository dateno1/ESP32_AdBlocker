// AdBlocker specific functions
//
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

static size_t formatDomain(char* domName) {
  // format input domain name by removing whitespace, www. prefix and converting to lowercase
  trim(domName);
  toCase(domName);
  size_t domLen = strlen(domName);
  int wwwOffset = (strncmp(domName, "www.", 4) == 0) ? 4 : 0;  // remove any leading "www."
  memmove(domName, domName + wwwOffset,  domLen + 1 - wwwOffset);
  return domLen - wwwOffset;
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
  char normName[FILE_NAME_LEN];
  size_t n = strlen(domainName);
  if (n == 0 || n >= FILE_NAME_LEN) {
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
    static char blockedDomain[FILE_NAME_LEN] = {0};
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
  strcpy(domName, inName);
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
    NetworkClientSecure wclient;
    if (!strcmp(dlHost, GITHUB_HOST)) {
      // known host: keep certificate verification
      if (remoteServerConnect(wclient, dlHost, dlPort, git_rootCACertificate, BLOCKLIST)) {
        res = fetchBlockList(wclient);
      } else LOG_ERR("Verified TLS connect failed: %s", dlHost);
      remoteServerClose(wclient);
    } else {
      // any other TLS host: accept any certificate (no MITM protection)
      LOG_WRN("TLS cert verification skipped for %s", dlHost);
      wclient.setInsecure();
      if (wclient.connect(dlHost, dlPort)) {
        res = fetchBlockList(wclient);
      } else LOG_ERR("Could not connect to %s:%u", dlHost, dlPort);
      wclient.stop();
    }
  } else {
    // plain HTTP: direct connection, no certificates involved
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

static void showBlockList(int maxItems = 0) {
  // for info
  if (!maxItems) maxItems = itemsLoaded;
  for (int i = 0; i < maxItems; i++) LOG_SEND("%d: %s\n", i, storage + ptrs[i]);
  LOG_SEND("Total %lu items\n", itemsLoaded);
}

static bool loadBlockList(const char* reason) {
  // load or refresh blocklist file
  bool res = false;
  if (!downloading) {
    duplicates = 0;
    updateConfigVect("loadProg", "0.0%");
    LOG_INF("%s load of latest blocklist", reason);
    if (netIsConnected()) {
      res = downloadBlockList();
      if (res) lastLoadMs = millis();
      else {
        snprintf(startupFailure, SF_LEN, STARTUP_FAIL "Blocklist URL %s failed to load", fileURL);
        LOG_WRN("%s", startupFailure);
        LOG_INF("*** Enter on browser: http://<AdBlocker IP>/control?zLoad=<valid blocklist URL>");
      }
      loadCustom();
    } else LOG_WRN("Internet download not available");
  } else LOG_WRN("Ignore request as download in progress");
  return res;
}

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
  else if (!strcmp(variable, "showBL")) showBlockList(intVal); // not on web page
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
    // reload or load new blocklist
    stopLoad = false;
    if (strlen(value)) {
      strncpy(fileURL, value, IN_FILE_NAME_LEN - 1);
      updateConfigVect("fileURLc", value);
      updateStatus("save", "0");
    }
    doRestart("Reload blocklist request");
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
  // daily blocklist refresh at/after alarmHour,
  // but never sooner than 1 hour after the previous load (e.g. the boot load)
  const uint32_t MIN_RELOAD_INTERVAL = 3600000UL; // 1 hour
  if (checkAlarm() && strlen(fileURL) &&
      (millis() - lastLoadMs > MIN_RELOAD_INTERVAL)) {
    loadBlockList("Scheduled");
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
maxDomains~200~1~N~Max number of domains (* 1000)
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