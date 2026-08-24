// Query external DNS
//
// s60sc 2026

#include "appGlobals.h"
#include <lwip/sockets.h>
#include <arpa/inet.h>

#define DNS_DEFAULT_PORT 53
#define CACHE_SIZE 20        // number of previous domain names & IPs cached
#define DEFAULT_TTL 300000   // 5 minutes in ms
#define MAX_HOSTNAME 256

#define RESOLVE_TIMEOUT_MS 1500
#define DNS_UPSTREAM_PORT 53

/************************ DNS Server ***************************/

static int dnsSock = -1;
static uint8_t rxbuf[512];
static uint8_t txbuf[512];

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed)) dns_header_t;

int parseDNSname(uint8_t *packet, int offset, char *out, int outSize, int pktLen) {
  int i = 0;
  while (offset < pktLen && packet[offset] != 0) {
    int len = packet[offset++];
    if ((len & 0xC0) == 0xC0) return -1;       // compression ptr invalid in question
    if (offset + len > pktLen) return -1;
    if (i + len + 2 >= outSize) return -1;
    for (int j = 0; j < len; j++) out[i++] = packet[offset++];
    out[i++] = '.';
  }
  if (i == 0 || offset >= pktLen) return -1;   // empty/unterminated name
  out[i - 1] = '\0';
  return offset + 1;
}

// Build reply for received query. Returns reply length, or 0 to drop silently.
static int processDNSquery(const uint8_t *rx, int len, uint8_t *tx, int txSize) {
  int offset = sizeof(dns_header_t);
  if (len < offset + 5) return 0;
  char domain[MAX_HOSTNAME];
  int new_offset = parseDNSname((uint8_t *)rx, offset, domain, sizeof(domain), len);
  if (new_offset < 0 || new_offset + 4 > len) return 0;

  uint16_t qtype = ((uint16_t)rx[new_offset] << 8) | rx[new_offset + 1];
  offset = new_offset + 4; // skip QTYPE + QCLASS

  memcpy(tx, rx, offset); // echo header + question
  dns_header_t *res = (dns_header_t *)tx;
  res->qdcount = htons(1);
  res->nscount = 0;
  res->arcount = 0;
  int resp_offset = offset;

  // ---- 4-state decision: blocked / resolved / NXDOMAIN / SERVFAIL ----
  IPAddress ansIP;
  DnsResult r = checkBlocklist(domain, ansIP);

  //Add Log for Debug
  LOG_INF("Q '%s' type=%u -> result=%d", domain, qtype, (int)r);

  if (r == DNS_NXDOMAIN || r == DNS_SERVFAIL) {
    res->flags = htons(0x8180 | ((r == DNS_NXDOMAIN) ? 0x0003 : 0x0002));
    res->ancount = htons(0);
  }
  else if (r == DNS_BLOCKED) {
    res->flags = htons(0x8180); // Response + Recursion + NOERROR
    if (qtype == 0x0001) {      // A -> sinkhole 0.0.0.0
      res->ancount = htons(1);
      tx[resp_offset++] = 0xC0; tx[resp_offset++] = 0x0C;
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x01;   // Type A
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x01;   // Class IN
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x00;   // TTL 60
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x3C;
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x04;   // RDLENGTH 4
      tx[resp_offset++] = 0; tx[resp_offset++] = 0;
      tx[resp_offset++] = 0; tx[resp_offset++] = 0;         // 0.0.0.0
    } else if (qtype == 0x001C) { // AAAA -> ::
      res->ancount = htons(1);
      tx[resp_offset++] = 0xC0; tx[resp_offset++] = 0x0C;
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x1C;   // Type AAAA
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x01;   // Class IN
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x00;   // TTL 60
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x3C;
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x10;   // RDLENGTH 16
      memset(&tx[resp_offset], 0, 16);                      // ::
      resp_offset += 16;
    } else {                  // blocked domain, other record type -> NODATA
      res->ancount = htons(0);
    }
  }
  else {                        // DNS_RESOLVED
    if (qtype == 0x0001) {      // A -> forwarded answer
      res->flags = htons(0x8180);
      res->ancount = htons(1);
      tx[resp_offset++] = 0xC0; tx[resp_offset++] = 0x0C;
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x01;   // Type A
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x01;   // Class IN
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x00;   // TTL 60
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x3C;
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x04;   // RDLENGTH 4
      tx[resp_offset++] = ansIP[0]; tx[resp_offset++] = ansIP[1];
      tx[resp_offset++] = ansIP[2]; tx[resp_offset++] = ansIP[3];
    } else {                    // AAAA etc on IPv4-only device -> NODATA
      res->flags = htons(0x8180);
      res->ancount = htons(0);
    }
  }

  if (resp_offset > txSize) return 0;
  return resp_offset;
}

// single dedicated task: receive query -> process -> reply from port 53
static void dnsTask(void *parameter) {
  struct sockaddr_in cli;
  socklen_t clilen;
  for (;;) {
    clilen = sizeof(cli);
    int len = recvfrom(dnsSock, rxbuf, sizeof(rxbuf), 0, (struct sockaddr *)&cli, &clilen);
    if (len < (int)sizeof(dns_header_t)) {
      if (len < 0) LOG_WRN("DNS recvfrom error %d", len);
      continue;
    }
    LOG_INF("DNS query %d bytes from %s:%u", len,
            inet_ntoa(cli.sin_addr), (unsigned)ntohs(cli.sin_port));
    int txLen = processDNSquery(rxbuf, len, txbuf, sizeof(txbuf));
    if (txLen > 0) {
      sendto(dnsSock, txbuf, txLen, 0, (struct sockaddr *)&cli, clilen);
      LOG_INF("DNS reply sent %d bytes", txLen);
    }
  }
}

void prepDNS() {
  dnsSock = socket(AF_INET, SOCK_DGRAM, 0);
  if (dnsSock < 0) {
    snprintf(startupFailure, SF_LEN, STARTUP_FAIL "DNS socket not created");
    LOG_WRN("%s", startupFailure);
    return;
  }
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(DNS_DEFAULT_PORT);
  addr.sin_addr.s_addr = INADDR_ANY;
  if (bind(dnsSock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    snprintf(startupFailure, SF_LEN, STARTUP_FAIL "DNS port 53 bind failed");
    LOG_WRN("%s", startupFailure);
    close(dnsSock);
    dnsSock = -1;
    return;
  }
  if (xTaskCreatePinnedToCore(dnsTask, "dnsTask", 4096, NULL, 3, NULL, 1) != pdPASS) {
    snprintf(startupFailure, SF_LEN, STARTUP_FAIL "DNS worker not started");
    LOG_WRN("%s", startupFailure);
    close(dnsSock);
    dnsSock = -1;
    return;
  }
  LOG_INF("AdBlocker DNS Server started on %s:%d", formatIPstr(), DNS_DEFAULT_PORT);
  LOG_INF("DNS socket bound to :53, fd=%d", dnsSock);
}

/************************ DNS Forwarder **************************/

struct CacheEntry {
  char hostname[MAX_HOSTNAME] = {0};
  IPAddress ip;
  uint32_t expiry;
};
CacheEntry dnsCache[CACHE_SIZE];

static bool cacheGet(const char* host, IPAddress& ip) {
  uint32_t now = millis();
  for (int i = 0; i < CACHE_SIZE; i++) {
    if (dnsCache[i].hostname[0] != '\0' && strcmp(dnsCache[i].hostname, host) == 0) {
      if (now < dnsCache[i].expiry) { ip = dnsCache[i].ip; return true; }
      dnsCache[i].hostname[0] = 0; // invalidate expired entry
    }
  }
  return false;
}

static void cachePut(const char* host, const IPAddress& ip) {
  static int cacheIndex = 0;
  strncpy(dnsCache[cacheIndex].hostname, host, MAX_HOSTNAME - 1);
  dnsCache[cacheIndex].hostname[MAX_HOSTNAME - 1] = 0; // in case too long
  dnsCache[cacheIndex].ip = ip;
  dnsCache[cacheIndex].expiry = millis() + DEFAULT_TTL;
  cacheIndex = (cacheIndex + 1) % CACHE_SIZE;
}

DnsResult resolveDomainStatus(const char* host, IPAddress& retIP) {
  retIP = IPAddress(0, 0, 0, 0);

  // Ignore internal discovery
  bool isLocal = false;
  size_t hostLen = strlen(host);
  if (strstr(host, "wpad") == host) isLocal = true;
  else if (hostLen >= 5 && !strcmp(host + hostLen - 5, ".home")) isLocal = true;
  else if (hostLen >= 6 && !strcmp(host + hostLen - 6, ".local")) isLocal = true;
  if (isLocal) {
    LOG_VRB("Ignore internal discovery: %s", host);
    return DNS_NXDOMAIN; // these names genuinely do not exist upstream
  }

  // positive cache lookup
  if (cacheGet(host, retIP)) {
    LOG_VRB("Resolved %s using cache to %d.%d.%d.%d", host, retIP[0], retIP[1], retIP[2], retIP[3]);
    return DNS_RESOLVED;
  }

  // upstream query per configured server, failover on timeout/error
  const char* DNSserverIPs[] = {ST_ns1, ST_ns2};
  for (int srvIdx = 0; srvIdx < 2; srvIdx++) {
    if (!DNSserverIPs[srvIdx][0]) continue;
    IPAddress srv;
    if (!srv.fromString(DNSserverIPs[srvIdx])) continue;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) break;

    struct timeval tv;
    tv.tv_sec = RESOLVE_TIMEOUT_MS / 1000;
    tv.tv_usec = (RESOLVE_TIMEOUT_MS % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // build query: header + QNAME + QTYPE=A + QCLASS=IN
    static uint16_t queryId = 0;
    uint16_t qid = ++queryId;
    uint8_t qbuf[280];
    uint8_t rbuf[512];
    size_t pos = 12;
    qbuf[0] = qid >> 8; qbuf[1] = qid & 0xFF;
    qbuf[2] = 0x01; qbuf[3] = 0x00; // RD=1
    qbuf[4] = 0; qbuf[5] = 1;       // QDCOUNT = 1
    memset(qbuf + 6, 0, 6);
    const char* hp = host;
    bool ok = true;
    while (*hp) {
      const char* dot = strchr(hp, '.');
      size_t lbl = dot ? (size_t)(dot - hp) : strlen(hp);
      if (!lbl || lbl > 63 || pos + lbl + 5 > sizeof(qbuf)) { ok = false; break; }
      qbuf[pos++] = (uint8_t)lbl;
      memcpy(qbuf + pos, hp, lbl);
      pos += lbl;
      hp += lbl + (dot ? 1 : 0);
    }
    if (!ok) { close(fd); return DNS_SERVFAIL; } // malformed name
    qbuf[pos++] = 0;                  // root label
    qbuf[pos++] = 0; qbuf[pos++] = 1; // QTYPE = A
    qbuf[pos++] = 0; qbuf[pos++] = 1; // QCLASS = IN

    DnsResult res = DNS_SERVFAIL;
    bool haveAnswer = false;
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(DNS_UPSTREAM_PORT);
    dst.sin_addr.s_addr = srv;

    if (sendto(fd, qbuf, pos, 0, (struct sockaddr*)&dst, sizeof(dst)) == (ssize_t)pos) {
      struct sockaddr_in from;
      socklen_t fromLen = sizeof(from);
      ssize_t rlen = recvfrom(fd, rbuf, sizeof(rbuf), 0, (struct sockaddr*)&from, &fromLen);
      if (rlen >= 12 &&
          ((uint16_t)rbuf[0] << 8 | rbuf[1]) == qid && // matching transaction ID
          (rbuf[2] & 0x80)) {                          // QR bit: is response
        uint8_t rcode = rbuf[3] & 0x0F;
        if (rcode == 3) {
          res = DNS_NXDOMAIN;
        } else if (rcode == 0) {
          // scan answer records for first A record (skips CNAME chains)
          size_t q = 12;
          bool compressed = false;
          while (q < (size_t)rlen && rbuf[q] != 0) { // skip question name
            if ((rbuf[q] & 0xC0) == 0xC0) { q += 2; compressed = true; break; }
            q += 1 + rbuf[q];
          }
          if (!compressed) q++; // root byte
          q += 4;               // QTYPE + QCLASS
          uint16_t ancount = ((uint16_t)rbuf[6] << 8) | rbuf[7];
          for (uint16_t a = 0; a < ancount && q + 10 <= (size_t)rlen; a++) {
            if ((rbuf[q] & 0xC0) == 0xC0) q += 2; // compressed owner name
            else {
              while (q < (size_t)rlen && rbuf[q] != 0) q += 1 + rbuf[q];
              q++;
            }
            if (q + 10 > (size_t)rlen) break;
            uint16_t rtype = ((uint16_t)rbuf[q] << 8) | rbuf[q + 1];
            uint16_t rdlen = ((uint16_t)rbuf[q + 8] << 8) | rbuf[q + 9];
            q += 10;
            if (rtype == 1 && rdlen == 4 && q + 4 <= (size_t)rlen) {
              retIP = IPAddress(rbuf[q], rbuf[q + 1], rbuf[q + 2], rbuf[q + 3]);
              res = DNS_RESOLVED;
              break;
            }
            q += rdlen; // skip CNAME/other record data
          }
          if (res != DNS_RESOLVED) res = DNS_NXDOMAIN; // NOERROR but no A record (NODATA)
        }
        // rcode 1, 2, 4, 5 -> stays DNS_SERVFAIL
        haveAnswer = true;
      }
    }
    close(fd);
    if (haveAnswer) return res; // definitive upstream answer - no failover needed
  }
  return DNS_SERVFAIL; // no upstream answered
}

// legacy wrapper kept for checkDomain() in adblocker.cpp
IPAddress resolveDomain(const char* host) {
  IPAddress ip;
  return resolveDomainStatus(host, ip) == DNS_RESOLVED ? ip : IPAddress(0, 0, 0, 0);
}