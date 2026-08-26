/* Query external DNS
 *
 * Architecture (single-task design):
 *   prepDNS()  : opens ONE UDP socket bound to :53 and spawns 'dnsTask'.
 *   dnsTask()  : recvfrom -> processDNSquery -> sendto (same socket, so replies
 *                carry source port 53 like any real resolver).
 *   resolveDomainStatus(): synchronous rcode-aware query to the configured
 *                upstreams; distinguishes NXDOMAIN (RCODE 3) from SERVFAIL
 *                (timeout / RCODE 2,4,5), which lwIP's gethostbyname cannot.
 * Concurrency: only 'dnsTask' talks to dnsSock; upstream probes use short-lived
 * ephemeral sockets, so upstream replies can never be confused with queries. */
//
//dateno1 2026
// s60sc 2026

#include "appGlobals.h"
#include <lwip/sockets.h>   // socket/sendto/recvfrom/setsockopt/close

#define DNS_DEFAULT_PORT   53    // listening port (also reply source port)
#define CACHE_SIZE         20    // positive-response cache slots (round-robin)
#define DEFAULT_TTL        300000 // cache lifetime, ms
#define MAX_HOSTNAME       256    // longest name we accept from clients
#define RESOLVE_TIMEOUT_MS 1500   // per-upstream-server attempt

typedef struct {
    uint16_t id;       // transaction ID (echoed in reply)
    uint16_t flags;    // QR/opcode/TC/RD/RA + RCODE live here in replies
    uint16_t qdcount;  // questions
    uint16_t ancount;  // answers
    uint16_t nscount;  // authority
    uint16_t arcount;  // additional
} __attribute__((packed)) dns_header_t;

/* Parse the QNAME starting at 'offset' into dotted text form.
 * Returns offset just past the terminating root label, or -1 on malformed
 * input (overrun, compression pointer, empty). Bounds-checked throughout -
 * never trust packet contents. */
int parseDNSname(uint8_t *packet, int offset, char *out, int outSize, int pktLen) {
  int i = 0;
  while (offset < pktLen && packet[offset] != 0) {
    int len = packet[offset++];
    if ((len & 0xC0) == 0xC0) return -1;      // pointers illegal in question section
    if (offset + len > pktLen) return -1;
    if (i + len + 2 >= outSize) return -1;    // reserve room for '.' + NUL
    for (int j = 0; j < len; j++) out[i++] = packet[offset++];
    out[i++] = '.';
  }
  if (i == 0 || offset >= pktLen) return -1;  // empty/unterminated name
  out[i - 1] = '\0';                          // strip trailing dot
  return offset + 1;
}

/* Core decision engine. Copies header+question into tx, then appends either
 * an A/AAAA answer (blocked/resolved) or nothing (NXDOMAIN/SERVFAIL, RCODE set).
 * Returns reply length, or 0 to drop silently (malformed query). */
static int processDNSquery(const uint8_t *rx, int len, uint8_t *tx, int txSize) {
  int offset = sizeof(dns_header_t);
  if (len < offset + 5) return 0;             // need header + minimal question
  char domain[MAX_HOSTNAME];
  int new_offset = parseDNSname((uint8_t *)rx, offset, domain, sizeof(domain), len);
  if (new_offset < 0 || new_offset + 4 > len) return 0;

  uint16_t qtype = ((uint16_t)rx[new_offset] << 8) | rx[new_offset + 1];
  offset = new_offset + 4;                    // skip QTYPE + QCLASS

  memcpy(tx, rx, offset);                     // echo header + question verbatim
  dns_header_t *res = (dns_header_t *)tx;
  res->qdcount = htons(1);
  res->nscount = 0;
  res->arcount = 0;                           // no OPT/EDNS downstream
  int resp_offset = offset;

  /* Four-state policy:
   *   BLOCKED  -> sinkhole 0.0.0.0 (A) or :: (AAAA), NODATA for other types
   *   RESOLVED -> forward upstream address (A); AAAA -> NODATA (IPv4 device)
   *   NXDOMAIN -> RCODE 3, zero answers (honest "does not exist")
   *   SERVFAIL -> RCODE 2, zero answers (upstream sick - NEVER cached) */
  IPAddress ansIP;
  DnsResult r = checkBlocklist(domain, ansIP);

  if (r == DNS_NXDOMAIN || r == DNS_SERVFAIL) {
    res->flags = htons(0x8180 | ((r == DNS_NXDOMAIN) ? 0x0003 : 0x0002));
    res->ancount = htons(0);
  }
  else if (r == DNS_BLOCKED) {
    res->flags = htons(0x8180);
    if (qtype == 0x0001) {                    // A -> 0.0.0.0
      res->ancount = htons(1);
      tx[resp_offset++] = 0xC0; tx[resp_offset++] = 0x0C; // name pointer
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x01; // TYPE A
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x01; // CLASS IN
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x00; // TTL 60s
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x3C;
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x04; // RDLENGTH
      tx[resp_offset++] = 0; tx[resp_offset++] = 0;
      tx[resp_offset++] = 0; tx[resp_offset++] = 0;       // 0.0.0.0
    } else if (qtype == 0x001C) {             // AAAA -> ::
      res->ancount = htons(1);
      tx[resp_offset++] = 0xC0; tx[resp_offset++] = 0x0C;
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x1C; // TYPE AAAA
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x01;
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x00;
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x3C;
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x10; // RDLENGTH 16
      memset(&tx[resp_offset], 0, 16);                    // all-zero = ::
      resp_offset += 16;
    } else {                                  // blocked, exotic type -> NODATA
      res->ancount = htons(0);
    }
  }
  else {                                      // DNS_RESOLVED
    if (qtype == 0x0001) {
      res->flags = htons(0x8180);
      res->ancount = htons(1);
      tx[resp_offset++] = 0xC0; tx[resp_offset++] = 0x0C;
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x01;
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x01;
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x00; // TTL 60s
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x3C;
      tx[resp_offset++] = 0x00; tx[resp_offset++] = 0x04;
      tx[resp_offset++] = ansIP[0]; tx[resp_offset++] = ansIP[1];
      tx[resp_offset++] = ansIP[2]; tx[resp_offset++] = ansIP[3];
    } else {                                  // IPv4-only forwarder -> NODATA,
      res->flags = htons(0x8180);             // lets client fall back to A
      res->ancount = htons(0);
    }
  }

  if (resp_offset > txSize) return 0;
  return resp_offset;
}

/* Dedicated worker: owns dnsSock for its whole life. Blocking recvfrom is
 * legal here (own task); concurrent client queries simply queue in the
 * socket buffer and are served serially - ample for household DNS load. */
static int dnsSock = -1;
static uint8_t rxbuf[512];
static uint8_t txbuf[512];

static void dnsTask(void *parameter) {
  struct sockaddr_in cli;
  socklen_t clilen;
  for (;;) {
    clilen = sizeof(cli);
    int len = recvfrom(dnsSock, rxbuf, sizeof(rxbuf), 0, (struct sockaddr *)&cli, &clilen);
    if (len < (int)sizeof(dns_header_t)) continue;
    int txLen = processDNSquery(rxbuf, len, txbuf, sizeof(txbuf));
    if (txLen > 0) sendto(dnsSock, txbuf, txLen, 0, (struct sockaddr *)&cli, clilen);
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
  addr.sin_addr.s_addr = INADDR_ANY;          // answers on STA and AP alike
  if (bind(dnsSock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    snprintf(startupFailure, SF_LEN, STARTUP_FAIL "DNS port 53 bind failed");
    LOG_WRN("%s", startupFailure);
    close(dnsSock); dnsSock = -1;
    return;
  }
  if (xTaskCreatePinnedToCore(dnsTask, "dnsTask", 4096, NULL, 3, NULL, 1) != pdPASS) {
    snprintf(startupFailure, SF_LEN, STARTUP_FAIL "DNS worker not started");
    LOG_WRN("%s", startupFailure);
    close(dnsSock); dnsSock = -1;
    return;
  }
  LOG_INF("AdBlocker DNS Server started on %s:%d", formatIPstr(), DNS_DEFAULT_PORT);
}

/************************ DNS Forwarder **************************/

/* Tiny positive-only cache. Negative results (NXDOMAIN/SERVFAIL) are never
 * cached so recovery after a WAN outage is immediate. */
struct CacheEntry {
  char hostname[MAX_HOSTNAME] = {0};
  IPAddress ip;
  uint32_t expiry;                            // millis() deadline
};
static CacheEntry dnsCache[CACHE_SIZE];

static bool cacheGet(const char* host, IPAddress& ip) {
  uint32_t now = millis();
  for (int i = 0; i < CACHE_SIZE; i++) {
    if (dnsCache[i].hostname[0] != '\0' && !strcmp(dnsCache[i].hostname, host)) {
      if ((int32_t)(now - dnsCache[i].expiry) >= 0) dnsCache[i].hostname[0] = 0; // expired
      else { ip = dnsCache[i].ip; return true; }
    }
  }
  return false;
}

static void cachePut(const char* host, const IPAddress& ip) {
  static int cacheIndex = 0;                  // round-robin eviction
  strncpy(dnsCache[cacheIndex].hostname, host, MAX_HOSTNAME - 1);
  dnsCache[cacheIndex].hostname[MAX_HOSTNAME - 1] = 0;
  dnsCache[cacheIndex].ip = ip;
  dnsCache[cacheIndex].expiry = millis() + DEFAULT_TTL;
  cacheIndex = (cacheIndex + 1) % CACHE_SIZE;
}

DnsResult resolveDomainStatus(const char* host, IPAddress& retIP) {
  retIP = IPAddress(0, 0, 0, 0);

  /* Local-discovery names must never leave the LAN (RFC 6761/6762 neighbours) */
  bool isLocal = false;
  size_t hostLen = strlen(host);
  if (strstr(host, "wpad") == host) isLocal = true;
  else if (hostLen >= 5 && !strcmp(host + hostLen - 5, ".home")) isLocal = true;
  else if (hostLen >= 6 && !strcmp(host + hostLen - 6, ".local")) isLocal = true;
  if (isLocal) { LOG_VRB("Ignore internal discovery: %s", host); return DNS_NXDOMAIN; }

  if (cacheGet(host, retIP)) {
    LOG_VRB("Resolved %s using cache to %d.%d.%d.%d", host, retIP[0], retIP[1], retIP[2], retIP[3]);
    return DNS_RESOLVED;
  }

  /* Try each configured forwarder once; failover only on transport failure.
   * A definitive RCODE from anyone ends the walk. */
  const char* servers[] = {ST_ns1, ST_ns2};
  for (int s = 0; s < 2; s++) {
    if (!servers[s][0]) continue;
    IPAddress srv;
    if (!srv.fromString(servers[s])) continue;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) break;
    struct timeval tv;
    tv.tv_sec = RESOLVE_TIMEOUT_MS / 1000;
    tv.tv_usec = (RESOLVE_TIMEOUT_MS % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Build query: 12B header + QNAME labels + QTYPE=A + QCLASS=IN */
    uint16_t qid = (uint16_t)esp_random();   // per-call random: safe under concurrency
    uint8_t qbuf[280], rbuf[512];
    size_t pos = 12;
    qbuf[0] = qid >> 8; qbuf[1] = qid & 0xFF;
    qbuf[2] = 0x01; qbuf[3] = 0x00;          // RD=1 (recurse please)
    qbuf[4] = 0; qbuf[5] = 1;                // QDCOUNT = 1
    memset(qbuf + 6, 0, 6);                  // AN/NS/AR = 0
    const char* hp = host;
    bool ok = true;
    while (*hp) {
      const char* dot = strchr(hp, '.');
      size_t lbl = dot ? (size_t)(dot - hp) : strlen(hp);
      if (!lbl || lbl > 63 || pos + lbl + 5 > sizeof(qbuf)) { ok = false; break; }
      qbuf[pos++] = (uint8_t)lbl;            // length-prefixed label
      memcpy(qbuf + pos, hp, lbl);
      pos += lbl;
      hp += lbl + (dot ? 1 : 0);
    }
    if (!ok) { close(fd); return DNS_SERVFAIL; }
    qbuf[pos++] = 0;                         // root label terminates QNAME
    qbuf[pos++] = 0; qbuf[pos++] = 1;        // QTYPE  = A
    qbuf[pos++] = 0; qbuf[pos++] = 1;        // QCLASS = IN

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(DNS_DEFAULT_PORT);  // upstream also speaks UDP/53
    dst.sin_addr.s_addr = srv;

    DnsResult res = DNS_SERVFAIL;
    bool haveAnswer = false;
    if (sendto(fd, qbuf, pos, 0, (struct sockaddr*)&dst, sizeof(dst)) == (ssize_t)pos) {
      struct sockaddr_in from;
      socklen_t fl = sizeof(from);
      ssize_t rlen = recvfrom(fd, rbuf, sizeof(rbuf), 0, (struct sockaddr*)&from, &fl);
      /* Accept only: long enough, matching ID, QR=1 (genuine response) */
      if (rlen >= 12 && ((uint16_t)rbuf[0] << 8 | rbuf[1]) == qid && (rbuf[2] & 0x80)) {
        uint8_t rcode = rbuf[3] & 0x0F;
        if (rcode == 3) res = DNS_NXDOMAIN;
        else if (rcode == 0) {
          /* Walk past echoed question, then scan answer RRs for the first
           * A record; CNAME chains are skipped via RDLENGTH stepping. */
          size_t q = 12;
          bool compressed = false;
          while (q < (size_t)rlen && rbuf[q] != 0) {
            if ((rbuf[q] & 0xC0) == 0xC0) { q += 2; compressed = true; break; }
            q += 1 + rbuf[q];
          }
          if (!compressed) q++;              // consume root byte
          q += 4;                            // QTYPE + QCLASS
          uint16_t ancount = ((uint16_t)rbuf[6] << 8) | rbuf[7];
          for (uint16_t a = 0; a < ancount && q + 10 <= (size_t)rlen; a++) {
            if ((rbuf[q] & 0xC0) == 0xC0) q += 2;              // compressed owner
            else { while (q < (size_t)rlen && rbuf[q]) q += 1 + rbuf[q]; q++; }
            if (q + 10 > (size_t)rlen) break;
            uint16_t rtype = ((uint16_t)rbuf[q] << 8) | rbuf[q + 1];
            uint16_t rdlen = ((uint16_t)rbuf[q + 8] << 8) | rbuf[q + 9];
            q += 10;                                            // TYPE+CLASS+TTL+RDLEN
            if (rtype == 1 && rdlen == 4 && q + 4 <= (size_t)rlen) {
              retIP = IPAddress(rbuf[q], rbuf[q + 1], rbuf[q + 2], rbuf[q + 3]);
              res = DNS_RESOLVED;
              break;
            }
            q += rdlen;                      // skip CNAME/others, keep scanning
          }
          if (res != DNS_RESOLVED) res = DNS_NXDOMAIN; // NOERROR+NODATA ~= NXDOMAIN
        }
        /* rcode 1,2,4,5 fall through as SERVFAIL */
        haveAnswer = true;                   // authoritative enough - stop failover
      }
    }
    close(fd);
    if (haveAnswer) return res;
  }
  return DNS_SERVFAIL;                       // no upstream answered in time
}

/* Legacy synchronous wrapper retained for checkDomain()'s "must resolve
 * before adding" validation. Returns 0.0.0.0 on anything but a clean hit. */
IPAddress resolveDomain(const char* host) {
  IPAddress ip;
  return resolveDomainStatus(host, ip) == DNS_RESOLVED ? ip : IPAddress(0, 0, 0, 0);
}
