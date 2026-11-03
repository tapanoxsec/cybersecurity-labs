# A Week of Internet Scanning on a Public Web Server

Oct 31, 2026&#32;

In one week, 15,858 IP addresses probed a single public web server, and none of the attempts to steal files or run code worked: every one of the 1,139 successful responses was the same static homepage.

## Setup

I analysed a public capture of about 6 days of traffic (16 to 22 October 2026) hitting one Ubuntu web server running Apache 2.4.58 at 203.161.44.208.

| Item | Value |
| --- | --- |
| Capture file | 2026-10-22-seven-days-of-scans-and-probes-and-web-traffic-hitting-my-web-server.pcap |
| Packets | 468,766 (about 38 MB) |
| Distinct source IPs | 15,858 |
| HTTP requests | about 10,900 |
| Tools | Wireshark (Protocol Hierarchy, Conversations, HTTP statistics, Follow HTTP Stream), AbuseIPDB, GreyNoise |

The traffic is almost all unsolicited: the server has no real audience, so what the capture shows is the background noise of the internet.

## Layers of probing

The traffic arrives in layers, from cheap port checks up to targeted web requests.

1. **Port probes.** TCP is 97.4% of the 468,766 packets, and about 434,000 of them carry no application data. 5,959 of the 15,858 conversations (38%) are 3 packets or fewer; the most common shape is 2 packets, 114 bytes: a SYN in and a reset out, because the port was closed.
2. **DNS fingerprinting.** Outside hosts sent DNS queries to a server that does not run DNS and got ICMP "port unreachable" back. Queries such as `version.bind` TXT ask which DNS software is running, and one query name identifies a Shadowserver research scanner.
3. **Odd-service sweeps.** The protocol hierarchy shows SIP (809 packets), Modbus, BACnet, EtherNet/IP, KNX, SNMP, Memcache and Chargen. Wireshark labels these by port number, so they show which ports scanners tried (VoIP, industrial control, amplification services), not what the server runs.
4. **TLS probes.** 64 Client Hellos arrived, several using obsolete SSLv3 and TLS 1.0, and one with an IP address as the server name. A scanner checking for weak protocols looks like this, not a browser.
5. **Web requests.** About 21,900 HTTP packets, covered in the next section.

Two address blocks, 85.217.140.0/24 and 85.217.149.0/24, produced 38% of all packets.

## Web probes

The HTTP requests fall into four kinds. Payloads are shown as text only; none were opened or run.

| Kind | Example from the capture | What the attacker wants |
| --- | --- | --- |
| Homepage and robots checks | `/` (1,321 requests), `/favicon.ico`, `/robots.txt` | Confirm a web server is there |
| Secret hunting | `/.env` and variants (`.env.bak`, `/app/.env`, `/laravel/.env`), `/.git/config`, `/.aws/credentials`, `docker-compose.yml`, `secrets.json` | Passwords and API keys left in the web root |
| Known exploits | `phpunit/.../eval-stdin.php` (about 450 requests), Apache path traversal (`/cgi-bin/.%2e/...`), a Struts2 OGNL string, `/?%ADd+allow_url_include=1+...php://input` (CVE-2024-4577), a router `wget \| sh` command, a DVR `/device.rsp` call that downloads an `arm7` binary | Run code on the server or recruit it into a botnet |
| Open-proxy tests | `GET http://api.ipify.org/?format=json`, `httpbin.org:443` (66 requests), `a7x.overflow.biz/hachk.php` | See whether the server will fetch other sites for the attacker |

One scanner stream shows the pattern well: 101 requests in 21 seconds, all with the same old Chrome 50 User-Agent, walking a list of `.env` and config paths.

## Who was scanning

I looked up five IPs on 30 October 2026 in GreyNoise and AbuseIPDB: two research scanners and three active attackers.

| IP | Owner (country) | GreyNoise | AbuseIPDB | What it did here |
| --- | --- | --- | --- | --- |
| 31.14.32.7 | NewVM B.V. (Netherlands), reverse DNS `scanner.modat.io` | Benign, actor Modat | 100%, 24,124 reports | Steady probing all week, about 6,000 packets |
| 85.217.140.39 | Modat B.V. (France), reverse DNS `scanner.modat.io` | Benign, actor Modat | 100%, 31,171 reports | One of 53 IPs in a block sending 22% of all packets |
| 45.198.224.125 | VPSVAULT.HOST (Canada) | Malicious, 20 tags | 100%, 9,178 reports | Repeated `GET /` on ports 80 and 8080 |
| 160.119.66.206 | HostMem, AS49870 (Netherlands) | Malicious, 17 tags | 100%, 4,634 reports | Named in the botnet download; posts to `/device.rsp` every 20-30 minutes, brute-forces SSH as root on honeypots |
| 43.165.198.224 | AS132203, Tencent-linked (Indonesia) | Malicious, 22 tags | 100%, 1,164 reports | One `GET /` here; other sites' honeypots caught it requesting `/.env`, `/.git/HEAD` and WordPress paths |

All five were still being reported on 30 October, two weeks after the capture.

The two sources disagree on Modat on purpose. GreyNoise calls it benign because it is a known internet search-engine scanner; AbuseIPDB scores it 100% because thousands of firewalls report its port scans. The reverse DNS name `scanner.modat.io` is the quickest tell.

## What succeeded

Nothing sensitive was served. The server returned 1,139 responses with code 200, and every one was the same homepage.

| Response | Count | Detail |
| --- | --- | --- |
| 200, uncompressed | 347 | Content-Length 501, the "Welcome to www.wiresharkworkshop.online" page |
| 200, gzip-compressed | 792 | Content-Length 308, which Wireshark decodes to 501 bytes, the same page |
| 404 Not Found | 99 of 101 in the stream I followed | `/.env`, `/assets/.env`, `/api/.env`, `/settings.json`, `/phpinfo.php` and similar |

The two 200s in that stream, `/?phpinfo=-1` and `/?url=.env`, were `/` with a query string: the server ignored the query and returned the homepage. The exploit probe for CVE-2024-4577 and the `api.ipify.org` proxy test got the same page, so the server is not an open proxy and the exploits did not run.

The lesson is that a 200 only means the server answered. Check the body before calling a request a success.

## Takeaways and limits

A defender would take five things from this capture.

1. Never leave `.env`, `.git` or `.aws` files in a web root, because they are the most requested paths in the capture.
2. Close ports that should not be public. A web page answered on 27017, MongoDB's port, which invites database scanners.
3. Combine reputation sources: GreyNoise (is it a known scanner?), AbuseIPDB (how many people block it?) and reverse DNS.
4. Rate-limit or block repeat visitors such as 45.198.224.125, and treat research scanners like Modat as policy decisions, not attacks.
5. Judge a request by its pattern, not one packet: a lone `GET /` can be step one of a reconnaissance run.

**Limits.** This is one server over one week. AbuseIPDB and GreyNoise are crowd-sourced signals, not proof of intent. I confirmed the 1,139 successful responses by size and by inspecting sample packets and one full stream, not by decoding every body, and the owners of 85.217.149.0/24 and the other IPs in the busiest blocks are inferred, not looked up.
