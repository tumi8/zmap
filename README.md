ZMap: The Internet Scanner
==========================

![Build Status](https://github.com/zmap/zmap/actions/workflows/cmake.yml/badge.svg)

ZMap is a fast single packet network scanner designed for Internet-wide network
surveys. On a typical desktop computer with a gigabit Ethernet connection, ZMap
is capable scanning the entire public IPv4 address space in under 45 minutes. With
a 10gigE connection and [PF_RING](http://www.ntop.org/products/packet-capture/pf_ring/),
ZMap can scan the IPv4 address space in under 5 minutes.

ZMap operates on GNU/Linux, Mac OS, and BSD. ZMap currently has fully implemented
probe modules for TCP SYN scans, ICMP, DNS queries, UPnP, BACNET, and can send a
large number of [UDP probes](https://github.com/zmap/zmap/blob/master/examples/udp-probes/README).
If you are looking to do more involved scans, e.g.,
banner grab or TLS handshake, take a look at [ZGrab 2](https://github.com/zmap/zgrab2),
ZMap's sister project that performs stateful application-layer handshakes.

Installation
------------

The latest stable release of ZMap is version 2.1.1 and supports Linux, macOS, and
BSD. However, the release was tagged in 2015, and since then quite a bit has changed. Accordingly,
_we strongly encourage researchers to use [ZMap 3.0.0 Beta 1](https://github.com/zmap/zmap/releases/tag/v3.0.0-beta1)._

**Instructions on building ZMap from source** can be found in [INSTALL](INSTALL.md).

Usage
-----

A guide to using ZMap is found in our [GitHub Wiki](https://github.com/zmap/zmap/wiki).

IPv6 support
------------

We added IPv6 support to ZMap and include the following new probe modules:

* ICMPv6 Echo Request: `icmp6_echoscan`
* IPv6 TCP SYN (any port): `ipv6_tcp_synscan` or `ipv6_tcp_synopt`
* IPV6 UDP (any port and payload): `ipv6_udp`
* IPV6 DNS (any port): `ipv6_dns`

You can specify the respective IPv6 probe module using the `-M` or `--probe-module` command line flag.

In addition, you need to specify the source IPv6 address with the `--ipv6-source-ip` flag and a file containing IPv6 targets using the `--ipv6-target-file` flag.
More information can be found using the `--help` flag.

As targets for your IPv6 measurements you can e.g. use addresses from our [IPv6 Hitlist Service](https://ipv6hitlist.github.io/).

QUIC Probe module
-----------------------

We added probe modules for IPv4 and IPv6 to detect QUIC capable hosts based on the Version negotiation as described in [RFC9000](https://datatracker.ietf.org/doc/html/rfc9000)

To start the scanner enter:

```bash
zmap -q -M quic_initial -p"443" --output-module="csv" \
-f "saddr,classification,success,versions" -o "output.csv" \
--probe-args="padding:1200" "$address/$netmask"
```

* `-q`: silent / without stdout
* `-p`: port, usually 443 for QUIC
* `-M quic_initial`: loads our QUIC probe module
* `--output-module=csv`: save as csv
* `-f "..."`: specifies fields that will be stored in the output file
* `-o output.csv`: name of the output file
* `--probe-args="padding:X"` [optional]: changes default padding to X bytes
* `$address`: IPv4 address
* `$netmask`: 0-32


The Initial packet should be at least 1200 Bytes long according to the specification.
The default padding is 1200 - sizeof(long_quic_header) [22 Bytes] = 1178 Bytes

With the `--probe-args="padding:X"` argument, we can scan target using Initial packets 
that do not follow the current specification. 
* Default: X=1178
* Initial packets without padding: X=0
* Initial packets with size 300: X=278

IPv6 DNS Probe Moodule
---------------------

We added IPv6 DNS support to ZMap.
To start the scanner enter (replace all variables with your system value [$interface,$node_ip,$target_file,$logfile,$gatewaymac):

```bash
zmap \
        --interface="$interface" \
        --ipv6-source-ip="$node_ip" \
        --ipv6-target-file="$target_file" \
        --target-port=53 \
        --probe-module=ipv6_dns \
        --probe-args="AAAA,www.google.com" \
        --blocklist-file=/etc/zmap/blocklist.conf \
        --rate=55000\
        --gateway-mac=$gatewaymac
```
* `--interface`: specify interface
* `$interface`: valid interface of scanning device
* `--ipv6-source-ip`: specify IPv6 source address
* `$node_ip`: IPv6 address
* `--ipv6-target-file`: file with ipv6 addresses which shall be scanned
* `$target_file`: path to scan file
* `--target-port`: port, usually 53 for DNS
* `--probe-module=ipv6_dns`: loads IPv6 DNS module
* `--probe-args="AAAA,www.google.com"`: format is [QTYPE],[QNAME] - qtype support for "A", "NS", "CNAME", "SOA", "PTR", "MX", "TXT", "AAAA", "RRSIG", "ALL"
* `--blocklist-file=/etc/zmap/blocklist.conf`: default blocklist file (addresses in there are skipped during scan)
* `--rate=55000`: scan rate in packets per second
* `--gateway-mac`: optional MAC address, may be necessary if scanning node has multiple interfaces and you are using a non-default interface
* `$gatewaymac`: MAC address of the specified interface

License and Copyright
---------------------

ZMap Copyright 2017 Regents of the University of Michigan

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See LICENSE for the specific
language governing permissions and limitations under the License.
