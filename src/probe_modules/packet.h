/*
 * Copyright 2021 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "../../lib/includes.h"
#include "../../lib/blocklist.h"
#include "../../lib/pbm.h"
#include "../state.h"
#include "../send.h"

#ifndef PACKET_H
#define PACKET_H

#define ICMP_UNREACH_HEADER_SIZE 8

#define PACKET_VALID 1
#define PACKET_INVALID 0

#define ICMP_HEADER_SIZE 8

#define PRINT_PACKET_SEP \
	"------------------------------------------------------\n"

#define CLASSIFICATION_SUCCESS_FIELDSET_FIELDS           \
	{.name = "classification",                       \
	 .type = "string",                               \
	 .desc = "packet classification"},               \
	{                                                \
		.name = "success", .type = "bool",       \
		.desc = "is response considered success" \
	}

#define CLASSIFICATION_SUCCESS_FIELDSET_LEN 2

#define ICMP_FIELDSET_FIELDS                                                                             \
	{.name = "icmp_responder",                                                                       \
	 .type = "string",                                                                               \
	 .desc = "Source IP of ICMP_UNREACH messages"},                                                  \
	    {.name = "icmp_type", .type = "int", .desc = "icmp message type"},                           \
	    {.name = "icmp_code",                                                                        \
	     .type = "int",                                                                              \
	     .desc = "icmp message sub type code"},                                                      \
	{                                                                                                \
		.name = "icmp_unreach_str", .type = "string",                                            \
		.desc =                                                                                  \
		    "for icmp_unreach responses, the string version of icmp_code (e.g. network-unreach)" \
	}

#define ICMP_FIELDSET_LEN 4

typedef unsigned short __attribute__((__may_alias__)) alias_unsigned_short;

void make_eth_header(struct ether_header *ethh, macaddr_t *src, macaddr_t *dst);
void make_eth_header_ethertype(struct ether_header *ethh, macaddr_t *src, macaddr_t *dst, uint16_t ether_type);

void make_ip_header(struct ip *iph, uint8_t, uint16_t);
void make_ip6_header(struct ip6_hdr *iph, uint8_t, uint16_t);
void make_tcp_header(struct tcphdr *, uint16_t th_flags);
size_t set_mss_option(struct tcphdr *tcp_header);
size_t set_tcp_options(struct tcphdr *tcp_header, uint8_t os);
void make_icmp_header(struct icmp *);
void make_icmp6_header(struct icmp6_hdr *);
void make_udp_header(struct udphdr *udp_header, uint16_t len);
void fprintf_ip_header(FILE *fp, struct ip *iph);
void fprintf_ipv6_header(FILE *fp, struct ip6_hdr *iph);
void fprintf_eth_header(FILE *fp, struct ether_header *ethh);

static inline unsigned short in_checksum(unsigned short *ip_pkt, int len)
{
	unsigned long sum = 0;
	for (int nwords = len / 2; nwords > 0; nwords--) {
		sum += *ip_pkt++;
	}
	if (len % 2 == 1) {
		sum += *((unsigned char *)ip_pkt);
	}
	sum = (sum >> 16) + (sum & 0xffff);
	return (unsigned short)(~sum);
}

static inline unsigned short in_icmp_checksum(unsigned short *ip_pkt, int len)
{
	unsigned long sum = 0;
	for (int nwords = len / 2; nwords > 0; nwords--) {
		sum += *ip_pkt++;
	}
	if (len % 2 == 1) {
		sum += *((unsigned char *)ip_pkt);
	}
	sum = (sum >> 16) + (sum & 0xffff);
	return (unsigned short)(~sum);
}

static inline unsigned short zmap_ip_checksum(unsigned short *buf)
{
	return in_checksum(buf, (int)sizeof(struct ip));
}

static inline unsigned short icmp_checksum(unsigned short *buf, size_t buflen)
{
	return in_icmp_checksum(buf, buflen);
}

static inline uint16_t ipv6_payload_checksum(
	unsigned short len,
	struct in6_addr *saddr,
	struct in6_addr *daddr,
	unsigned short *w,
	unsigned char proto)
{
	unsigned long sum = 0;
	uint16_t *src_addr = (uint16_t *) saddr;
	uint16_t *dest_addr = (uint16_t *) daddr;

	// Pseudo header for IPv6+UDP
	for (int i = 0; i < 8; i++) {
		sum += src_addr[i];
	}
	for (int i = 0; i < 8; i++) {
		sum += dest_addr[i];
	}
	sum += htons(len);
	sum += htons(proto);

	// Add checksum of header and data
	while (len > 1) {
		sum += *w++;
		len -= 2;
	}

	// If 1 byte is left, we add a padding byte (0xFF) to build a 16bit word
	if (len > 0) {
		sum += *w & ntohs(0xFF00);
	}

	// Account for carries
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);

	// Take the one's complement of sum
	return (unsigned short) (~sum);
}

static inline uint16_t tcp_checksum(unsigned short len_tcp, uint32_t saddr,
				    uint32_t daddr, struct tcphdr *tcp_pkt)
{
	alias_unsigned_short *src_addr = (alias_unsigned_short *)&saddr;
	alias_unsigned_short *dest_addr = (alias_unsigned_short *)&daddr;

	unsigned char prot_tcp = 6;
	unsigned long sum = 0;
	int nleft = len_tcp;
	unsigned short *w;

	w = (unsigned short *)tcp_pkt;
	// calculate the checksum for the tcp header and tcp data
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	// if nleft is 1 there is still one byte left.
	// We add a padding byte (0xFF) to build a 16bit word
	if (nleft > 0) {
		sum += *w & ntohs(0xFF00);
	}
	// add the pseudo header
	sum += src_addr[0];
	sum += src_addr[1];
	sum += dest_addr[0];
	sum += dest_addr[1];
	sum += htons(len_tcp);
	sum += htons(prot_tcp);
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	// Take the one's complement of sum
	return (unsigned short)(~sum);
}

// Returns 0 if dst_port is outside the expected valid range, non-zero otherwise
static inline int check_dst_port(uint16_t port, int num_ports,
				 uint32_t *validation)
{
	if (port > zconf.source_port_last || port < zconf.source_port_first) {
		return 0;
	}
	int32_t to_validate = port - zconf.source_port_first;
	int32_t min = validation[1] % num_ports;
	int32_t max = (validation[1] + zconf.packet_streams - 1) % num_ports;

	if (min <= max) {
		return (to_validate <= max && to_validate >= min);
	} else {
		return ((to_validate <= max) != (to_validate >= min));
	}
}

static inline uint16_t get_src_port(int num_ports, int probe_num,
				    uint32_t *validation)
{
	return zconf.source_port_first +
	       ((validation[1] + probe_num) % num_ports);
}

static inline int check_src_port(uint16_t port, const struct port_conf *ports)
{
	return bm_check(ports->port_bitmap, port);
}

static inline struct ip *get_ip_header(const u_char *packet, uint32_t len)
{
	if (len < sizeof(struct ether_header)) {
		return NULL;
	}
	return (struct ip *)&packet[sizeof(struct ether_header)];
}

static inline struct tcphdr *get_tcp_header_ipv6(struct ip6_hdr *ipv6_hdr,
					    uint32_t len)
{

	if ((ntohs(ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen)) > len) {
		// buffer not large enough to contain expected tcp header, i.e. IPv6 payload
		return NULL;
	}
	return (struct tcphdr*) (&ipv6_hdr[1]);
}

static inline struct tcphdr *get_tcp_header(const struct ip *ip_hdr,
					    uint32_t len)
{
	// buf not large enough to contain expected udp header
	if ((4 * ip_hdr->ip_hl + sizeof(struct tcphdr)) > len) {
		return NULL;
	}
	return (struct tcphdr *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
}

static inline struct udphdr *get_udp_header_ipv6(const struct ip6_hdr *ipv6_hdr,
					    uint32_t len)
{
	if (ntohs(ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen) > len) {
		// buffer not large enough to contain expected UDP header, i.e. IPv6 payload
		return NULL;
	}
	return (struct udphdr *) &ipv6_hdr[1];
}

static inline struct udphdr *get_udp_header(const struct ip *ip_hdr,
					    uint32_t len)
{
	// buf not large enough to contain expected udp header
	if ((4 * ip_hdr->ip_hl + sizeof(struct udphdr)) > len) {
		return NULL;
	}
	return (struct udphdr *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
}

static inline struct icmp *get_icmp_header(const struct ip *ip_hdr,
					   uint32_t len)
{
	// buf not large enough to contain expected udp header
	if ((4 * ip_hdr->ip_hl + sizeof(struct icmp)) > len) {
		return NULL;
	}
	return (struct icmp *)((char *)ip_hdr + 4 * ip_hdr->ip_hl);
}

static inline uint8_t *get_udp_payload(const struct udphdr *udp,
				       UNUSED uint32_t len)
{
	return (uint8_t *)(&udp[1]);
}

static inline struct ip *get_inner_ip_header(const struct icmp *icmp,
					     uint32_t len)
{
	if (len < (ICMP_UNREACH_HEADER_SIZE + sizeof(struct ip))) {
		return NULL;
	}
	return (struct ip *)((char *)icmp + ICMP_UNREACH_HEADER_SIZE);
}

// Note: caller must free return value
char *make_ip_str(uint32_t ip);
char *make_ipv6_str(struct in6_addr *ipv6);

extern const char *icmp_unreach_strings[];

int icmp_helper_validate(const struct ip *ip_hdr, uint32_t len,
			 size_t min_l4_len, struct ip **probe_pkt,
			 size_t *probe_len);

void fs_add_null_icmp(fieldset_t *fs);

void fs_populate_icmp_from_iphdr(struct ip *ip, size_t len, fieldset_t *fs);

#endif
