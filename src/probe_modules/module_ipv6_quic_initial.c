
/*
 * Jan Rüth 2018, Philippe Buschmann 2021, Johannes Zirngibl 2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 */

/* module to perform IETF QUIC (draft-32) enumeration */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "../../lib/blocklist.h"
#include "../../lib/includes.h"
#include "../../lib/xalloc.h"
#include "../../lib/lockfd.h"
#include "logger.h"
#include "probe_modules.h"
#include "packet.h"
#include "aesrand.h"
#include "state.h"
#include "module_udp.h"
#include "module_quic_initial.h"

#define UNUSED __attribute__((unused))

static int padding_length = QUIC_PACKET_LENGTH - sizeof(quic_long_hdr);

static inline uint64_t ipv6_make_quic_conn_id(char a, char b, char c, char d, char e,
					 char f, char g, char h)
{
	return (uint64_t)(a) | (uint64_t)(b) << 8 | (uint64_t)(c) << 16 |
	       (uint64_t)(d) << 24 | (uint64_t)(e) << 32 | (uint64_t)(f) << 40 |
	       (uint64_t)(g) << 48 | (uint64_t)(h) << 56;
}

static int num_ports;

probe_module_t module_ipv6_quic_initial;
static char filter_rule[30];
uint64_t connection_id_v6;

void ipv6_quic_initial_set_num_ports(int x) { num_ports = x; }

int ipv6_quic_initial_global_initialize(struct state_conf *conf){
	char *args = NULL;

	if (conf->probe_args != NULL) {
		args = strdup(conf->probe_args);
	}

    // Only look at received packets destined to the specified scanning address (useful for parallel zmap scans)
    if (asprintf((char ** restrict) &module_ipv6_quic_initial.pcap_filter, "%s && ip6 dst host %s", module_ipv6_quic_initial.pcap_filter, conf->ipv6_source_ip) == -1) {
        return 1;
    }


	if (args != NULL) {
		if (strncmp(args, "padding:", strlen("padding:")) == 0) {
			char *padding_string = strtok(args, ":");
			// get part after colon
			padding_string = strtok(NULL, ":");
			int num = atoi(padding_string);
			padding_length = num;
		}
	}

	num_ports = conf->source_port_last - conf->source_port_first + 1;

	char port[16];
	sprintf(port, "%d", conf->target_port);
	// answers have the target port as source
	memcpy(filter_rule, "udp src port \0", 14);

	module_ipv6_quic_initial.pcap_filter = strncat(filter_rule, port, 16);
	// set length of pcap
	module_ipv6_quic_initial.pcap_snaplen =
	    sizeof(struct ether_header) + sizeof(struct ip6_hdr) +
	    sizeof(struct udphdr) + QUIC_PACKET_LENGTH;

	connection_id_v6 =
	    ipv6_make_quic_conn_id('S', 'C', 'A', 'N', 'N', 'I', 'N', 'G');

	if (args != NULL) {
		free(args);
	}
	return EXIT_SUCCESS;
}

int ipv6_quic_initial_global_cleanup(
    __attribute__((unused)) struct state_conf *zconf,
    __attribute__((unused)) struct state_send *zsend,
    __attribute__((unused)) struct state_recv *zrecv)
{
	return EXIT_SUCCESS;
}

int ipv6_quic_initial_init_perthread(void *buf, macaddr_t *src, macaddr_t *gw,
				__attribute__((unused)) port_h_t dst_port,
				__attribute__((unused)) void **arg_ptr)
{
	// set length of udp msg
	int udp_send_msg_len = padding_length + sizeof(quic_long_hdr);
	//log_debug("prepare", "UDP PAYLOAD LEN: %d", udp_send_msg_len);

	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *)buf;
	make_eth_header_ethertype(eth_header, src, gw, ETHERTYPE_IPV6);
    struct ip6_hdr *ip6_header = (struct ip6_hdr*)(&eth_header[1]);
	uint16_t len =
	    htons(sizeof(struct ip6_hdr) + sizeof(struct udphdr) + udp_send_msg_len);
	//log_debug("prepare", "IP LEN IN HEX %h", len);
	make_ip6_header(ip6_header, IPPROTO_UDP, len);

	struct udphdr *udp_header = (struct udphdr *)(&ip6_header[1]);
	len = sizeof(struct udphdr) + udp_send_msg_len;
	make_udp_header(udp_header, zconf.target_port, len);

	char *payload = (char *)(&udp_header[1]);

	module_ipv6_quic_initial.max_packet_length =
	    sizeof(struct ether_header) + sizeof(struct ip6_hdr) +
	    sizeof(struct udphdr) + udp_send_msg_len;
	assert(module_ipv6_quic_initial.max_packet_length <= MAX_PACKET_SIZE);
	memset(payload, 0, udp_send_msg_len);

	return EXIT_SUCCESS;
}

int ipv6_quic_initial_make_packet(void *buf, size_t *buf_len,
			     ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
			     UNUSED uint8_t ttl, uint32_t *validation,
			     int probe_num, UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *)buf;
	struct ip6_hdr *ip6_header = (struct ip6_hdr *)(&eth_header[1]);
	struct udphdr *udp_header = (struct udphdr *)&ip6_header[1];

    ip6_header->ip6_src = ((struct in6_addr *) arg)[0];
    ip6_header->ip6_dst = ((struct in6_addr *) arg)[1];
    ip6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = ttl;

	udp_header->uh_sport =
	    htons(get_src_port(num_ports, probe_num, validation));

	uint8_t *payload = (uint8_t *)&udp_header[1];
	int payload_len = 0;

	memset(payload, 0, padding_length + sizeof(quic_long_hdr));

	quic_long_hdr *common_hdr = (quic_long_hdr *)payload;

	// set header flags
	uint8_t protected_header_flags =
	    HEADER_FLAG_RESERVED_BITS | HEADER_FLAG_PACKET_NUMBER_LENGTH;
	uint8_t public_header_flags = HEADER_FLAG_FORM_LONG_HEADER |
				      HEADER_FLAG_FIXED_BIT |
				      HEADER_FLAG_TYPE_INITIAL;
	common_hdr->header_flags = protected_header_flags | public_header_flags;
	common_hdr->version = QUIC_VERSION_FORCE_NEGOTIATION;
	common_hdr->dst_conn_id_length = HEADER_CONNECTION_ID_LENGTH;
	common_hdr->dst_conn_id = connection_id_v6;
	common_hdr->src_conn_id_length = 0x00;
	common_hdr->token_length = 0x00;
	common_hdr->length = padding_length + sizeof(common_hdr->packet_number);
	common_hdr->packet_number = 0x0000;

	// Padding was already done with memset
	payload_len = padding_length + sizeof(quic_long_hdr);

	// Update the IP and UDP headers to match the new payload length
	ip6_header->ip6_ctlun.ip6_un1.ip6_un1_plen =
	    htons(sizeof(struct udphdr) + payload_len);
	udp_header->uh_ulen = ntohs(sizeof(struct udphdr) + payload_len);

	udp_header->uh_sum = 0;
	udp_header->uh_sum = ipv6_payload_checksum(ntohs(udp_header->uh_ulen), &ip6_header->ip6_src, &ip6_header->ip6_dst, (unsigned short *) udp_header, IPPROTO_UDP);

	size_t headers_len = sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct udphdr);
	*buf_len = headers_len + payload_len;

	return EXIT_SUCCESS;
}

void ipv6_quic_initial_print_packet(FILE *fp, void *packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip6_hdr *iph = (struct ip6_hdr *)&ethh[1];
	struct udphdr *udph = (struct udphdr *)(&iph[1]);
	fprintf(fp, "udp { source: %u | dest: %u | checksum: %#04X }\n",
		ntohs(udph->uh_sport), ntohs(udph->uh_dport),
		ntohs(udph->uh_sum));
	fprintf_ipv6_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

void ipv6_quic_initial_process_packet(const u_char *packet, UNUSED uint32_t len,
				 fieldset_t *fs, UNUSED uint32_t *validation,
				 __attribute__((unused)) struct timespec ts)
{
	struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *) &packet[sizeof(struct ether_header)];
	if (ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr*) &ipv6_hdr[1];

		// Verify that the UDP length is big enough for the header and at least one byte
		uint16_t data_len = ntohs(udp->uh_ulen);
		if (data_len > sizeof(struct udphdr)) {
			uint8_t *payload = (uint8_t *)&udp[1];
			if (data_len > (sizeof(quic_version_negotiation_hdr) +
					sizeof(struct udphdr))) {
				quic_version_negotiation_hdr
				    *quic_version_negotiation =
					(quic_version_negotiation_hdr *)payload;
				if (quic_version_negotiation->version ==
					QUIC_VERSION_VERSION_NEGOTIATION &&
				    quic_version_negotiation
					    ->dst_conn_id_length == 0x00 &&
				    quic_version_negotiation
					    ->src_conn_id_length == 0x08 &&
				    quic_version_negotiation->src_conn_id ==
					connection_id_v6) {
					fs_add_string(fs, "classification",
						      (char *)"quic", 0);
					fs_add_uint64(fs, "success", 1);
					int supported_version_length =
					    (data_len -
					     (sizeof(
						  quic_version_negotiation_hdr) +
					      sizeof(struct udphdr))) /
					    4;
					if (supported_version_length > 0) {
						uint8_t *supported_version =
						    (uint8_t
							 *)&quic_version_negotiation
							[1];
						// (4 * 2) representation of 4 bytes as hex in string + 1 space
						int output_string_len =
						    supported_version_length *
							((4 * 2) + 1) +
						    1;
						char *versions =
						    malloc(output_string_len *
							   sizeof(char));
						for (int i = 0;
						     i <
						     supported_version_length;
						     i++) {
							int string_index =
							    9 * i;
							int supported_version_index =
							    4 * i;
							snprintf(
							    (versions +
							     string_index),
							    11,
							    "%02x%02x%02x%02x ",
							    *(supported_version +
							      supported_version_index),
							    *(supported_version +
							      supported_version_index +
							      1),
							    *(supported_version +
							      supported_version_index +
							      2),
							    *(supported_version +
							      supported_version_index +
							      3));
						}
						fs_add_string(fs, "versions",
							      versions, 1);
					}
				} else if (quic_version_negotiation->version ==
					   QUIC_VERSION_FORCE_NEGOTIATION) {
					// if version number not zero'd, the response is probably from a udp echo server
					fs_add_string(fs, "classification",
						      (char *)"udp", 0);
					fs_add_uint64(fs, "success", 0);
				}
			}
		} else {
			fs_add_string(fs, "classification", (char *)"udp", 0);
			fs_add_uint64(fs, "success", 0);
		}
	}
}

int ipv6_quic_initial_validate_packet(const struct ip *ip_hdr, uint32_t len,
				 __attribute__((unused)) uint32_t *src_ip,
				 UNUSED uint32_t *validation)
{
    struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *) ip_hdr;

	// We only want to process UDP datagrams
	if (ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_UDP) {
		return PACKET_INVALID;
	}
	if ((ntohs(ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen)) > len) {
		// buffer not large enough to contain expected udp header
		return PACKET_INVALID;
	}
	struct udphdr *udp =
	    (struct udphdr *) (&ipv6_hdr[1]);
	uint16_t sport = ntohs(udp->uh_dport);
	if (!check_dst_port(sport, num_ports, validation)) {
		return PACKET_INVALID;
	}
	return PACKET_VALID;
}

static fielddef_t fields[] = {
    {.name = "classification",
     .type = "string",
     .desc = "packet classification"},
    {.name = "success",
     .type = "int",
     .desc = "is response considered success"},
    {.name = "versions", .type = "string", .desc = "versions if reported"}};

probe_module_t module_ipv6_quic_initial = {
    .name = "ipv6_quic_initial",
    // we are resetting the actual packet length during initialization of the module
    .max_packet_length = sizeof(struct ether_header) + sizeof(struct ip6_hdr) +
		     sizeof(struct udphdr) + QUIC_PACKET_LENGTH,
    // this gets replaced by the actual port during global init
    .pcap_filter = "udp",
    // this gets replaced by the actual payload we expect to get back
    .pcap_snaplen = 1500,
    .port_args = 1,
    .thread_initialize = &ipv6_quic_initial_init_perthread,
    .global_initialize = &ipv6_quic_initial_global_initialize,
    .make_packet = &ipv6_quic_initial_make_packet,
    .print_packet = &ipv6_quic_initial_print_packet,
    .validate_packet = &ipv6_quic_initial_validate_packet,
    .process_packet = &ipv6_quic_initial_process_packet,
    .close = &ipv6_quic_initial_global_cleanup,
    .helptext = "Probe module that sends QUIC CHLO packets to hosts.",
    .fields = fields,
    .numfields = sizeof(fields) / sizeof(fields[0])};
