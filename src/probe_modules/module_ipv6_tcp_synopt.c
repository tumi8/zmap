/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing TCP SYN OPT scans over IPv6
// based on TCP SYN module, with changes by Quirin Scheitle and Markus Sosnowski

// Needed for asprintf
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../../lib/includes.h"
#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"
#include "../../lib/xalloc.h"
#include "logger.h"

#include "module_tcp_synopt.h"


probe_module_t module_ipv6_tcp_synopt;
static uint32_t num_ports;

#define MAX_OPT_LEN 40
#define ZMAPV6_TCP_SYNOPT_TCP_HEADER_LEN 20
#define ZMAPV6_TCP_SYNOPT_PACKET_LEN 74
#define SOURCE_PORT_VALIDATION_MODULE_DEFAULT true; // default to validating source port
static bool should_validate_src_port = SOURCE_PORT_VALIDATION_MODULE_DEFAULT


static char *tcp_send_opts = NULL;
static int tcp_send_opts_len = 0;


int ipv6_tcp_synopt_global_initialize(struct state_conf *conf)
{
	// code partly copied from UDP module
	char *args, *c;
	int i;
	unsigned int n;

	num_ports = conf->source_port_last - conf->source_port_first + 1;

	// Only look at received packets destined to the specified scanning address (useful for parallel zmap scans)
	if (asprintf((char ** restrict) &module_ipv6_tcp_synopt.pcap_filter, "%s && ip6 dst host %s", module_ipv6_tcp_synopt.pcap_filter, conf->ipv6_source_ip) == -1) {
		return 1;
	}

	if (!(conf->probe_args && strlen(conf->probe_args) > 0)){
		printf("no args, using empty tcp options\n");
		module_ipv6_tcp_synopt.max_packet_length = ZMAPV6_TCP_SYNOPT_PACKET_LEN;
		return(EXIT_SUCCESS);
	}
	args = strdup(conf->probe_args);
	if (! args) exit(1);

	c = strchr(args, ':');
	if (! c) {
		free(args);
		//free(udp_send_msg);
		printf("tcp synopt usage error\n");
		exit(1);
	}

	*c++ = 0;

	if (strcmp(args, "hex") == 0) {
		tcp_send_opts_len = strlen(c) / 2;
		if(strlen(c)/2 %4 != 0){
			printf("tcp options are not multiple of 4, please pad with NOPs (0x01)!\n");
			exit(1);
		}
		free(tcp_send_opts);
		tcp_send_opts = xmalloc(tcp_send_opts_len);

		for (i=0; i < tcp_send_opts_len; i++) {
			if (sscanf(c + (i*2), "%2x", &n) != 1) {
				free(tcp_send_opts);
				log_fatal("udp", "non-hex character: '%c'", c[i*2]);
				free(args);
				exit(1);
			}
			tcp_send_opts[i] = (n & 0xff);
		}
	} else {
		printf("options given, but not hex, exiting!");
		exit(1);
	}
	if (tcp_send_opts_len > MAX_OPT_LEN) {
		log_warn("udp", "warning: exiting - too long option!\n");
		tcp_send_opts_len = MAX_OPT_LEN;
		exit(1);
	}
	module_ipv6_tcp_synopt.max_packet_length = ZMAPV6_TCP_SYNOPT_PACKET_LEN + tcp_send_opts_len;

	return EXIT_SUCCESS;
}

static int ipv6_tcp_synopt_prepare_packet(void *buf, macaddr_t *src, macaddr_t *gw,
				  UNUSED void *arg_ptr)
{
	struct ether_header *eth_header = (struct ether_header *) buf;
	make_eth_header_ethertype(eth_header, src, gw, ETHERTYPE_IPV6);
	struct ip6_hdr *ip6_header = (struct ip6_hdr*)(&eth_header[1]);
	uint16_t payload_len = ZMAPV6_TCP_SYNOPT_TCP_HEADER_LEN+tcp_send_opts_len;
	make_ip6_header(ip6_header, IPPROTO_TCP, payload_len);
	struct tcphdr *tcp_header = (struct tcphdr*)(&ip6_header[1]);
	make_tcp_header(tcp_header, TH_SYN);
	return EXIT_SUCCESS;
}

int ipv6_tcp_synopt_make_packet(void *buf, size_t *buf_len, __attribute__((unused)) ipaddr_n_t src_ip, __attribute__((unused)) ipaddr_n_t dst_ip, port_n_t dport, 
        uint8_t ttl, uint32_t *validation, int probe_num, UNUSED uint16_t ip_id, void *arg)
{
	struct ether_header *eth_header = (struct ether_header *) buf;
	struct ip6_hdr *ip6_header = (struct ip6_hdr*) (&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr*) (&ip6_header[1]);
	unsigned char* opts = (unsigned char*)&tcp_header[1];
	uint32_t tcp_seq = validation[0];
	ip6_header->ip6_src = ((struct in6_addr *) arg)[0];
	ip6_header->ip6_dst = ((struct in6_addr *) arg)[1];
	ip6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = ttl;

	tcp_header->th_sport = htons(get_src_port(num_ports,
				probe_num, validation));
	tcp_header->th_dport = dport;
	tcp_header->th_seq = tcp_seq;

    memcpy(opts, tcp_send_opts, tcp_send_opts_len);

    tcp_header->th_off = 5+tcp_send_opts_len/4; // default length = 5 + 9*32 bit options


	tcp_header->th_sum = 0;

	unsigned short len_tcp = ZMAPV6_TCP_SYNOPT_TCP_HEADER_LEN+tcp_send_opts_len;

	tcp_header->th_sum = ipv6_payload_checksum(len_tcp, &ip6_header->ip6_src, &ip6_header->ip6_dst, (unsigned short *) tcp_header, IPPROTO_TCP);

	*buf_len = ZMAPV6_TCP_SYNOPT_PACKET_LEN+tcp_send_opts_len;

	return EXIT_SUCCESS;
}

void ipv6_tcp_synopt_print_packet(FILE *fp, void* packet)
{
	struct ether_header *ethh = (struct ether_header *) packet;
	struct ip6_hdr *iph = (struct ip6_hdr *) &ethh[1];
	struct tcphdr *tcph = (struct tcphdr *) &iph[1];
	fprintf(fp, "tcp { source: %u | dest: %u | seq: %u | checksum: %#04X }\n",
			ntohs(tcph->th_sport),
			ntohs(tcph->th_dport),
			ntohl(tcph->th_seq),
			ntohs(tcph->th_sum));
	fprintf_ipv6_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

int ipv6_tcp_synopt_validate_packet(const struct ip *ip_hdr, uint32_t len,
		__attribute__((unused))uint32_t *src_ip,
		uint32_t *validation,
		const struct port_conf *ports)
{
	struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *) ip_hdr;

	if (ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP) {
		return PACKET_INVALID;
	}
	if ((ntohs(ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen)) > len) {
		// buffer not large evnough to contain expected tcp header, i.e. IPv6 payload
		return PACKET_INVALID;
	}
	struct tcphdr *tcp_hdr = (struct tcphdr*) (&ipv6_hdr[1]);
	port_h_t sport = ntohs(tcp_hdr->th_sport);
	port_h_t dport = ntohs(tcp_hdr->th_dport);
	// validate source port
	if (should_validate_src_port && !check_src_port(sport, ports)) {
		return PACKET_INVALID;
	}
	// validate destination port
	if (!check_dst_port(dport, num_ports, validation)) {
		return 0;
	}
	// validate tcp acknowledgement number
	if (htonl(tcp_hdr->th_ack) != htonl(validation[0]) + 1) {
		return PACKET_INVALID;
	}
	return PACKET_VALID;
}

void ipv6_tcp_synopt_process_packet(const u_char *packet,
		__attribute__((unused)) uint32_t len, fieldset_t *fs,
		__attribute__((unused)) uint32_t *validation,
		 __attribute__((unused)) struct timespec ts)
{
	struct ether_header *eth_hdr = (struct ether_header *) packet;
	struct ip6_hdr *ipv6_hdr = (struct ip6_hdr *) (&eth_hdr[1]);
	struct tcphdr *tcp_hdr = (struct tcphdr*) (&ipv6_hdr[1]);
	//	unsigned int optionbytes2=len-(sizeof(struct ether_header)+ntohs(ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen) + sizeof(struct tcphdr));
	unsigned int optionbytes2=len-(sizeof(struct ether_header)+sizeof(struct ip6_hdr) + sizeof(struct tcphdr));
	tcpsynopt_process_packet_parse(len, fs,tcp_hdr,optionbytes2);
	return;
}

probe_module_t module_ipv6_tcp_synopt = {
	.name = "ipv6_tcp_synopt",
	.max_packet_length = ZMAPV6_TCP_SYNOPT_PACKET_LEN, // will be extended at runtime
	.pcap_filter = "ip6 proto 6 && (ip6[53] & 4 != 0 || ip6[53] == 18)",
	.pcap_snaplen = 116+10*4, // max option len
	.port_args = 1,
	.global_initialize = &ipv6_tcp_synopt_global_initialize,
	.prepare_packet = &ipv6_tcp_synopt_prepare_packet,
	.make_packet = &ipv6_tcp_synopt_make_packet,
	.print_packet = &ipv6_tcp_synopt_print_packet,
	.process_packet = &ipv6_tcp_synopt_process_packet,
	.validate_packet = &ipv6_tcp_synopt_validate_packet,
	.close = NULL,
	.helptext = "Probe module that sends an IPv6+TCP SYN packet to a specific "
		"port. Possible classifications are: synack and rst. A "
		"SYN-ACK packet is considered a success and a reset packet "
		"is considered a failed response.",
	.fields = fields,
	.numfields = sizeof(fields)/sizeof(fields[0])
	};
//	.numfields = 10};


