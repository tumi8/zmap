/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef VALIDATE_H
#define VALIDATE_H

#include <netinet/in.h>

#define VALIDATE_BYTES 16

void validate_init(void);
void validate_gen(const uint32_t src, const uint32_t dst, const uint16_t dst_port, uint8_t output[VALIDATE_BYTES]);
void validate_gen_ipv6(const struct in6_addr *src, const struct in6_addr *dst, const uint16_t dst_port, uint8_t output[VALIDATE_BYTES]);
void validate_gen_ex(const uint32_t input0, const uint32_t input1,
		     const uint32_t input2, const uint32_t input3,
		     uint8_t output[VALIDATE_BYTES]);

#endif //_VALIDATE_H
