/*
OBS EasyJoin
Copyright (C) 2024 Rob Elsner rob@elsner.dev 

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program. If not, see <https://www.gnu.org/licenses/>
*/

#pragma once

#include <arpa/inet.h>
#include <unistd.h>

#define DNS_RECORD_TYPE_A 1
#define DNS_RECORD_TYPE_AAAA 28
#define DNS_RECORD_TYPE_PTR 12

typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr_in6 sockaddr_in6;

typedef struct mdns_packet_header {
	unsigned short id;
	unsigned int qr : 1;
	unsigned int opcode : 4;
	unsigned int aa : 1;
	unsigned int tc : 1;
	unsigned int rd : 1;
	unsigned int ra : 1;
	unsigned int z : 3;
	unsigned int rcode : 4;
	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;
} __attribute__((packed)) mdns_packet_header;

typedef struct dns_question {
	char *qname; // [len][label][len][...][0]
	unsigned short qtype;
	unsigned short qclass;
} __attribute__((packed)) dns_question;

typedef struct dns_answer {
	char *name;
	int name_len;
	unsigned short type;
	unsigned short class;
	unsigned int ttl;
	unsigned short rdlength;
	unsigned char *rdata;
} dns_answer;

typedef struct parsed_mdns_question {
	unsigned char name_len;
	unsigned char *name;
	unsigned short type;
	unsigned char unicast_response;
	unsigned short class;
} parsed_mdns_question;

dns_answer *construct_A_answer(char *, sockaddr_in *, unsigned int);
dns_answer *construct_AAAA_answer(char *, sockaddr_in6 *, unsigned int);
void mdns_init(void);
void mdns_shutdown(void);
parsed_mdns_question **parse_dns_questions(unsigned char *, int *, int, int);
mdns_packet_header *parse_packet_header(unsigned char *, int);
void free_mdns_packet_header(mdns_packet_header *);
void free_dns_answer(dns_answer *);
void free_dns_question(dns_question *);
void free_parsed_mdns_question(parsed_mdns_question **, int count);
mdns_packet_header *create_header(unsigned short);
unsigned char *to_datagram(mdns_packet_header *,
			   /* TODO parsed_mdns_question**, */ dns_answer **,
			   int, int *);
