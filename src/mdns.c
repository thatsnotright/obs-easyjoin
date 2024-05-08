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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <obs-module.h>
#include <plugin-support.h>
#include "mdns.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>

#define RECORD_A 1
#define RECORD_AAAA 28

int mdns_send_socket = -1;
int mdns_rx_socket = -1;
pthread_t listen_thread;

// TODO make this configurable
char* OBS_EASYJOIN_HOST_NAME = "obs-easyjoin.local.";

void* _mdns_listen();

void mdns_init() {
  struct sockaddr_in mdns_rx_addr;
	pthread_attr_t attr;
  
  bzero(&mdns_rx_addr, sizeof(mdns_rx_addr));
  mdns_rx_addr.sin_family = AF_INET;
  mdns_rx_addr.sin_port = htons(5353);
  mdns_rx_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	pthread_attr_init(&attr);
  if (pthread_create(&listen_thread, &attr, _mdns_listen, (void*)NULL)) {
		pthread_attr_destroy(&attr);
  	obs_log(LOG_ERROR, "mDNS failed to start listen thread");
		goto cleanup;
	}

	obs_log(LOG_INFO, "mDNS loaded successfully (version %s)",PLUGIN_VERSION);
  mdns_rx_socket = socket(AF_INET, SOCK_DGRAM, 0);
  if (setsockopt(mdns_rx_socket, SOL_SOCKET, SO_REUSEPORT, &(int){1}, sizeof(int)) < 0) {
    obs_log(LOG_ERROR, "Failed to set mDNS receive socket options");
		goto cleanup;
  }
  if (setsockopt(mdns_rx_socket, IPPROTO_IP, IP_PKTINFO, &(int){1}, sizeof(int)) < 0) {
    obs_log(LOG_ERROR, "Failed to set mDNS receive socket IP_PKTINFO options");
    goto cleanup;
  }
  if (bind(mdns_rx_socket, (struct sockaddr *)&mdns_rx_addr, sizeof(mdns_rx_addr)) < 0) {
    obs_log(LOG_ERROR, "Failed to bind mDNS receive socket");
		goto cleanup;
  }
  return;
cleanup:
	  pthread_attr_destroy(&attr);
    mdns_shutdown();
}

#define handle_error_en(en, msg) \
    do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

void mdns_shutdown() {
  if (mdns_rx_socket > -1) 
    close(mdns_rx_socket);
  if (listen_thread > 0)
    pthread_cancel(listen_thread);
  mdns_rx_socket = -1;
  listen_thread = -1;
  obs_log(LOG_INFO, "mDNS unloaded"); 
}

void* _mdns_listen() {
  int errno = 0;
  unsigned char buffer[1500];

  if ((errno = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL)) != 0) {
    obs_log(LOG_ERROR, "Failed to set mDNS listen thread cancel type");
    handle_error_en(errno, "pthread_setcanceltype");
  }
  struct msghdr* header = malloc(sizeof(struct msghdr));
  struct iovec* iov = malloc(sizeof(struct iovec));
  iov->iov_base = buffer;
  iov->iov_len = 1500;
  header->msg_iov = iov;
  header->msg_iovlen = 1;
  header->msg_name = malloc(sizeof(struct sockaddr_in));
  header->msg_namelen = sizeof(struct sockaddr_in);
  int flags = 0;

  while (1) {
    int len = recvmsg(mdns_rx_socket, header, flags);
    if (len < 0) {
      obs_log(LOG_ERROR, "Failed to receive mDNS packet");
      continue;
    }
    obs_log(LOG_DEBUG, "Received mDNS packet of length %d from %s", len, inet_ntoa(((struct sockaddr_in*)header->msg_name)->sin_addr));
    mdns_packet_header* parsed_packet = parse_packet_header(&buffer[0], len);
    if (parsed_packet->qr == 1) {
      obs_log(LOG_INFO, "Ignoring response packet");
      continue;
    }
    int offset = 12;
    parsed_mdns_question** questions = parse_dns_questions(&buffer[0], &offset, parsed_packet->qdcount, len);
    for (int i = 0; i < parsed_packet->qdcount; i++) {
      obs_log(LOG_INFO, "Question %d: %s: %d", i, questions[i]->name, questions[i]->type);
      obs_log(LOG_INFO, "Is it for us %s? %d",OBS_EASYJOIN_HOST_NAME, strncmp((char*)questions[i]->name, (char*)OBS_EASYJOIN_HOST_NAME, questions[i]->name_len) );
      if (questions[i]->type == RECORD_A && strncmp((char*)questions[i]->name, (char*)OBS_EASYJOIN_HOST_NAME, questions[i]->name_len) == 0) {
        dns_answer* answer = construct_A_answer(OBS_EASYJOIN_HOST_NAME, ((struct sockaddr_in*)header->msg_name), 120);
        int pkt_len=0;
        unsigned char* data = to_datagram(parsed_packet, /* questions, */ &answer, 1, &pkt_len);
        int send_len = 0;
        if (questions[i]->unicast_response) {
          // send to the address in the header
          if ((send_len = sendto(mdns_rx_socket, data, pkt_len, 0, header->msg_name, header->msg_namelen)) == -1) {
            obs_log(LOG_ERROR, "Failed to send mDNS response %d", send_len);
          }
        } else {
          // send to the multicast address
          struct sockaddr_in mdns_addr;
          bzero(&mdns_addr, sizeof(mdns_addr));
          mdns_addr.sin_family = AF_INET;
          mdns_addr.sin_port = htons(5353);
          mdns_addr.sin_addr.s_addr = inet_addr("224.0.0.251");
          if ((send_len = sendto(mdns_rx_socket, data, pkt_len, 0, (struct sockaddr*)&mdns_addr, sizeof(struct sockaddr_in))) == -1) {
            obs_log(LOG_ERROR, "Failed to send mDNS response %d", send_len);
          }
        }  
        free(data);
        free_dns_answer(answer);
      }
    }
    free_parsed_mdns_question(questions, parsed_packet->qdcount);
    free_mdns_packet_header(parsed_packet);
   }
 return NULL;
}
/*
*  int offset = 12;
  parsed_packet->questions = parse_dns_questions(packet, &offset, parsed_packet->header->qdcount, length);
 */
mdns_packet_header* parse_packet_header(unsigned char* packet, int length) {
  mdns_packet_header* parsed_packet = malloc(length);
  parsed_packet = malloc(sizeof(mdns_packet_header));
  parsed_packet->id = ntohs(*(unsigned short*)&packet[0]);
  parsed_packet->qr = ntohs(*(unsigned short*)&packet[2]) >> 15; 
  parsed_packet->opcode = (ntohs(*(unsigned short*)&packet[2]) >> 11) & 0xf;
  parsed_packet->aa = (ntohs(*(unsigned short*)&packet[2]) >> 10) & 0x1;
  parsed_packet->tc = (ntohs(*(unsigned short*)&packet[2]) >> 9) & 0x1;
  parsed_packet->rd = (ntohs(*(unsigned short*)&packet[2]) >> 8) & 0x1;
  parsed_packet->ra = (ntohs(*(unsigned short*)&packet[2]) >> 7) & 0x1;
  parsed_packet->z = (ntohs(*(unsigned short*)&packet[2]) >> 4) & 0x7;
  parsed_packet->rcode = ntohs(*(unsigned short*)&packet[2]) & 0xf;
  parsed_packet->qdcount = ntohs(*(unsigned short*)&packet[4]);
  parsed_packet->ancount = ntohs(*(unsigned short*)&packet[6]);
  parsed_packet->nscount = ntohs(*(unsigned short*)&packet[8]);
  parsed_packet->arcount = ntohs(*(unsigned short*)&packet[10]);
  
  return parsed_packet;
}

parsed_mdns_question** parse_dns_questions(unsigned char* packet, int* offset, int count, int length) {
  int start = *offset;
  parsed_mdns_question** questions = malloc(sizeof(parsed_mdns_question*) * count);
  for (int i = 0; i < count && start+i < length; i++) {
    parsed_mdns_question* question = malloc(sizeof(parsed_mdns_question));
    questions[i] = question;
    question->name = malloc(1);
    question->name_len = 0;

    while(packet[*offset] != 0) {
      int label_len = packet[*offset];
      (*offset)++;
      if (label_len > 0) {
        question->name = realloc(question->name, question->name_len + label_len + 1);
        memcpy(&question->name[question->name_len], &packet[*offset], label_len);
        question->name[question->name_len + label_len] = '.';
        question->name_len += label_len + 1;
      } else {
        question->name[0] = 0;
        question->name_len = 1;
      }
      *offset += label_len;
    }
    question->name[question->name_len] = '\0';
    (*offset)++;
    question->type = ntohs(*(unsigned short*)&packet[*offset]);
    (*offset) += 2;
    question->unicast_response = 0;
    question->class = ntohs(*(unsigned short*)&packet[*offset]);
    (*offset) += 2;
  }
  return questions;
}

void free_mdns_packet_header(mdns_packet_header* packet) {
  free(packet);
}

dns_answer* construct_A_answer(char* name, sockaddr_in* addr, unsigned int ttl) {
  dns_answer* answer = malloc(sizeof(dns_answer));
  answer-> name = malloc(strnlen((const char*)name, 64) + 1);
  size_t name_offset = 0;
  int name_len = 0;
  int label_offset = 0;
  while(name_offset < strnlen((char*)name, 64)) {
    int label_len = 0;
    while(name[label_offset + label_len] != '.' && name[label_offset + label_len] != '\0') {
      label_len++;
    }
    if (label_len == 0) {
      break;
    }
    name_len += label_len + 1;
    answer->name = realloc(answer->name, name_len);
    answer->name[label_offset] = label_len;
    memcpy(&answer->name[label_offset+1], &name[label_offset], label_len);
    label_offset += label_len + 1;
    name_offset += label_len+1; // skip the dot or length byte
  }
  answer->name_len = name_len + 1;
  answer->name = realloc(answer->name, name_len + 1);
  answer->name[name_len] = 0;
  answer->type = htons(DNS_RECORD_TYPE_A);
  answer->class = htons(1);
  answer->ttl = htonl(ttl);
  answer->rdlength = htons(sizeof(struct in_addr));
  answer->rdata = malloc(sizeof(struct in_addr));
  memcpy(answer->rdata, &addr->sin_addr, sizeof(struct in_addr));
  return answer;
}

dns_answer* construct_AAAA_answer(char* name, sockaddr_in6* addr, unsigned int ttl) {
  dns_answer* answer = malloc(sizeof(dns_answer)); 
  answer->name = malloc(strnlen((const char*)name, 64) + 1);
  size_t name_offset = 0;
  int name_len = 0;
  while(name_offset < strnlen((char*)name, 64)) {
    int label_len = 0;
    while(name[name_offset] != '.' && name[name_offset] != '\0') {
      label_len++;
      name_offset++;
    }
    name_len += label_len + 1;
    answer->name = realloc(answer->name, label_len + 1);
    answer->name[label_len] = label_len;
    memcpy(&answer->name[name_offset], &name[name_offset], label_len);
    answer->name[label_len] = name[name_offset];
    name_offset++; // skip the dot or length byte
  }
  answer->name_len = htons(name_len);
  answer->type = htons(DNS_RECORD_TYPE_AAAA);
  answer->class = htons(1);
  answer->ttl = htons(ttl);
  answer->rdlength = htons(sizeof(sockaddr_in6));
  answer->rdata = malloc(sizeof(sockaddr_in6));
  memcpy(answer->rdata, addr, sizeof(sockaddr_in6));
  return answer;
}

mdns_packet_header* create_header(unsigned short id) {
  mdns_packet_header* packet = malloc(sizeof(mdns_packet_header)); 
  packet->id = htons(id);
  packet->qr = 0;
  packet->opcode = 0;
  packet->aa = 0;
  packet->tc = 0;
  packet->rd = htons(1);
  packet->ra = 0;
  packet->z = 0;
  packet->rcode = 0;
  packet->qdcount = 0;
  packet->ancount = 0;
  packet->nscount = 0;
  packet->arcount = 0;
  return packet;
}

unsigned char* to_datagram(mdns_packet_header* packet,/* TODO parsed_mdns_question** _questions,*/ dns_answer** answers, int answer_count, int* length) {
  unsigned char* buffer = malloc(1500);
  int offset = 0;
  packet->ancount = answer_count;
  *(unsigned short*)&buffer[offset] = htons(packet->id);
  offset += 2;
  packet->qr = 1;
  packet->aa = 1;
  *(unsigned short*)&buffer[offset] = htons((packet->qr << 15) | (packet->opcode << 11) | (packet->aa << 10) | (packet->tc << 9) | (packet->rd << 8) | (packet->ra << 7) | (packet->z << 4) | packet->rcode);
  offset += 2;
  *(unsigned short*)&buffer[offset] = 0;
  offset += 2;
  *(unsigned short*)&buffer[offset] = htons(packet->ancount);
  offset += 2;
  *(unsigned short*)&buffer[offset] = htons(packet->nscount);
  offset += 2;
  *(unsigned short*)&buffer[offset] = htons(packet->arcount);
  offset += 2;
/*  printf("qdcount %d\n", packet->qdcount);
  for (int i = 0; i < packet->qdcount; i++) {
    parsed_mdns_question* question = questions[i];
    int name_offset = 0;
    while(name_offset < question->name_len) {
      int label_len = 0;
      int label_offset = 0;
      while(question->name[name_offset + label_len] != '.' && question->name[name_offset + label_len] != '\0') {
        label_len++;
      }
      if (label_len == 0) {
        break;
      }
      buffer[offset] = label_len;
      memcpy(&buffer[offset + 1], &question->name[name_offset], label_len);
      label_offset += label_len + 1;
      name_offset += label_len+1; // skip the dot or length byte
      offset += label_offset;
    }
    buffer[offset] = 0;
    offset ++;
    *(unsigned short*)&buffer[offset] = htons(question->type);
    offset += 2;
    *(unsigned short*)&buffer[offset] = htons(question->class);
    offset += 2;
  }*/
  for (int i = 0; i < answer_count; i++) {
    dns_answer* answer = answers[i];
    memcpy(&buffer[offset], answer->name, answer->name_len);
    offset += answer->name_len;
    *(unsigned short*)&buffer[offset] = answer->type;
    offset += 2;
    *(unsigned short*)&buffer[offset] = answer->class;
    offset += 2;
    *(unsigned int*)&buffer[offset] = (answer->ttl);
    offset += 4;
    int len = ntohs(answer->rdlength);
    *(unsigned short*)&buffer[offset] = answer->rdlength;
    offset += 2;
    memcpy(&buffer[offset], answer->rdata, len);
    offset += len;
  }
  *length = offset;
  return buffer;
}

void free_dns_answer(dns_answer* answer) {
  free(answer->name);
  free(answer->rdata);
  free(answer);
}

void free_dns_question(dns_question* question) {
  free(question->qname);
  free(question);
}

void free_parsed_mdns_question(parsed_mdns_question** question, int count) {
  for (int i = 0; i < count; i++) {
    free(question[i]->name);
  }
  free(question);
}
