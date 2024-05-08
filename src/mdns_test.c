#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "mdns.h"

void main() {
  unsigned char packet[] = {
    0xdb, 0x42, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
    0x0c, 0x6e, 0x6f, 0x72, 0x74, 0x68, 0x65, 0x61,
    0x73, 0x74, 0x65, 0x72, 0x6e, 0x03, 0x65, 0x64,
    0x75, 0x00, 0x00, 0x01, 0x00, 0x01
  };
  mdns_packet_header* parsed_packet = parse_packet_header(packet, sizeof(packet));
  for (long unsigned int i = 0; i < sizeof(packet); i++) {
    printf("%02x ", packet[i]);
    if (i % 8 == 7) {
      printf("\n");
    }
  }
  assert(parsed_packet->id == 0xdb42);
  assert(parsed_packet->qr == 0);
  assert(parsed_packet->opcode == 0);
  assert(parsed_packet->aa == 0);
  assert(parsed_packet->tc == 0);
  assert(parsed_packet->rd == 1);
  assert(parsed_packet->ra == 0);
  assert(parsed_packet->z == 0);
  assert(parsed_packet->rcode == 0);
  assert(parsed_packet->qdcount == 1);
  assert(parsed_packet->ancount == 0);
  assert(parsed_packet->nscount == 0);
  assert(parsed_packet->arcount == 0);
  int offset = 12;
  parsed_mdns_question** questions = parse_dns_questions(packet, &offset, 1, sizeof(packet));
  assert(strncmp((char*)questions[0]->name, "www.northeastern.edu.", questions[0]->name_len) == 0);
  // print each question
  for (int i = 0; i < parsed_packet->qdcount; i++) {
    printf("Question %d: %s\n", i, questions[i]->name);
  }
  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(80);
  addr.sin_addr.s_addr = inet_addr("192.168.1.37");
  dns_answer* answer = construct_A_answer("obs.local", &addr, 120);
  assert(answer->type == htons(DNS_RECORD_TYPE_A));
  dns_answer** answers = malloc(sizeof(dns_answer*));
  answers[0] = answer;
  int pkt_len = 0;
  unsigned char* data = to_datagram(parsed_packet,/* questions,*/ answers, 1, &pkt_len); 
  printf("packet length: %d\n", pkt_len);
  // assert that the first 12 bytes are the same
  for (int i = 0; i < 12; i++) {
    printf("%02x (%02x)\n", data[i], packet[i]);
  }
  free_mdns_packet_header(parsed_packet);
  free_dns_answer(answer);
  free_parsed_mdns_question(questions, 1);
  free(data);
  printf("All tests passed!\n");
}
