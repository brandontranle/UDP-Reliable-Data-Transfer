#pragma once

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

// Maximum payload size
#define MAX_PAYLOAD 1012

// Retransmission time
#define TV_DIFF(end, start)                                                    \
    (end.tv_sec * 1000000) - (start.tv_sec * 1000000) + end.tv_usec -          \
        start.tv_usec
#define RTO 1000000
#define MIN(a, b) (a > b ? b : a)
#define MAX(c, d) (c > d ? c : d)

// Window size
#define MIN_WINDOW MAX_PAYLOAD
#define MAX_WINDOW MAX_PAYLOAD * 40
#define DUP_ACKS 3

// States
#define SERVER 0
#define CLIENT 1

// Flags
#define SYN 0b001
#define ACK 0b010
#define PARITY 0b100

// Diagnostic messages
#define RECV 0
#define SEND 1
#define RTOS 2
#define DUPS 3

// Structs
typedef struct {
    uint16_t seq;
    uint16_t ack;
    uint16_t length;
    uint16_t win;
    uint16_t flags; // LSb 0 SYN, LSb 1 ACK, LSb 2 Parity
    uint16_t unused;
    uint8_t payload[0];
} packet;

// Bit counter
static inline int bit_count(packet* pkt) {
    uint8_t* bytes = (uint8_t*) pkt;
    int len = sizeof(packet) + MIN(MAX_PAYLOAD, ntohs(pkt->length));
    int count = 0;

    for (int i = 0; i < len; i++) {
        uint8_t val = bytes[i];

        while (val > 0) {
            if (val & 1) {
                count += 1;
            }
            val >>= 1;
        }
    }

    return count;
}

// Helpers
static inline void print(char* txt) {
    fprintf(stderr, "%s\n", txt);
}

static inline void print_diag(packet* pkt, int diag) {
    switch (diag) {
    case RECV:
        fprintf(stderr, "RECV");
        break;
    case SEND:
        fprintf(stderr, "SEND");
        break;
    case RTOS:
        fprintf(stderr, "RTOS");
        break;
    case DUPS:
        fprintf(stderr, "DUPS");
        break;
    }

    bool syn = pkt->flags & SYN;
    bool ack = pkt->flags & ACK;
    bool parity = pkt->flags & PARITY;
    fprintf(stderr, " %hu ACK %hu LEN %hu WIN %hu FLAGS ", ntohs(pkt->seq),
            ntohs(pkt->ack), ntohs(pkt->length), ntohs(pkt->win));
    if (!syn && !ack && !parity) {
        fprintf(stderr, "NONE");
    } else {
        if (syn) {
            fprintf(stderr, "SYN ");
        }
        if (ack) {
            fprintf(stderr, "ACK ");
        }
        if (parity) {
            fprintf(stderr, "PARITY ");
        }
    }
    fprintf(stderr, "\n");
}

