#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include "transport.h"
#include "consts.h"
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Global variables
int state = 0;
uint32_t seq = 0;
uint32_t ack = 0;
uint16_t last_ack = 0;
int dup_ack_count = 0;
uint16_t last_retransmit_seq = 0;

#define BUFFER_SIZE 40
#define FAST_RETRANSMIT_THRESHOLD 3
#define MAX_RETRANSMIT_ATTEMPTS 5

typedef struct
{
    packet packets[BUFFER_SIZE];
    struct timeval times[BUFFER_SIZE];
    int retransmit_count[BUFFER_SIZE]; // Track retransmission attempts
    int count;
    uint16_t window_start; // Sequence number of first packet in window
    uint16_t window_size;  // Current window size
} Buffer;

Buffer send_buffer = {.count = 0, .window_start = 0, .window_size = MAX_WINDOW};
Buffer recv_buffer = {.count = 0, .window_start = 0, .window_size = MAX_WINDOW};

ssize_t (*input_p)(uint8_t *, size_t);
void (*output_p)(uint8_t *, size_t);

// Buffer operations
bool buffer_add(Buffer *buf, packet *pkt)
{
    if (buf->count >= BUFFER_SIZE)
        return false;

    memcpy(&buf->packets[buf->count], pkt, sizeof(packet) + ntohs(pkt->length));
    gettimeofday(&buf->times[buf->count], NULL);
    buf->retransmit_count[buf->count] = 0;
    buf->count++;
    return true;
}

void buffer_remove_first(Buffer *buf)
{
    if (buf->count <= 0)
        return;

    for (int i = 0; i < buf->count - 1; i++)
    {
        buf->packets[i] = buf->packets[i + 1];
        buf->times[i] = buf->times[i + 1];
        buf->retransmit_count[i] = buf->retransmit_count[i + 1];
    }
    buf->count--;
}

// Helper function to check if sequence number is in window
bool is_in_window(uint16_t seq_num, uint16_t window_start, uint16_t window_size)
{
    return (seq_num >= window_start && seq_num < window_start + window_size);
}

void calculate_parity(packet *pkt)
{
    // First clear parity bit
    pkt->flags &= ~PARITY;

    // Calculate XOR sum without parity bit
    uint8_t *bytes = (uint8_t *)pkt;
    int len = sizeof(packet) + ntohs(pkt->length);
    int xor_sum = 0;

    for (int i = 0; i < len; i++)
    {
        xor_sum ^= bytes[i];
    }

    // Set parity bit if needed to make total XOR sum 0
    if (xor_sum != 0)
    {
        pkt->flags |= PARITY;
    }
}

bool check_parity(packet *pkt)
{
    uint8_t *bytes = (uint8_t *)pkt;
    int len = sizeof(packet) + ntohs(pkt->length);
    int xor_sum = 0;

    // XOR all bits including parity bit
    for (int i = 0; i < len; i++)
    {
        xor_sum ^= bytes[i];
    }

    // Packet is valid if XOR sum is 0
    return xor_sum == 0;
}
void send_packet(int sockfd, struct sockaddr_in *addr, packet *pkt)
{
    if (sendto(sockfd, pkt, sizeof(packet) + ntohs(pkt->length), 0,
               (struct sockaddr *)addr, sizeof(*addr)) < 0)
    {
        perror("sendto");
    }
}

void process_data(packet *pkt)
{
    uint16_t recv_seq = ntohs(pkt->seq);

    if (recv_seq == ack)
    {
        // In-order packet
        output_p(pkt->payload, ntohs(pkt->length));
        ack += ntohs(pkt->length);
        fflush(stdout);

        // Process any buffered packets
        bool found;
        do
        {
            found = false;
            for (int i = 0; i < recv_buffer.count; i++)
            {
                if (ntohs(recv_buffer.packets[i].seq) == ack)
                {
                    output_p(recv_buffer.packets[i].payload,
                             ntohs(recv_buffer.packets[i].length));
                    ack += ntohs(recv_buffer.packets[i].length);
                    fflush(stdout);

                    // Remove this packet
                    for (int j = i; j < recv_buffer.count - 1; j++)
                    {
                        recv_buffer.packets[j] = recv_buffer.packets[j + 1];
                    }
                    recv_buffer.count--;
                    found = true;
                    break;
                }
            }
        } while (found);
    }
    else if (recv_seq > ack && recv_seq < ack + recv_buffer.window_size)
    {
        // Out of order but within window - buffer it
        buffer_add(&recv_buffer, pkt);
    }
}

void retransmit_packet(int sockfd, struct sockaddr_in *addr, int index)
{
    if (index < 0 || index >= send_buffer.count)
        return;

    packet *pkt = &send_buffer.packets[index];
    uint16_t seq_num = ntohs(pkt->seq);

    // Check if packet is already acknowledged
    if (seq_num + ntohs(pkt->length) <= last_ack)
    {
        return;
    }

    if (send_buffer.retransmit_count[index] < MAX_RETRANSMIT_ATTEMPTS)
    {
        send_packet(sockfd, addr, pkt);
        gettimeofday(&send_buffer.times[index], NULL);
        send_buffer.retransmit_count[index]++;

        fprintf(stderr, "[%s] Retransmitting seq=%hu (attempt %d)\n",
                state == SERVER ? "SERVER" : "CLIENT",
                seq_num, send_buffer.retransmit_count[index]);
    }
}

void process_ack(int sockfd, struct sockaddr_in *addr, uint16_t received_ack)
{
    // Ignore old ACKs
    if (received_ack <= last_ack)
    {
        if (received_ack == last_ack)
        {
            dup_ack_count++;
            if (dup_ack_count >= DUP_ACKS)
            {
                // Fast retransmit the first unacked packet
                if (send_buffer.count > 0)
                {
                    retransmit_packet(sockfd, addr, 0);
                }
                dup_ack_count = 0;
            }
        }
        return;
    }

    // New ACK - higher than last_ack
    last_ack = received_ack;
    dup_ack_count = 0;

    // Remove all cumulative acknowledged packets
    while (send_buffer.count > 0)
    {
        packet *first_pkt = &send_buffer.packets[0];
        uint16_t first_seq = ntohs(first_pkt->seq);
        uint16_t first_len = ntohs(first_pkt->length);

        // If this packet is fully acknowledged
        if (first_seq + first_len <= received_ack)
        {
            buffer_remove_first(&send_buffer);

            // Update window start to next unacked packet
            if (send_buffer.count > 0)
            {
                send_buffer.window_start = ntohs(send_buffer.packets[0].seq);
            }
        }
        else
        {
            break; // Stop at first unacked packet
        }
    }
}

void handle_timeout(int sockfd, struct sockaddr_in *addr, struct timeval now)
{
    for (int i = 0; i < send_buffer.count; i++)
    {
        // Only retransmit packets that haven't been acknowledged
        uint16_t seq_num = ntohs(send_buffer.packets[i].seq);
        uint16_t len = ntohs(send_buffer.packets[i].length);

        if (seq_num + len > last_ack &&
            TV_DIFF(now, send_buffer.times[i]) >= RTO)
        {
            retransmit_packet(sockfd, addr, i);
        }
    }
}

void listen_loop(int sockfd, struct sockaddr_in *addr, int type,
                 ssize_t (*input_function)(uint8_t *, size_t),
                 void (*output_function)(uint8_t *, size_t))
{

    input_p = input_function;
    output_p = output_function;

    char buffer[sizeof(packet) + MAX_PAYLOAD] = {0};
    struct sockaddr_in peer_addr;
    socklen_t addr_size = sizeof(peer_addr);

    // Set non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    while (true)
    {
        // Send data if window allows
        size_t bytes_in_flight = 0;
        for (int i = 0; i < send_buffer.count; i++)
        {
            bytes_in_flight += ntohs(send_buffer.packets[i].length);
        }

        if (bytes_in_flight < send_buffer.window_size)
        {
            uint8_t data[MAX_PAYLOAD];
            ssize_t bytes_read = input_p(data, MIN(MAX_PAYLOAD,
                                                   send_buffer.window_size - bytes_in_flight));

            if (bytes_read > 0)
            {
                packet send_pkt = {0};
                send_pkt.seq = htons(seq);
                send_pkt.ack = htons(ack);
                send_pkt.length = htons(bytes_read);
                send_pkt.win = htons(MAX_WINDOW); // Advertise max window
                send_pkt.flags = ACK;             // Always set ACK flag for data packets
                memcpy(send_pkt.payload, data, bytes_read);

                calculate_parity(&send_pkt);

                if (buffer_add(&send_buffer, &send_pkt))
                {
                    send_packet(sockfd, addr, &send_pkt);
                    seq += bytes_read;
                }
            }
        }

        // Receive packets
        int bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                      (struct sockaddr *)&peer_addr, &addr_size);

        if (bytes_received > 0)
        {
            packet *pkt = (packet *)buffer;

            if (check_parity(pkt))
            {
                fprintf(stderr, "[%s] Corrupted packet received, dropping\n",
                        type == SERVER ? "SERVER" : "CLIENT");
                continue;
            }

            if (pkt->flags & ACK)
            {
                process_ack(sockfd, addr, ntohs(pkt->ack));
                // Update window size based on receiver's advertised window
                send_buffer.window_size = ntohs(pkt->win);
            }

            if (pkt->length > 0)
            {
                process_data(pkt);
                packet ack_pkt = {0};
                ack_pkt.seq = htons(seq);
                ack_pkt.ack = htons(ack);
                ack_pkt.flags = ACK;
                ack_pkt.win = htons(MAX_WINDOW - recv_buffer.count); // Advertise available buffer space
                calculate_parity(&ack_pkt);
                send_packet(sockfd, addr, &ack_pkt);
                fprintf(stderr, "[%s] Sent ACK: ack=%hu\n",
                        type == SERVER ? "SERVER" : "CLIENT", ack);
            }
        }

        struct timeval now;
        gettimeofday(&now, NULL);
        handle_timeout(sockfd, addr, now);

        // usleep(1000); // Small delay to prevent CPU spinning
    }
}