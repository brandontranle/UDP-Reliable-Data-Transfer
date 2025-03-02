// transport.c
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

#define BUFFER_SIZE 40  // Increased buffer size
#define MAX_RETRANSMIT_ATTEMPTS 5  // Increased max retransmit attempts

// Global variables
int state = 0;
uint32_t seq = 0;
uint32_t ack = 0;
uint16_t last_ack = 0;
int dup_ack_count = 0;

static ssize_t (*g_input)(uint8_t*, size_t) = NULL;
static void (*g_output)(uint8_t*, size_t) = NULL;

int ack_sent = 0; // did process_data already send an ACK?

// 32-bit signed diff accounting for wrap-around.
static inline int32_t seq_diff(uint16_t a, uint16_t b) {
    int32_t diff = (int32_t)a - (int32_t)b;
    if (diff < -32768)
        diff += 65536;
    else if (diff > 32768)
        diff -= 65536;
    return diff;
}

// ---------- FORWARD DECLARATIONS ----------
void calculate_parity(packet *pkt);
bool check_parity(packet *pkt);
void send_packet(int sockfd, struct sockaddr_in *addr, packet *pkt);

bool perform_handshake(int sockfd, struct sockaddr_in *addr, int type,
                       uint16_t *local_init_seq, uint16_t *remote_init_seq);

static uint16_t generate_initial_seq() {
    srand(time(NULL));
    return rand() % 1000; // small random range
}

// -------------- HANDSHAKE LOGIC --------------
// Modularity B)
#define HS_INIT 0
#define HS_SYN_SENT 1
#define HS_SYN_RECEIVED 2
#define HS_ESTABLISHED 3

bool perform_handshake(int sockfd, struct sockaddr_in *addr, int type,
                       uint16_t *local_init_seq, uint16_t *remote_init_seq)
{
    char buffer[sizeof(packet) + MAX_PAYLOAD] = {0};
    struct sockaddr_in peer_addr;
    socklen_t addr_size = sizeof(peer_addr);
    struct timeval timeout;
    int handshake_state = HS_INIT;

    *local_init_seq = generate_initial_seq();
    *remote_init_seq = 0; // will be filled on receiving SYN

    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    while (handshake_state != HS_ESTABLISHED) {
        // ------ CLIENT ------
        if (type == CLIENT) {
            if (handshake_state == HS_INIT) {
                // Send SYN
                packet syn_pkt = {0};
                syn_pkt.seq = htons(*local_init_seq);
                syn_pkt.ack = 0;
                uint8_t payload[MAX_PAYLOAD] = {0};
                ssize_t bytes_read = 0;
                // Handles piggybacked data in SYN
                if (g_input) {
                    bytes_read = g_input(payload, MAX_PAYLOAD);
                    if (bytes_read > 0) {
                        memcpy(syn_pkt.payload, payload, bytes_read);
                        syn_pkt.length = htons(bytes_read);
                    } else {
                        syn_pkt.length = 0;
                    }
                } else {
                    syn_pkt.length = 0;
                }
                syn_pkt.win = htons(MIN_WINDOW);
                syn_pkt.flags = SYN;
                syn_pkt.unused = 0;
                calculate_parity(&syn_pkt);
                print_diag(&syn_pkt, SEND);
                send_packet(sockfd, addr, &syn_pkt);
                handshake_state = HS_SYN_SENT;
                gettimeofday(&timeout, NULL);
                int rcvbuf = 65536, sndbuf = 65536;
                setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
                setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
            }
            else if (handshake_state == HS_SYN_SENT) {
                // Wait for SYN+ACK
                addr_size = sizeof(peer_addr);
                int bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                              (struct sockaddr *)&peer_addr, &addr_size);
                if (bytes_received > 0) {
                    packet *recv_pkt = (packet *)buffer;
                    // Check if from same peer
                    if (memcmp(&peer_addr.sin_addr, &addr->sin_addr, sizeof(struct in_addr)) == 0 &&
                        peer_addr.sin_port == addr->sin_port)
                    {
                        print_diag(recv_pkt, RECV);
                        if (!check_parity(recv_pkt))
                            continue;
                        // Looking for SYN+ACK
                        if ((recv_pkt->flags & (SYN | ACK)) == (SYN | ACK)) {
                            *remote_init_seq = ntohs(recv_pkt->seq);
                            uint16_t payload_len = ntohs(recv_pkt->length);
                            // Extracts piggybacked data from SYN+ACK
                            if (payload_len > 0)
                                g_output(recv_pkt->payload, payload_len);
                            // Send final ACK with data if available, using packet-based sequencing.
                            packet ack_pkt = {0};
                            uint8_t payload[MAX_PAYLOAD] = {0};
                            ssize_t bytes_read = 0;
                            if (g_input) {
                                bytes_read = g_input(payload, MAX_PAYLOAD);
                                if (bytes_read > 0) {
                                    memcpy(ack_pkt.payload, payload, bytes_read);
                                    ack_pkt.length = htons(bytes_read);
                                    // Increment sequence number if data is sent
                                    ack_pkt.seq = htons(*local_init_seq + 1);
                                    *local_init_seq = *local_init_seq + 1;
                                } else {
                                    ack_pkt.length = 0;
                                    ack_pkt.seq = htons(0);
                                }
                            } else {
                                ack_pkt.length = 0;
                                ack_pkt.seq = htons(0);
                            }
                            ack_pkt.ack = htons((*remote_init_seq) + 1);
                            ack_pkt.win = htons(MAX_WINDOW);
                            ack_pkt.flags = ACK;
                            ack_pkt.unused = 0;
                            calculate_parity(&ack_pkt);
                            print_diag(&ack_pkt, SEND);
                            send_packet(sockfd, addr, &ack_pkt);
                            handshake_state = HS_ESTABLISHED;
                        }
                    }
                }
                // ------ Retransmit SYN if timeout ------
                struct timeval now;
                gettimeofday(&now, NULL);
                // compare current time with time SYN was sent
                // if more than 1 econd, retransmit
                if (TV_DIFF(now, timeout) >= RTO) {
                    packet syn_pkt = {0};
                    syn_pkt.seq = htons(*local_init_seq);
                    syn_pkt.ack = 0;
                    uint8_t payload[MAX_PAYLOAD] = {0};
                    ssize_t bytes_read = 0;
                    if (g_input) {
                        bytes_read = g_input(payload, MAX_PAYLOAD);
                        if (bytes_read > 0) {
                            memcpy(syn_pkt.payload, payload, bytes_read);
                            syn_pkt.length = htons(bytes_read);
                        } else {
                            syn_pkt.length = 0;
                        }
                    } else {
                        syn_pkt.length = 0;
                    }
                    syn_pkt.win = htons(MAX_WINDOW);
                    syn_pkt.flags = SYN;
                    syn_pkt.unused = 0;
                    calculate_parity(&syn_pkt);
                    print_diag(&syn_pkt, SEND);
                    send_packet(sockfd, addr, &syn_pkt);
                    gettimeofday(&timeout, NULL);
                }
            }
         // ------ SERVER ------
        } else { 
            addr_size = sizeof(peer_addr);
            int bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                          (struct sockaddr *)&peer_addr, &addr_size);
            if (bytes_received > 0) {
                packet *recv_pkt = (packet *)buffer;
                print_diag(recv_pkt, RECV);
                if (!check_parity(recv_pkt))
                    continue;
                // If server receives SYN, start handshake
                if (handshake_state == HS_INIT && (recv_pkt->flags & SYN)) {
                    // Process piggybacked data from client's SYN
                    uint16_t payload_len = ntohs(recv_pkt->length);
                    if (payload_len > 0)
                        g_output(recv_pkt->payload, payload_len);
                    *remote_init_seq = ntohs(recv_pkt->seq);
                    packet synack_pkt = {0};
                    synack_pkt.seq = htons(*local_init_seq);
                    synack_pkt.ack = htons((*remote_init_seq) + 1);
                    uint8_t payload[MAX_PAYLOAD] = {0};
                    ssize_t bytes_read = 0;
                    if (g_input) {
                        bytes_read = g_input(payload, MAX_PAYLOAD);
                        if (bytes_read > 0) {
                            memcpy(synack_pkt.payload, payload, bytes_read);
                            synack_pkt.length = htons(bytes_read);
                        } else {
                            synack_pkt.length = 0;
                        }
                    } else {
                        synack_pkt.length = 0;
                    }
                    synack_pkt.win = htons(MIN_WINDOW);
                    synack_pkt.flags = SYN | ACK;
                    synack_pkt.unused = 0;
                    calculate_parity(&synack_pkt);
                    send_packet(sockfd, addr, &synack_pkt);
                    handshake_state = HS_SYN_RECEIVED;
                    gettimeofday(&timeout, NULL);
                }
                // If server receives final ACK, finish handshake
                else if (handshake_state == HS_SYN_RECEIVED && (recv_pkt->flags & ACK)) {
                    uint16_t their_ack = ntohs(recv_pkt->ack);
                    // Process final ACK. If it carries payload, output it and update sequence.
                    if (their_ack == (*local_init_seq + 1)) {
                        uint16_t payload_len = ntohs(recv_pkt->length);
                        if (payload_len > 0) {
                            g_output(recv_pkt->payload, payload_len);
                            *remote_init_seq = *remote_init_seq + 1;
                        }
                        handshake_state = HS_ESTABLISHED;
                    }
                }
            }
            // Reset the handshake if timeout
            if (handshake_state == HS_SYN_RECEIVED) {
                struct timeval now;
                gettimeofday(&now, NULL);
                if (TV_DIFF(now, timeout) >= RTO) {
                    handshake_state = HS_INIT;
                }
            }
        }
    }
    return true;
}

// ---------- PACKET + BUFFER ----------
typedef struct {
    uint16_t seq;
    uint16_t ack;
    uint16_t length;
    uint16_t win;
    uint16_t flags;
    uint16_t unused;
    uint8_t  payload[MAX_PAYLOAD]; // Use this instead since consts.h has an empty payload packet def.
} full_packet;

typedef struct {
    full_packet packets[BUFFER_SIZE];
    struct timeval times[BUFFER_SIZE];
    int retransmit_count[BUFFER_SIZE];
    int count; // number of packets currently in buffer
    uint16_t window_start;  // starting seq number for window
    uint16_t window_size; // max allowed unacked data
} Buffer;

static Buffer send_buffer = { .count = 0, .window_start = 0, .window_size = MAX_WINDOW }; // stores packets waiting for ack
static Buffer recv_buffer = { .count = 0, .window_start = 0, .window_size = MAX_WINDOW }; // stores packets waiting to be delivered in order

void calculate_parity(packet *pkt) {
    pkt->flags &= ~PARITY; // clear parity bit
    int ones = bit_count(pkt);
    if (ones % 2 != 0)
        pkt->flags |= PARITY; // set parity bit if odd
}

bool check_parity(packet *pkt) {
    return ((bit_count(pkt) % 2) == 0);
}

void send_packet(int sockfd, struct sockaddr_in *addr, packet *pkt)
{
    size_t total_size = sizeof(packet) + ntohs(pkt->length); // total size = header + payload
    sendto(sockfd, pkt, total_size, 0, (struct sockaddr *)addr, sizeof(*addr));
}

// adding packet to buffer
static bool buffer_add(Buffer *buf, packet *pkt) {
    // if buffer is full return
    if (buf->count >= BUFFER_SIZE)
        return false;
    uint16_t pkt_len = ntohs(pkt->length);
    // iterate through all packets in buffer and calculate bytes in flight
    size_t bytes_in_flight = 0;
    for (int i = 0; i < buf->count; i++)
        bytes_in_flight += ntohs(buf->packets[i].length);
    // can't send too much unacked data at once
    if (bytes_in_flight + pkt_len > buf->window_size)
        return false;
    memcpy(&buf->packets[buf->count], pkt, sizeof(packet) + pkt_len);
    gettimeofday(&buf->times[buf->count], NULL);
    buf->retransmit_count[buf->count] = 0;
    buf->count++;
    return true;
}

// removing oldest packet from buffer
static void buffer_remove_first(Buffer *buf)
{
    // can't remove
    if (buf->count <= 0)
        return;
    // shift all packets to the left
    for (int i = 0; i < buf->count - 1; i++) {
        buf->packets[i] = buf->packets[i + 1];
        buf->times[i] = buf->times[i + 1];
        buf->retransmit_count[i] = buf->retransmit_count[i + 1];
    }
    buf->count--;
}

// ------ PACKET PROCESSING STUFF ------

static void retransmit_packet(int sockfd, struct sockaddr_in *addr, int index)
{
    if (index < 0 || index >= send_buffer.count)
        return;
    packet *pkt = (packet *)&send_buffer.packets[index];
    uint16_t seq_num = ntohs(pkt->seq);
    // if packet is already acked, don't retransmit
    if ((seq_num + 1) <= last_ack)
        return;
    // if retransmit count is less than max, retransmit
    if (send_buffer.retransmit_count[index] < MAX_RETRANSMIT_ATTEMPTS) {
        print_diag(pkt, RTOS);
        send_packet(sockfd, addr, pkt);
        gettimeofday(&send_buffer.times[index], NULL);
        send_buffer.retransmit_count[index]++;
    }
}

static void process_ack(int sockfd, struct sockaddr_in *addr, packet *recv_pkt) {
    uint16_t received_ack = ntohs(recv_pkt->ack);
    uint16_t received_win = ntohs(recv_pkt->win);
    // update window size
    if (received_win >= MIN_WINDOW)
    // if buffer is empty, return
        send_buffer.window_size = received_win;
    if (send_buffer.count == 0)
        return;
    // calculate difference between received ack and last ack
    int32_t diff = seq_diff(received_ack, last_ack);
    // new data is acked
    if (diff > 0) {
        last_ack = received_ack;
        dup_ack_count = 0;
        // remove acked packets from buffer
        while (send_buffer.count > 0) {
            packet *pkt = (packet *)&send_buffer.packets[0];
            uint16_t seq_num = ntohs(pkt->seq);
            if (seq_num + 1 <= received_ack)
                buffer_remove_first(&send_buffer);
            else
                break;
        }
    // duplicate ack
    } else if (diff == 0) {
        dup_ack_count++;
        if (dup_ack_count >= DUP_ACKS) {
            // retransmit oldest unacked packet
            if (send_buffer.count > 0) {
                packet *pkt = (packet *)&send_buffer.packets[0];
                print_diag(pkt, DUPS);
                retransmit_packet(sockfd, addr, 0);
                dup_ack_count = 0;
            }
        }
    }
}

static void process_data(int sockfd, struct sockaddr_in *addr, packet *pkt) {
    ack_sent = 0;
    uint16_t recv_seq = ntohs(pkt->seq);
    uint16_t recv_len = ntohs(pkt->length);
    if (recv_seq == 0) {
        process_ack(sockfd, addr, pkt);
        return;
    }
    int32_t diff = seq_diff(recv_seq, ack);
    if (diff == 0) {
        if (recv_len > 0)
            g_output(pkt->payload, recv_len);
        ack = (uint16_t)(recv_seq + 1);
        bool made_progress = true;
        while (made_progress && recv_buffer.count > 0) {
            made_progress = false;
            for (int i = 0; i < recv_buffer.count; i++) {
                packet *buf_pkt = (packet *)&recv_buffer.packets[i];
                uint16_t buf_seq = ntohs(buf_pkt->seq);
                if (buf_seq == ack) {
                    uint16_t buf_len = ntohs(buf_pkt->length);
                    if (buf_len > 0)
                        g_output(buf_pkt->payload, buf_len);
                    ack = (uint16_t)(buf_seq + 1);
                    memmove(&recv_buffer.packets[i],
                            &recv_buffer.packets[i + 1],
                            (recv_buffer.count - i - 1) * sizeof(full_packet));
                    recv_buffer.count--;
                    made_progress = true;
                    break;
                }
            }
        }
    } else if (diff > 0) {
        for (int i = 0; i < recv_buffer.count; i++) {
            if (ntohs(recv_buffer.packets[i].seq) == recv_seq)
                goto send_ack;
        }
        int insert_pos = 0;
        while (insert_pos < recv_buffer.count) {
            uint16_t buf_seq = ntohs(recv_buffer.packets[insert_pos].seq);
            if (seq_diff(recv_seq, buf_seq) < 0)
                break;
            insert_pos++;
        }
        if (insert_pos < BUFFER_SIZE) {
            if (recv_buffer.count < BUFFER_SIZE) {
                memmove(&recv_buffer.packets[insert_pos + 1],
                        &recv_buffer.packets[insert_pos],
                        (recv_buffer.count - insert_pos) * sizeof(full_packet));
                memcpy(&recv_buffer.packets[insert_pos], pkt, sizeof(packet) + recv_len);
                recv_buffer.count++;
            } else {
                if (insert_pos < BUFFER_SIZE - 1) {
                    memmove(&recv_buffer.packets[insert_pos + 1],
                            &recv_buffer.packets[insert_pos],
                            (BUFFER_SIZE - insert_pos - 1) * sizeof(full_packet));
                    memcpy(&recv_buffer.packets[insert_pos], pkt, sizeof(packet) + recv_len);
                }
            }
        }
    }
send_ack:
    if (pkt->flags & ACK)
        process_ack(sockfd, addr, pkt);
    if (!ack_sent) {
        packet ack_pkt = {0};
        ack_pkt.seq = 0;
        ack_pkt.ack = htons(ack);
        ack_pkt.length = 0;
        ack_pkt.win = htons(MAX_WINDOW);
        ack_pkt.flags = ACK;
        calculate_parity(&ack_pkt);
        print_diag(&ack_pkt, SEND);
        send_packet(sockfd, addr, &ack_pkt);
        ack_sent = 1;
    }
}

void listen_loop(int sockfd, struct sockaddr_in* addr, int type, ssize_t (*input_p)(uint8_t*, size_t), void (*output_p)(uint8_t*, size_t))
{
    g_input = input_p;
    g_output = output_p;
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    uint16_t local_seq, remote_seq;
    if (!perform_handshake(sockfd, addr, type, &local_seq, &remote_seq))
        return;

    //based on the data exchange in the hanshake!
    seq = local_seq + 1;
    last_ack = seq;
    ack = remote_seq + 1;

    send_buffer.count = 0;
    recv_buffer.count = 0;
    send_buffer.window_size = MIN_WINDOW;
    recv_buffer.window_size = MAX_WINDOW;

    struct timeval last_transmission;
    gettimeofday(&last_transmission, NULL);
    char buffer[sizeof(packet) + MAX_PAYLOAD] = {0};
    struct sockaddr_in peer_addr;
    socklen_t addr_size = sizeof(peer_addr);
    while (1) {
        struct timeval now;
        gettimeofday(&now, NULL);
        addr_size = sizeof(peer_addr);
        int bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                      (struct sockaddr*)&peer_addr, &addr_size);
        if (bytes_received > 0) {
            packet *recv_pkt = (packet*)buffer;
            if (!check_parity(recv_pkt)) {
                packet ack_pkt = {0};
                ack_pkt.seq = 0;
                ack_pkt.ack = htons(ack);
                ack_pkt.length = 0;
                ack_pkt.win = htons(MAX_WINDOW);
                ack_pkt.flags = ACK;
                calculate_parity(&ack_pkt);
                send_packet(sockfd, addr, &ack_pkt);
                continue;
            }
            print_diag(recv_pkt, RECV);
            process_data(sockfd, addr, recv_pkt);
        }
        size_t bytes_in_flight = 0;
        for (int i = 0; i < send_buffer.count; i++)
            bytes_in_flight += ntohs(send_buffer.packets[i].length);
        if (bytes_in_flight < send_buffer.window_size && send_buffer.count < BUFFER_SIZE) {
            size_t can_send = send_buffer.window_size - bytes_in_flight;
            if (can_send > MAX_PAYLOAD)
                can_send = MAX_PAYLOAD;
            uint8_t data[MAX_PAYLOAD];
            ssize_t bytes_read = g_input(data, can_send);
            if (bytes_read > 0) {
                packet send_pkt = {0};
                send_pkt.seq = htons(seq);
                send_pkt.ack = htons(ack);
                send_pkt.length = htons(bytes_read);
                send_pkt.win = htons(MAX_WINDOW);
                send_pkt.flags = ACK;  // Always set ACK
                memcpy(send_pkt.payload, data, bytes_read);
                calculate_parity(&send_pkt);
                if (buffer_add(&send_buffer, &send_pkt)) {
                    print_diag(&send_pkt, SEND);
                    send_packet(sockfd, addr, &send_pkt);
                    seq = (uint16_t)(seq + 1);
                    gettimeofday(&last_transmission, NULL);
                }
            }
        }
        gettimeofday(&now, NULL);
        for (int i = 0; i < send_buffer.count; i++) {
            long elapsed = TV_DIFF(now, send_buffer.times[i]);
            if (elapsed >= RTO) {
                retransmit_packet(sockfd, addr, i);
                gettimeofday(&last_transmission, NULL);
            }
        }
        long since_last_transmission = TV_DIFF(now, last_transmission);
        if (since_last_transmission > RTO / 2 && send_buffer.count > 0) {
            packet ack_pkt = {0};
            ack_pkt.seq = 0;
            ack_pkt.ack = htons(ack);
            ack_pkt.length = 0;
            ack_pkt.win = htons(MAX_WINDOW);
            ack_pkt.flags = ACK;
            calculate_parity(&ack_pkt);
            send_packet(sockfd, addr, &ack_pkt);
            gettimeofday(&last_transmission, NULL);
        }
    }
}
