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

#define BUFFER_SIZE 40
#define FAST_RETRANSMIT_THRESHOLD 3
#define MAX_RETRANSMIT_ATTEMPTS 5
// Duplicate ACK throttle time in microseconds (300 ms)
#define DUP_ACK_THROTTLE_TIME 300000

// Global variables
int state = 0;
uint32_t seq = 0;
uint32_t ack = 0;
uint16_t last_ack = 0;
int dup_ack_count = 0;
uint16_t last_retransmit_seq = 0;
uint16_t recv_flow_window;

// We store the user-provided function pointers from listen_loop()
// so we can call them from anywhere in this file.
static ssize_t (*g_input)(uint8_t*, size_t) = NULL;
static void    (*g_output)(uint8_t*, size_t) = NULL;

// Flag: did process_data already send an ACK?
int ack_sent = 0;

// Use a 32-bit signed diff that correctly accounts for wrap-around.
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
    *remote_init_seq = 0; // will fill on receiving SYN

    // 1-second handshake timeout
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    while (handshake_state != HS_ESTABLISHED) {
        if (type == CLIENT) {
            if (handshake_state == HS_INIT) {
                // Send SYN
                packet syn_pkt = {0};
                syn_pkt.seq    = htons(*local_init_seq);
                syn_pkt.ack    = 0;
                syn_pkt.length = 0;
                syn_pkt.win    = htons(MAX_WINDOW);
                syn_pkt.flags  = SYN;
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

                    // Check if from the same peer
                    if (memcmp(&peer_addr.sin_addr, &addr->sin_addr, sizeof(struct in_addr)) == 0 &&
                        peer_addr.sin_port == addr->sin_port)
                    {
                        print_diag(recv_pkt, RECV);
                        if (!check_parity(recv_pkt)) {
                            // bad parity: ignore
                            continue;
                        }
                        // Looking for (SYN|ACK)
                        if ((recv_pkt->flags & (SYN | ACK)) == (SYN | ACK)) {
                            *remote_init_seq = ntohs(recv_pkt->seq);

                            // Send final ACK
                            packet ack_pkt = {0};
                            ack_pkt.seq    = htons((*local_init_seq) + 1);
                            ack_pkt.ack    = htons((*remote_init_seq) + 1);
                            ack_pkt.length = 0;
                            ack_pkt.win    = 0; // per reference logs
                            ack_pkt.flags  = ACK;
                            ack_pkt.unused = 0;
                            calculate_parity(&ack_pkt);
                            send_packet(sockfd, addr, &ack_pkt);

                            handshake_state = HS_ESTABLISHED;
                        }
                    }
                }
                // Retransmit SYN if no response within 1s
                struct timeval now;
                gettimeofday(&now, NULL);
                if (TV_DIFF(now, timeout) >= RTO) {
                    packet syn_pkt = {0};
                    syn_pkt.seq    = htons(*local_init_seq);
                    syn_pkt.ack    = 0;
                    syn_pkt.length = 0;
                    syn_pkt.win    = htons(MAX_WINDOW);
                    syn_pkt.flags  = SYN;
                    syn_pkt.unused = 0;
                    calculate_parity(&syn_pkt);
                    print_diag(&syn_pkt, SEND);
                    send_packet(sockfd, addr, &syn_pkt);
                    gettimeofday(&timeout, NULL);
                }
            }
        } else { // SERVER
            addr_size = sizeof(peer_addr);
            int bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                (struct sockaddr *)&peer_addr, &addr_size);
            if (bytes_received > 0) {
                packet *recv_pkt = (packet *)buffer;
                print_diag(recv_pkt, RECV);

                if (!check_parity(recv_pkt))
                    continue;

                if (handshake_state == HS_INIT && (recv_pkt->flags & SYN)) {
                    // Send SYN+ACK
                    *remote_init_seq = ntohs(recv_pkt->seq);

                    packet synack_pkt = {0};
                    synack_pkt.seq    = htons(*local_init_seq);
                    synack_pkt.ack    = htons((*remote_init_seq) + 1);
                    synack_pkt.length = 0;
                    synack_pkt.win    = htons(MIN_WINDOW);
                    synack_pkt.flags  = SYN | ACK;
                    synack_pkt.unused = 0;
                    calculate_parity(&synack_pkt);
                    send_packet(sockfd, addr, &synack_pkt);

                    handshake_state = HS_SYN_RECEIVED;
                    gettimeofday(&timeout, NULL);
                }
                else if (handshake_state == HS_SYN_RECEIVED && (recv_pkt->flags & ACK)) {
                    uint16_t their_ack = ntohs(recv_pkt->ack);
                    if (their_ack == (*local_init_seq + 1))
                        handshake_state = HS_ESTABLISHED;
                }
            }

            if (handshake_state == HS_SYN_RECEIVED) {
                struct timeval now;
                gettimeofday(&now, NULL);
                if (TV_DIFF(now, timeout) >= RTO) {
                    // If we time out, revert to HS_INIT so we can wait again
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
    uint8_t  payload[MAX_PAYLOAD];
} full_packet;

typedef struct {
    full_packet packets[BUFFER_SIZE];
    struct timeval times[BUFFER_SIZE];
    int retransmit_count[BUFFER_SIZE];
    int count;
    uint16_t window_start;
    uint16_t window_size;
} Buffer;

// The actual buffers
static Buffer send_buffer = { .count = 0, .window_start = 0, .window_size = MAX_WINDOW };
static Buffer recv_buffer = { .count = 0, .window_start = 0, .window_size = MAX_WINDOW };

// Helper: read parity
void calculate_parity(packet *pkt) {
    pkt->flags &= ~PARITY; // Clear parity bit
    int ones = bit_count(pkt);
    if (ones % 2 != 0)
        pkt->flags |= PARITY;
}

bool check_parity(packet *pkt) {
    return ((bit_count(pkt) % 2) == 0);
}

// Helper: send a packet
void send_packet(int sockfd, struct sockaddr_in *addr, packet *pkt)
{
    size_t total_size = sizeof(packet) + ntohs(pkt->length);
    sendto(sockfd, pkt, total_size, 0, (struct sockaddr *)addr, sizeof(*addr));
}

// Add a packet to the send/recv buffer
static bool buffer_add(Buffer *buf, packet *pkt)
{
    if (buf->count >= BUFFER_SIZE) 
        return false;
    size_t pkt_size = sizeof(packet) + ntohs(pkt->length);
    memcpy(&buf->packets[buf->count], pkt, pkt_size);

    gettimeofday(&buf->times[buf->count], NULL);
    buf->retransmit_count[buf->count] = 0;
    buf->count++;
    return true;
}

// Remove first packet from buffer
static void buffer_remove_first(Buffer *buf)
{
    if (buf->count <= 0) return;

    for (int i = 0; i < buf->count - 1; i++) {
        // shift
        buf->packets[i]           = buf->packets[i + 1];
        buf->times[i]             = buf->times[i + 1];
        buf->retransmit_count[i]  = buf->retransmit_count[i + 1];
    }
    buf->count--;
}

// Retransmit
static void retransmit_packet(int sockfd, struct sockaddr_in *addr, int index)
{
    if (index < 0 || index >= send_buffer.count) 
        return;

    packet *pkt = (packet *)&send_buffer.packets[index];
    uint16_t seq_num = ntohs(pkt->seq);
    uint16_t length  = ntohs(pkt->length);

    // if it is fully acked
    if ((seq_num + length) <= last_ack)
        return;

    if (send_buffer.retransmit_count[index] < MAX_RETRANSMIT_ATTEMPTS) {
        print_diag(pkt, RTOS);
        send_packet(sockfd, addr, pkt);
        gettimeofday(&send_buffer.times[index], NULL);
        send_buffer.retransmit_count[index]++;
    }
}

// -------------- ACK Handling --------------
static void process_ack(int sockfd, struct sockaddr_in *addr, uint16_t received_ack)
{
    static uint16_t last_dup_ack_val = 0;
    static int dup_ack_count_local   = 0;

    // If ack <= last_ack, might be duplicate
    if (seq_diff(received_ack, last_ack) <= 0) {
        if (received_ack == last_dup_ack_val)
            dup_ack_count_local++;
        else {
            last_dup_ack_val     = received_ack;
            dup_ack_count_local  = 1;
        }

        // If we got 3 duplicates, fast retransmit
        if (dup_ack_count_local >= DUP_ACKS) {
            if (send_buffer.count > 0) {
                // Retransmit the oldest unacked
                retransmit_packet(sockfd, addr, 0);
            }
            dup_ack_count_local  = 0;
            last_dup_ack_val     = received_ack;
        }
        return;
    }

    // If new ACK > last_ack, then normal
    last_dup_ack_val    = received_ack;
    dup_ack_count_local = 0;
    last_ack            = received_ack;

    // pop from send_buffer anything up to this ack
    while (send_buffer.count > 0) {
        packet *first_pkt   = (packet*)&send_buffer.packets[0];
        uint16_t first_seq  = ntohs(first_pkt->seq);
        uint16_t first_len  = ntohs(first_pkt->length);
        uint16_t packet_end = first_seq + first_len; // The seq after last byte in that packet

        if (seq_diff(received_ack, packet_end) >= 0)
            buffer_remove_first(&send_buffer);
        else
            break;
    }

    // reset timer for first unacked
    if (send_buffer.count > 0) {
        gettimeofday(&send_buffer.times[0], NULL);
    }
}

// -------------- Data Handling --------------
static void process_data(int sockfd, struct sockaddr_in *addr, packet *pkt)
{
    ack_sent = 0;

    uint16_t recv_seq = ntohs(pkt->seq);
    uint16_t recv_len = ntohs(pkt->length);

    int32_t diff = seq_diff(recv_seq, ack);
    if (diff == 0) {
        // In-order data: deliver & bump ack
        g_output(pkt->payload, recv_len);

        if (recv_flow_window < MAX_WINDOW) {
            uint16_t new_win = recv_flow_window + 500;
            if (new_win > MAX_WINDOW) new_win = MAX_WINDOW;
            recv_flow_window = new_win;
        }
        ack = (uint16_t)(ack + recv_len);

        // Check if we can deliver more from buffer
        bool found = true;
        while (found && recv_buffer.count > 0) {
            found = false;
            for (int i = 0; i < recv_buffer.count; i++) {
                uint16_t b_seq = ntohs(recv_buffer.packets[i].seq);
                uint16_t b_len = ntohs(recv_buffer.packets[i].length);

                if (seq_diff(b_seq, ack) == 0) {
                    g_output(recv_buffer.packets[i].payload, b_len);

                    if (recv_flow_window < MAX_WINDOW) {
                        uint16_t new_win = recv_flow_window + 500;
                        if (new_win > MAX_WINDOW) new_win = MAX_WINDOW;
                        recv_flow_window = new_win;
                    }
                    ack = (uint16_t)(ack + b_len);

                    // remove from buffer
                    for (int j = i; j < recv_buffer.count - 1; j++) {
                        recv_buffer.packets[j] = recv_buffer.packets[j + 1];
                    }
                    recv_buffer.count--;
                    found = true;
                    break;
                }
            }
        }
    }
    else if (diff > 0) {
        // Future data (out-of-order), buffer it if there's space
        if (recv_buffer.count < BUFFER_SIZE) {
            size_t total_size = sizeof(packet) + recv_len;
            memcpy(&recv_buffer.packets[recv_buffer.count], pkt, total_size);
            recv_buffer.count++;
        }
        // else just drop
    }
    else {
        // Old or duplicate data: send duplicate ACK if not done recently
        static uint16_t last_dup_ack_sent = 0;
        static struct timeval last_dup_ack_time = {0};

        struct timeval now;
        gettimeofday(&now, NULL);

        if (last_dup_ack_sent == ack) {
            // Already sent a duplicate ack with the same ack
            long tdiff = TV_DIFF(now, last_dup_ack_time);
            if (tdiff < DUP_ACK_THROTTLE_TIME) {
                // throttle
                return;
            }
        }
        last_dup_ack_sent = ack;
        last_dup_ack_time = now;

        // send dup ack
        packet dup_ack_pkt = {0};
        dup_ack_pkt.seq    = htons(seq);
        dup_ack_pkt.ack    = htons(ack);
        dup_ack_pkt.length = 0;
        dup_ack_pkt.win    = htons(recv_flow_window);
        dup_ack_pkt.flags  = ACK;
        calculate_parity(&dup_ack_pkt);

        send_packet(sockfd, addr, &dup_ack_pkt);
        ack_sent = 1;
    }
}


// -------------- Main I/O Loop --------------
void listen_loop(int sockfd, struct sockaddr_in* addr, int type,
                 ssize_t (*input_function)(uint8_t*, size_t),
                 void (*output_function)(uint8_t*, size_t))
{
    // Store function pointers globally
    g_input  = input_function;
    g_output = output_function;

    // Make sockfd non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    // Make stdin non-blocking
    flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);


    uint16_t local_seq, remote_seq;
    if (!perform_handshake(sockfd, addr, type, &local_seq, &remote_seq)) {
        return; // handshake failed
    }

    // Initialize after handshake
    seq = local_seq + 1;
    ack = remote_seq + 1;

    last_ack      = 0;
    dup_ack_count = 0;

    send_buffer.count = 0;
    recv_buffer.count = 0;

    send_buffer.window_size = MIN_WINDOW;
    recv_buffer.window_size = MAX_WINDOW;
    recv_flow_window        = MIN_WINDOW;

    struct timeval last_transmission;
    gettimeofday(&last_transmission, NULL);

    char buffer[sizeof(packet) + MAX_PAYLOAD] = {0};
    struct sockaddr_in peer_addr;
    socklen_t addr_size = sizeof(peer_addr);

    // Main Loop
    while (1) {
        struct timeval now;
        gettimeofday(&now, NULL);

        // 1) Possibly send new data if window allows
        size_t bytes_in_flight = 0;
        for (int i = 0; i < send_buffer.count; i++) {
            bytes_in_flight += ntohs(send_buffer.packets[i].length);
        }
        if (bytes_in_flight < send_buffer.window_size) {
            size_t can_send = send_buffer.window_size - bytes_in_flight;
            if (can_send > MAX_PAYLOAD) {
                can_send = MAX_PAYLOAD;
            }
            // read from user's input function
            uint8_t data[MAX_PAYLOAD];
            ssize_t bytes_read = g_input(data, can_send);
            if (bytes_read > 0) {
                // Build a data+ACK packet
                packet send_pkt = {0};
                send_pkt.seq  = htons(seq);
                send_pkt.ack  = htons(ack);
                send_pkt.length = htons(bytes_read);
                send_pkt.win  = htons(recv_flow_window);
                send_pkt.flags= ACK;
                memcpy(send_pkt.payload, data, bytes_read);

                calculate_parity(&send_pkt);
                if (buffer_add(&send_buffer, &send_pkt)) {
                    // actually send
                    send_packet(sockfd, addr, &send_pkt);
                    print_diag(&send_pkt, SEND);

                    seq = (uint16_t)(seq + bytes_read);
                    gettimeofday(&last_transmission, NULL);
                }
            }
        }

        // 2) Read incoming
        addr_size = sizeof(peer_addr);
        int bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                      (struct sockaddr*)&peer_addr, &addr_size);
        if (bytes_received > 0) {
            packet *recv_pkt = (packet*)buffer;

            // parity check
            if (!check_parity(recv_pkt)) {
                // send a corrupt ack
                packet corrupt_ack = {0};
                corrupt_ack.seq  = htons(seq);
                corrupt_ack.ack  = htons(ack);
                corrupt_ack.length = 0;
                corrupt_ack.win  = htons(recv_flow_window);
                corrupt_ack.flags= ACK;
                calculate_parity(&corrupt_ack);
                send_packet(sockfd, addr, &corrupt_ack);
                continue;
            }
            print_diag(recv_pkt, RECV);

            // handle ack
            if (recv_pkt->flags & ACK) {
                process_ack(sockfd, addr, ntohs(recv_pkt->ack));

                // update local window based on their Flow Window
                uint16_t new_win = ntohs(recv_pkt->win);
                if (new_win < MIN_WINDOW) new_win = MIN_WINDOW;
                if (new_win > MAX_WINDOW) new_win = MAX_WINDOW;
                send_buffer.window_size = new_win;
            }
            // handle data
            if (ntohs(recv_pkt->length) > 0) {
                process_data(sockfd, addr, recv_pkt);

                // If we haven't already sent an ACK,
                // we do so now
                if (!ack_sent) {
                    packet data_ack = {0};
                    data_ack.seq    = htons(seq);
                    data_ack.ack    = htons(ack);
                    data_ack.length = 0;
                    data_ack.win    = htons(recv_flow_window);
                    data_ack.flags  = ACK;
                    calculate_parity(&data_ack);
                    send_packet(sockfd, addr, &data_ack);
                    print_diag(&data_ack, SEND);
                }
            }
        }

        // 3) Retransmit if needed
        gettimeofday(&now, NULL);
        for (int i = 0; i < send_buffer.count; i++) {
            long elapsed = TV_DIFF(now, send_buffer.times[i]);
            if (elapsed >= RTO) {
                // retransmit
                retransmit_packet(sockfd, addr, i);
                gettimeofday(&last_transmission, NULL);
            }
        }
    }
}
