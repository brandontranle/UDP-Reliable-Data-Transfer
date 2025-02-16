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
uint16_t recv_flow_window;


#define BUFFER_SIZE 40
#define FAST_RETRANSMIT_THRESHOLD 3
#define MAX_RETRANSMIT_ATTEMPTS 5

static inline int16_t seq_diff(uint16_t a, uint16_t b) {
    return (int16_t)(a - b);
}


// ---------- FORWARD DECLARATIONS ----------
void calculate_parity(packet *pkt);
bool check_parity(packet *pkt);
void send_packet(int sockfd, struct sockaddr_in *addr, packet *pkt);

bool perform_handshake(int sockfd, struct sockaddr_in *addr, int type,
                       uint16_t *local_init_seq, uint16_t *remote_init_seq);

static uint16_t generate_initial_seq() {
    srand(time(NULL));
    return rand() % 1000; // or any small random range
}

// -------------- HANDSHAKE LOGIC --------------
#define HS_INIT 0
#define HS_SYN_SENT 1
#define HS_SYN_RECEIVED 2
#define HS_ESTABLISHED 3

bool perform_handshake(int sockfd, struct sockaddr_in *addr, int type,
                       uint16_t *local_init_seq, uint16_t *remote_init_seq)
{
    // We store local & remote seqs in local variables, then output them
    char buffer[sizeof(packet) + MAX_PAYLOAD] = {0};
    struct sockaddr_in peer_addr;
    socklen_t addr_size = sizeof(peer_addr);
    struct timeval timeout;
    int handshake_state = HS_INIT;

    // Generate & store the local seq
    *local_init_seq = generate_initial_seq();
    *remote_init_seq = 0; // We'll fill once we see the peer's SYN

    // 1-second handshake RTO
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    while (handshake_state != HS_ESTABLISHED) {
        if (type == CLIENT) {
            // CLIENT side
            if (handshake_state == HS_INIT) {
                // Send SYN
                packet syn_pkt = {0};
                syn_pkt.seq = htons(*local_init_seq);
                syn_pkt.ack = 0;
                syn_pkt.length = 0;
                syn_pkt.win = htons(MAX_WINDOW);
                syn_pkt.flags = SYN;
                syn_pkt.unused = 0;

                calculate_parity(&syn_pkt);
                print_diag(&syn_pkt, SEND);
                send_packet(sockfd, addr, &syn_pkt);

                //fprintf(stderr, "CLIENT: Sending SYN, seq=%hu\n", *local_init_seq);
                handshake_state = HS_SYN_SENT;
                gettimeofday(&timeout, NULL);

                // Optionally set buffer sizes
                int rcvbuf = 65536;
                int sndbuf = 65536;
                setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
                setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
            }
            else if (handshake_state == HS_SYN_SENT) {
                // Wait for SYN-ACK from server
                addr_size = sizeof(peer_addr);
                int bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                    (struct sockaddr *)&peer_addr, &addr_size);

                if (bytes_received > 0) {
                    // Confirm from correct server
                    if (memcmp(&peer_addr.sin_addr, &addr->sin_addr, sizeof(struct in_addr)) == 0 &&
                        peer_addr.sin_port == addr->sin_port)
                    {
                        packet *recv_pkt = (packet *)buffer;
                        print_diag(recv_pkt, RECV);

                        if (!check_parity(recv_pkt)) {
                            //fprintf(stderr, "CLIENT: Corrupted handshake packet, dropping\n");
                            continue;
                        }
                        // Check if it's SYN+ACK
                        if ((recv_pkt->flags & (SYN | ACK)) == (SYN | ACK)) {
                            // Record server's initial sequence
                            *remote_init_seq = ntohs(recv_pkt->seq);

                            // Send final ACK
                            packet ack_pkt = {0};
                            ack_pkt.seq = htons((*local_init_seq) + 1);
                            ack_pkt.ack = htons((*remote_init_seq) + 1);
                            ack_pkt.length = 0;
                            ack_pkt.win = 0; // match reference logs
                            ack_pkt.flags = ACK;
                            ack_pkt.unused = 0;

                            calculate_parity(&ack_pkt);
                            send_packet(sockfd, addr, &ack_pkt);
                            
                            /*
                            fprintf(stderr, "CLIENT: Sending final ACK, seq=%hu, ack=%hu\n",
                                    (*local_init_seq + 1),
                                    (*remote_init_seq + 1));
                            */
                            handshake_state = HS_ESTABLISHED;
                        }
                    }
                }

                // Check for handshake timeout
                struct timeval now;
                gettimeofday(&now, NULL);
                if (TV_DIFF(now, timeout) >= RTO) {
                    // Retransmit SYN
                    packet syn_pkt = {0};
                    syn_pkt.seq = htons(*local_init_seq);
                    syn_pkt.ack = 0;
                    syn_pkt.length = 0;
                    syn_pkt.win = htons(MAX_WINDOW);
                    syn_pkt.flags = SYN;
                    syn_pkt.unused = 0;

                    calculate_parity(&syn_pkt);
                    print_diag(&syn_pkt, SEND);
                    send_packet(sockfd, addr, &syn_pkt);

                    gettimeofday(&timeout, NULL);
                }
            }
        }
        else {
            // SERVER side
            addr_size = sizeof(peer_addr);
            int bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                (struct sockaddr *)&peer_addr, &addr_size);

            if (bytes_received > 0) {
                packet *recv_pkt = (packet *)buffer;
                print_diag(recv_pkt, RECV);

                if (!check_parity(recv_pkt)) {
                    //fprintf(stderr, "SERVER: Corrupted handshake packet, dropping\n");
                    continue;
                }

                if (handshake_state == HS_INIT && (recv_pkt->flags & SYN)) {
                    // Received client SYN
                    // Save client's initial seq
                    *remote_init_seq = ntohs(recv_pkt->seq);

                    // Send SYN+ACK
                    packet synack_pkt = {0};
                    synack_pkt.seq = htons(*local_init_seq);
                    synack_pkt.ack = htons((*remote_init_seq) + 1);
                    synack_pkt.length = 0;
                    synack_pkt.win = htons(MIN_WINDOW); // start with min window
                    synack_pkt.flags = SYN | ACK;
                    synack_pkt.unused = 0;

                    calculate_parity(&synack_pkt);
                    send_packet(sockfd, addr, &synack_pkt);
                    
                    /*
                    fprintf(stderr, "SERVER: Sending SYN-ACK, seq=%hu, ack=%hu\n",
                            *local_init_seq,
                            (*remote_init_seq + 1));
                    */
                    handshake_state = HS_SYN_RECEIVED;
                    gettimeofday(&timeout, NULL);
                }
                else if (handshake_state == HS_SYN_RECEIVED && (recv_pkt->flags & ACK)) {
                    // Final ACK
                    uint16_t their_ack = ntohs(recv_pkt->ack);
                    if (their_ack == (*local_init_seq + 1)) {
                        //fprintf(stderr, "SERVER: Received final ACK, handshake complete\n");
                        handshake_state = HS_ESTABLISHED;
                    }
                }
            }

            // Check for handshake timeout if needed
            if (handshake_state == HS_SYN_RECEIVED) {
                struct timeval now;
                gettimeofday(&now, NULL);
                if (TV_DIFF(now, timeout) >= RTO) {
                    //fprintf(stderr, "SERVER: Handshake timeout, restarting\n");
                    handshake_state = HS_INIT;
                }
            }
        }
    }

    return true;
}

// At the top of transport.c, after includes, add:
typedef struct {
    uint16_t seq;
    uint16_t ack;
    uint16_t length;
    uint16_t win;
    uint16_t flags; // LSb 0 SYN, LSb 1 ACK, LSb 2 PARITY
    uint16_t unused;
    uint8_t payload[MAX_PAYLOAD];  // allocate full payload space
} full_packet;

// Then update your Buffer definitions:
typedef struct {
    full_packet packets[BUFFER_SIZE];
    struct timeval times[BUFFER_SIZE];
    int retransmit_count[BUFFER_SIZE];
    int count;
    uint16_t window_start;
    uint16_t window_size;
} Buffer;

Buffer send_buffer = {.count = 0, .window_start = 0, .window_size = MAX_WINDOW};
Buffer recv_buffer = {.count = 0, .window_start = 0, .window_size = MAX_WINDOW};

ssize_t (*input_p)(uint8_t *, size_t);
void (*output_p)(uint8_t *, size_t);

// -------------- BUFFER HELPERS --------------
bool buffer_add(Buffer *buf, packet *pkt)
{
    if (buf->count >= BUFFER_SIZE) return false;
    size_t pkt_size = sizeof(packet) + ntohs(pkt->length); 
    // Copy into our full_packet buffer (we have enough room because payload is fixed size)
    memcpy(&buf->packets[buf->count], pkt, pkt_size);
    gettimeofday(&buf->times[buf->count], NULL);
    buf->retransmit_count[buf->count] = 0;
    buf->count++;
    return true;
}

void buffer_remove_first(Buffer *buf)
{
    if (buf->count <= 0) return;
    for (int i = 0; i < buf->count - 1; i++) {
        memmove(&buf->packets[i], &buf->packets[i + 1], sizeof(full_packet));
        buf->times[i] = buf->times[i + 1];
        buf->retransmit_count[i] = buf->retransmit_count[i + 1];
    }
    buf->count--;
}



bool is_in_window(uint16_t seq_num, uint16_t window_start, uint16_t window_size)
{
    return (seq_num >= window_start) && (seq_num < (window_start + window_size));
}

void calculate_parity(packet *pkt) {
    pkt->flags &= ~PARITY; // clear PARITY bit first
    int ones = bit_count(pkt);
    if (ones % 2 != 0) {
        pkt->flags |= PARITY;
    }
}

bool check_parity(packet *pkt) {
    return (bit_count(pkt) % 2) == 0;
}

void send_packet(int sockfd, struct sockaddr_in *addr, packet *pkt)
{
    sendto(sockfd, pkt, sizeof(packet) + ntohs(pkt->length), 0,
           (struct sockaddr *)addr, sizeof(*addr));
}

// ---------- RETRANSMIT / HANDLING FUNCTIONS -----------
void retransmit_packet(int sockfd, struct sockaddr_in *addr, int index)
{
    if (index < 0 || index >= send_buffer.count) return;

    packet *pkt = (packet *)&send_buffer.packets[index];
    uint16_t seq_num = ntohs(pkt->seq);
    uint16_t length = ntohs(pkt->length);

    // If it’s already fully acked, skip
    if ((seq_num + length) <= last_ack) {
        return;
    }
    if (send_buffer.retransmit_count[index] < MAX_RETRANSMIT_ATTEMPTS) {
        send_packet(sockfd, addr, pkt);
        gettimeofday(&send_buffer.times[index], NULL);
        send_buffer.retransmit_count[index]++;

        /*
        fprintf(stderr, "[%s] Retransmitting seq=%hu (attempt %d)\n",
                (state == SERVER ? "SERVER" : "CLIENT"),
                seq_num, send_buffer.retransmit_count[index]);
        */
    }
}
void process_ack(int sockfd, struct sockaddr_in *addr, uint16_t received_ack)
{
    // If ack is not greater than last_ack, treat it as duplicate
    if (seq_diff(received_ack, last_ack) <= 0) {
        if (received_ack == last_ack) {
            dup_ack_count++;
            if (dup_ack_count >= DUP_ACKS) {
                // Fast retransmit: retransmit the first unacked packet
                if (send_buffer.count > 0) {
                    retransmit_packet(sockfd, addr, 0);
                }
                dup_ack_count = 0;
            }
        }
        return;
    }

    // New ack received
    last_ack = received_ack;
    dup_ack_count = 0;

    // Remove fully acknowledged packets from send buffer using seq_diff for wrap-around
    while (send_buffer.count > 0) {
        packet *first_pkt = (packet *)&send_buffer.packets[0];
        uint16_t first_seq = ntohs(first_pkt->seq);
        uint16_t first_len = ntohs(first_pkt->length);
        uint16_t packet_end = (uint16_t)(first_seq + first_len);
        if (seq_diff(received_ack, packet_end) >= 0) {
            buffer_remove_first(&send_buffer);
        } else {
            break;
        }
    }

    // Reset timer for the oldest unacked packet, if any
    if (send_buffer.count > 0) {
        gettimeofday(&send_buffer.times[0], NULL);
    }
}

// In process_data, update the shifting loop similarly:
void process_data(int sockfd, struct sockaddr_in *addr, packet *pkt)
{
    uint16_t recv_seq = ntohs(pkt->seq);
uint16_t recv_len = ntohs(pkt->length);
int16_t diff = seq_diff(recv_seq, ack);
if (diff == 0) {
    // in-order: deliver the payload
    output_p(pkt->payload, recv_len);

    // Increase advertised window gradually (by 500 bytes, capped at MAX_WINDOW)
    if (recv_flow_window < MAX_WINDOW) {
        uint16_t new_win = recv_flow_window + 500;
        recv_flow_window = (new_win > MAX_WINDOW) ? MAX_WINDOW : new_win;
    }

    ack = (uint16_t)(ack + recv_len);  // addition modulo 2^16
    bool found = true;
    while (found && recv_buffer.count > 0) {
        found = false;
        for (int i = 0; i < recv_buffer.count; i++) {
            uint16_t buf_seq = ntohs(recv_buffer.packets[i].seq);
            uint16_t buf_len = ntohs(recv_buffer.packets[i].length);
            if (seq_diff(buf_seq, ack) == 0) {
                output_p(recv_buffer.packets[i].payload, buf_len);

                if (recv_flow_window < MAX_WINDOW) {
                    uint16_t new_win = recv_flow_window + 500;
                    recv_flow_window = (new_win > MAX_WINDOW) ? MAX_WINDOW : new_win;
                }


                ack = (uint16_t)(ack + buf_len);
                // Shift remaining buffered packets
                // Shift buffered packets using fixed block size
for (int j = i; j < recv_buffer.count - 1; j++) {
    memmove(&recv_buffer.packets[j], &recv_buffer.packets[j + 1], sizeof(full_packet));
}

                recv_buffer.count--;
                found = true;
                break;
            }
        }
    }
} else if (diff > 0) {
    // Packet is in the future: buffer it
    if (recv_buffer.count < BUFFER_SIZE) {
        int pkt_size = sizeof(packet) + recv_len;
        memcpy(&recv_buffer.packets[recv_buffer.count], pkt, pkt_size);
        recv_buffer.count++;
    }
} else {
    // Duplicate or old packet: send duplicate ACK
    packet ack_pkt = {0};
    ack_pkt.seq = htons(seq);
    ack_pkt.ack = htons(ack);
    ack_pkt.length = 0;
    ack_pkt.win = htons(recv_flow_window);
    ack_pkt.flags = ACK;
    calculate_parity(&ack_pkt);
    send_packet(sockfd, addr, &ack_pkt);
}

}

// ------------- MAIN LOOP -------------
void listen_loop(int sockfd, struct sockaddr_in *addr, int type,
    ssize_t (*input_function)(uint8_t *, size_t),
    void (*output_function)(uint8_t *, size_t))
{
    input_p = input_function;
    output_p = output_function;

    // set non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    // Prepare handshake
    uint16_t local_seq, remote_seq;
    if (!perform_handshake(sockfd, addr, type, &local_seq, &remote_seq)) {
       //fprintf(stderr, "Handshake failed\n");
        return;
    }

    // Now that handshake is done:
    seq = local_seq + 1;       // next to send
    ack = remote_seq + 1;      // next expected from peer
    last_ack = 0;
    dup_ack_count = 0;
    send_buffer.count = 0;
    recv_buffer.count = 0;
    send_buffer.window_size = MIN_WINDOW; // initial sender window
    recv_buffer.window_size = MAX_WINDOW; // not used now, but kept for symmetry
    recv_flow_window = MIN_WINDOW;         // initialize our advertised window

    // run loop
    struct timeval last_transmission;
    gettimeofday(&last_transmission, NULL);

    char buffer[sizeof(packet) + MAX_PAYLOAD] = {0};
    struct sockaddr_in peer_addr;
    socklen_t addr_size = sizeof(peer_addr);

    while (1) {
        struct timeval now;
        gettimeofday(&now, NULL);

        // measure bytes in flight
        size_t bytes_in_flight = 0;
        for (int i = 0; i < send_buffer.count; i++) {
            bytes_in_flight += ntohs(send_buffer.packets[i].length);
        }

        // Attempt to send new data if window allows
        if (bytes_in_flight < send_buffer.window_size) {
            uint8_t data[MAX_PAYLOAD];
            size_t can_send = send_buffer.window_size - bytes_in_flight;
            if (can_send > MAX_PAYLOAD) {
                can_send = MAX_PAYLOAD;
            }
            ssize_t bytes_read = input_p(data, can_send);
            if (bytes_read > 0) {
                packet send_pkt = {0};
                send_pkt.seq = htons(seq);
                send_pkt.ack = htons(ack);
                send_pkt.length = htons(bytes_read);
                send_pkt.win = htons(MAX_WINDOW - recv_buffer.count * MAX_PAYLOAD);
                send_pkt.flags = ACK; // data packet with ACK bit set
                memcpy(send_pkt.payload, data, bytes_read);

                calculate_parity(&send_pkt);
                if (buffer_add(&send_buffer, &send_pkt)) {
                    send_packet(sockfd, addr, &send_pkt);
                    print_diag(&send_pkt, SEND);
                    seq = (uint16_t)(seq + bytes_read);
                    gettimeofday(&last_transmission, NULL);
                }
            }
        }

        // Receive inbound packets
        addr_size = sizeof(peer_addr);
        int bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                      (struct sockaddr *)&peer_addr, &addr_size);
        if (bytes_received > 0) {
            packet *recv_pkt = (packet *)buffer;
            if (!check_parity(recv_pkt)) {
                packet ack_pkt = {0};
                ack_pkt.seq = htons(seq);
                ack_pkt.ack = htons(ack);
                ack_pkt.length = 0;
                ack_pkt.win = htons(recv_flow_window);
                ack_pkt.flags = ACK;
                calculate_parity(&ack_pkt);
                send_packet(sockfd, addr, &ack_pkt);
                continue;
            }
            

            print_diag(recv_pkt, RECV);

            // Process ack field
            if (recv_pkt->flags & ACK) {
                process_ack(sockfd, addr, ntohs(recv_pkt->ack));
                // update window
                send_buffer.window_size = ntohs(recv_pkt->win);
                if (send_buffer.window_size < MIN_WINDOW) {
                    send_buffer.window_size = MIN_WINDOW;
                }
                else if (send_buffer.window_size > MAX_WINDOW) {
                    send_buffer.window_size = MAX_WINDOW;
                }
            }

            // Process data
            if (ntohs(recv_pkt->length) > 0) {
                process_data(sockfd, addr, recv_pkt);

                // always send ack back
                packet ack_pkt = {0};
                ack_pkt.seq = htons(seq);
                ack_pkt.ack = htons(ack);
                ack_pkt.length = 0;
                ack_pkt.win = htons(recv_flow_window);
                ack_pkt.flags = ACK;
                calculate_parity(&ack_pkt);
                send_packet(sockfd, addr, &ack_pkt);
                print_diag(&ack_pkt, SEND);
            }
        }

        // Check timeouts for unacked packets
        gettimeofday(&now, NULL);
        for (int i = 0; i < send_buffer.count; i++) {
            if (TV_DIFF(now, send_buffer.times[i]) >= RTO) {
                retransmit_packet(sockfd, addr, i);
                gettimeofday(&last_transmission, NULL);
            }
        }
    }
}