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

// Function declarations
void calculate_parity(packet *pkt);
bool check_parity(packet *pkt);
void send_packet(int sockfd, struct sockaddr_in *addr, packet *pkt);
bool perform_handshake(int sockfd, struct sockaddr_in *addr, int type, uint16_t *initial_seq);


// Handshake states
#define HS_INIT 0
#define HS_SYN_SENT 1
#define HS_SYN_RECEIVED 2
#define HS_ESTABLISHED 3

// Function to generate random initial sequence number (keeping it under 1000 as per spec)
static uint16_t generate_initial_seq() {
    srand(time(NULL));
    return rand() % 1000;
}

bool perform_handshake(int sockfd, struct sockaddr_in *addr, int type, uint16_t *initial_seq) {
    char buffer[sizeof(packet) + MAX_PAYLOAD] = {0};
    struct sockaddr_in peer_addr;
    socklen_t addr_size = sizeof(peer_addr);
    struct timeval timeout;
    int handshake_state = HS_INIT;
    *initial_seq = generate_initial_seq();
    
    // Set initial timeout for handshake packets
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    
    while (handshake_state != HS_ESTABLISHED) {
        if (type == CLIENT) {
            if (handshake_state == HS_INIT) {
                // Send initial SYN
                packet syn_pkt = {0};
                syn_pkt.seq = htons(*initial_seq);
                syn_pkt.ack = 0;
                syn_pkt.length = 0;
                syn_pkt.win = htons(MAX_WINDOW);
                syn_pkt.flags = SYN;
                syn_pkt.unused = 0;
                calculate_parity(&syn_pkt);
                
                print_diag(&syn_pkt, SEND);
                send_packet(sockfd, addr, &syn_pkt);
                fprintf(stderr, "CLIENT: Sending SYN, seq=%hu\n", *initial_seq);
                handshake_state = HS_SYN_SENT;
                gettimeofday(&timeout, NULL);  // Reset timeout after sending
                
                // Set socket buffer sizes
                int rcvbuf = 65536;
                int sndbuf = 65536;
                setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
                setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
            }
            else if (handshake_state == HS_SYN_SENT) {
                addr_size = sizeof(peer_addr);  // Reset size before each receive
                int bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                            (struct sockaddr *)&peer_addr, &addr_size);
                
                if (bytes_received > 0) {
                    // Verify packet is from the server
                    if (memcmp(&peer_addr.sin_addr, &addr->sin_addr, sizeof(struct in_addr)) == 0 &&
                        peer_addr.sin_port == addr->sin_port) {
                        
                        packet *recv_pkt = (packet *)buffer;
                        print_diag(recv_pkt, RECV);

                        if (!check_parity(recv_pkt)) {
                            fprintf(stderr, "Received corrupted handshake packet, dropping\n");
                            continue;
                        }
                        
                        // Check if it's a SYN-ACK
                        if ((recv_pkt->flags & (SYN | ACK)) == (SYN | ACK)) {
                            // Send ACK
                            packet ack_pkt = {0};
                            ack_pkt.seq = htons(*initial_seq + 1);
                            ack_pkt.ack = htons(ntohs(recv_pkt->seq) + 1);
                            ack_pkt.length = 0;
                            ack_pkt.win = 0;  // Set to 0 as per reference logs
                            ack_pkt.flags = ACK;
                            ack_pkt.unused = 0;
                            calculate_parity(&ack_pkt);
                            
                            send_packet(sockfd, addr, &ack_pkt);
                            fprintf(stderr, "CLIENT: Sending ACK, seq=%hu, ack=%hu\n", 
                                    *initial_seq + 1, ntohs(recv_pkt->seq) + 1);
                            handshake_state = HS_ESTABLISHED;
                        }
                    }
                }
                
                // Check for timeout
                struct timeval now;
                gettimeofday(&now, NULL);
                if (TV_DIFF(now, timeout) >= RTO) {
                    // Keep the same sequence number for retransmission
                    packet syn_pkt = {0};
                    syn_pkt.seq = htons(*initial_seq);
                    syn_pkt.ack = 0;
                    syn_pkt.length = 0;
                    syn_pkt.win = htons(MAX_WINDOW);
                    syn_pkt.flags = SYN;
                    syn_pkt.unused = 0;
                    calculate_parity(&syn_pkt);
                    
                    print_diag(&syn_pkt, SEND);
                    send_packet(sockfd, addr, &syn_pkt);
                    
                    // Reset timeout and stay in SYN_SENT state
                    gettimeofday(&timeout, NULL);
                }
            }
        }
        else { // SERVER
            // Try to receive packet
            addr_size = sizeof(peer_addr);
            int bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                        (struct sockaddr *)&peer_addr, &addr_size);
                                        
            if (bytes_received > 0) {
                packet *recv_pkt = (packet *)buffer;
                print_diag(recv_pkt, RECV);
                
                if (!check_parity(recv_pkt)) {
                    fprintf(stderr, "Received corrupted handshake packet, dropping\n");
                    continue;
                }
                
                if (handshake_state == HS_INIT && (recv_pkt->flags & SYN)) {
                    // Print diagnostic for received packet
                    print_diag(recv_pkt, RECV);
                    
                    // Received SYN, send SYN-ACK
                    packet synack_pkt = {0};
                    synack_pkt.seq = htons(*initial_seq);
                    synack_pkt.ack = htons(ntohs(recv_pkt->seq) + 1);
                    synack_pkt.length = 0;
                    synack_pkt.win = htons(MIN_WINDOW);  // Start with minimum window
                    synack_pkt.flags = SYN | ACK;
                    synack_pkt.unused = 0;
                    calculate_parity(&synack_pkt);
                    
                    send_packet(sockfd, addr, &synack_pkt);
                    fprintf(stderr, "SERVER: Sending SYN-ACK, seq=%hu, ack=%hu\n", 
                            *initial_seq, ntohs(synack_pkt.ack));
                    handshake_state = HS_SYN_RECEIVED;
                    gettimeofday(&timeout, NULL);
                }
                else if (handshake_state == HS_SYN_RECEIVED && (recv_pkt->flags & ACK)) {
                    // Received final ACK
                    if (ntohs(recv_pkt->ack) == *initial_seq + 1) {
                        fprintf(stderr, "SERVER: Received ACK, handshake complete\n");
                        handshake_state = HS_ESTABLISHED;
                    }
                }
            }
            
            // Check for timeout and retransmit if needed
            if (handshake_state == HS_SYN_RECEIVED) {
                struct timeval now;
                gettimeofday(&now, NULL);
                if (TV_DIFF(now, timeout) >= RTO) {
                    fprintf(stderr, "SERVER: Handshake timeout, retransmitting\n");
                    handshake_state = HS_INIT;
                }
            }
        }
    }
    
    return true;
}


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

void calculate_parity(packet *pkt) {
    // First clear parity bit
    pkt->flags &= ~PARITY;

    // Use bit_count function from consts.h to count 1 bits
    int ones = bit_count(pkt);
    
    // If we have odd number of 1s, set parity bit to make it even
    if (ones % 2 != 0) {
        pkt->flags |= PARITY;
    }
}

bool check_parity(packet *pkt) {
    // Total number of 1 bits should be even
    return (bit_count(pkt) % 2) == 0;
}
void send_packet(int sockfd, struct sockaddr_in *addr, packet *pkt)
{
    if (sendto(sockfd, pkt, sizeof(packet) + ntohs(pkt->length), 0,
               (struct sockaddr *)addr, sizeof(*addr)) < 0)
    {
        perror("sendto");
    }
}

void process_data(packet *pkt) {
    uint16_t recv_seq = ntohs(pkt->seq);
    uint16_t recv_len = ntohs(pkt->length);

    fprintf(stderr, "Processing data packet seq=%hu, expected ack=%hu\n", recv_seq, ack);

    // Special case for the first packet
    if (ack == 0) {
        // Find the lowest sequence number we've received
        uint16_t min_seq = recv_seq;
        for (int i = 0; i < recv_buffer.count; i++) {
            uint16_t buf_seq = ntohs(recv_buffer.packets[i].seq);
            if (buf_seq < min_seq) {
                min_seq = buf_seq;
            }
        }

        // If this is the lowest sequence we've seen, write it
        if (recv_seq == min_seq) {
            fprintf(stderr, "Writing first packet seq=%hu len=%hu\n", recv_seq, recv_len);
            output_p(pkt->payload, recv_len);
            ack = recv_seq + recv_len;

            // Now check buffered packets for sequential packets
            bool found = true;
            while (found && recv_buffer.count > 0) {
                found = false;
                for (int i = 0; i < recv_buffer.count; i++) {
                    uint16_t buf_seq = ntohs(recv_buffer.packets[i].seq);
                    if (buf_seq == ack) {
                        uint16_t buf_len = ntohs(recv_buffer.packets[i].length);
                        fprintf(stderr, "Writing buffered packet seq=%hu len=%hu\n", buf_seq, buf_len);
                        output_p(recv_buffer.packets[i].payload, buf_len);
                        ack += buf_len;

                        // Remove from buffer
                        for (int j = i; j < recv_buffer.count - 1; j++) {
                            memcpy(&recv_buffer.packets[j], &recv_buffer.packets[j + 1],
                                   sizeof(packet) + MAX_PAYLOAD);
                        }
                        recv_buffer.count--;
                        found = true;
                        break;
                    }
                }
            }
        } else {
            // Buffer this packet if it's not the lowest
            if (recv_buffer.count < BUFFER_SIZE) {
                fprintf(stderr, "Buffering packet seq=%hu (waiting for earlier packets)\n", recv_seq);
                memcpy(&recv_buffer.packets[recv_buffer.count], pkt,
                       sizeof(packet) + recv_len);
                recv_buffer.count++;
            }
        }
        return;
    }

    // Normal case for subsequent packets
    if (recv_seq == ack) {
        fprintf(stderr, "Writing packet seq=%hu len=%hu\n", recv_seq, recv_len);
        output_p(pkt->payload, recv_len);
        ack += recv_len;

        // Check for buffered packets that can now be processed
        bool found = true;
        while (found && recv_buffer.count > 0) {
            found = false;
            for (int i = 0; i < recv_buffer.count; i++) {
                uint16_t buf_seq = ntohs(recv_buffer.packets[i].seq);
                if (buf_seq == ack) {
                    uint16_t buf_len = ntohs(recv_buffer.packets[i].length);
                    fprintf(stderr, "Writing buffered packet seq=%hu len=%hu\n", buf_seq, buf_len);
                    output_p(recv_buffer.packets[i].payload, buf_len);
                    ack += buf_len;

                    // Remove from buffer
                    for (int j = i; j < recv_buffer.count - 1; j++) {
                        memcpy(&recv_buffer.packets[j], &recv_buffer.packets[j + 1],
                               sizeof(packet) + MAX_PAYLOAD);
                    }
                    recv_buffer.count--;
                    found = true;
                    break;
                }
            }
        }
    } else if (recv_seq > ack && recv_seq < ack + recv_buffer.window_size) {
        // Future packet - buffer it
        if (recv_buffer.count < BUFFER_SIZE) {
            fprintf(stderr, "Buffering out-of-order packet seq=%hu\n", recv_seq);
            memcpy(&recv_buffer.packets[recv_buffer.count], pkt,
                   sizeof(packet) + recv_len);
            recv_buffer.count++;
        }
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

void process_ack(int sockfd, struct sockaddr_in *addr, uint16_t received_ack) {
    if (received_ack <= last_ack) {
        if (received_ack == last_ack) {
            dup_ack_count++;
            if (dup_ack_count >= DUP_ACKS) {
                // Fast retransmit
                for (int i = 0; i < send_buffer.count; i++) {
                    if (ntohs(send_buffer.packets[i].seq) == last_ack) {
                        retransmit_packet(sockfd, addr, i);
                        break;
                    }
                }
                dup_ack_count = 0;
            }
        }
        return;
    }

    // New ACK
    last_ack = received_ack;
    dup_ack_count = 0;

    // Remove acknowledged packets from send buffer
    while (send_buffer.count > 0) {
        packet *first_pkt = &send_buffer.packets[0];
        if (ntohs(first_pkt->seq) + ntohs(first_pkt->length) <= received_ack) {
            buffer_remove_first(&send_buffer);
        } else {
            break;
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
    void (*output_function)(uint8_t *, size_t)) {
input_p = input_function;
output_p = output_function;

char buffer[sizeof(packet) + MAX_PAYLOAD] = {0};
struct sockaddr_in peer_addr;
socklen_t addr_size = sizeof(peer_addr);

// Set non-blocking
int flags = fcntl(sockfd, F_GETFL, 0);
fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

// Initialize sequence numbers and buffers
uint16_t initial_seq;
if (!perform_handshake(sockfd, addr, type, &initial_seq)) {
fprintf(stderr, "Handshake failed\n");
return;
}

seq = initial_seq + 1;
ack = 0;
last_ack = 0;
dup_ack_count = 0;

send_buffer.count = 0;
send_buffer.window_size = MIN_WINDOW;
recv_buffer.count = 0;
recv_buffer.window_size = MAX_WINDOW;

struct timeval last_transmission;
gettimeofday(&last_transmission, NULL);

while (1) {
struct timeval now;
gettimeofday(&now, NULL);

// Calculate bytes in flight
size_t bytes_in_flight = 0;
for (int i = 0; i < send_buffer.count; i++) {
bytes_in_flight += ntohs(send_buffer.packets[i].length);
}

// Try to send new data if window allows
if (bytes_in_flight < send_buffer.window_size) {
uint8_t data[MAX_PAYLOAD];
ssize_t bytes_read = input_p(data, MIN(MAX_PAYLOAD,
                                    send_buffer.window_size - bytes_in_flight));

if (bytes_read > 0) {
   packet send_pkt = {0};
   send_pkt.seq = htons(seq);
   send_pkt.ack = htons(ack);
   send_pkt.length = htons(bytes_read);
   send_pkt.win = htons(MAX_WINDOW - recv_buffer.count * MAX_PAYLOAD);
   send_pkt.flags = ACK;
   memcpy(send_pkt.payload, data, bytes_read);
   calculate_parity(&send_pkt);

   if (buffer_add(&send_buffer, &send_pkt)) {
       send_packet(sockfd, addr, &send_pkt);
       print_diag(&send_pkt, SEND);
       seq += bytes_read;
       gettimeofday(&last_transmission, NULL);
   }
}
}

// Receive packets
addr_size = sizeof(peer_addr);
int bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                       (struct sockaddr *)&peer_addr, &addr_size);

if (bytes_received > 0) {
packet *recv_pkt = (packet *)buffer;

if (!check_parity(recv_pkt)) {
   fprintf(stderr, "[%s] Corrupted packet received, dropping\n",
           type == SERVER ? "SERVER" : "CLIENT");
   // Send duplicate ACK
   packet ack_pkt = {0};
   ack_pkt.seq = htons(seq);
   ack_pkt.ack = htons(ack);
   ack_pkt.length = 0;
   ack_pkt.win = htons(MAX_WINDOW - recv_buffer.count * MAX_PAYLOAD);
   ack_pkt.flags = ACK;
   calculate_parity(&ack_pkt);
   send_packet(sockfd, addr, &ack_pkt);
   continue;
}

print_diag(recv_pkt, RECV);

// Process acknowledgments
if (recv_pkt->flags & ACK) {
   process_ack(sockfd, addr, ntohs(recv_pkt->ack));
   send_buffer.window_size = ntohs(recv_pkt->win);
}

// Process data
if (ntohs(recv_pkt->length) > 0) {
   process_data(recv_pkt);

   // Send ACK
   packet ack_pkt = {0};
   ack_pkt.seq = htons(seq);
   ack_pkt.ack = htons(ack);
   ack_pkt.length = 0;
   ack_pkt.win = htons(MAX_WINDOW - recv_buffer.count * MAX_PAYLOAD);
   ack_pkt.flags = ACK;
   calculate_parity(&ack_pkt);
   send_packet(sockfd, addr, &ack_pkt);
   print_diag(&ack_pkt, SEND);
}
}

// Check for timeouts and retransmit if needed
for (int i = 0; i < send_buffer.count; i++) {
if (TV_DIFF(now, send_buffer.times[i]) >= RTO) {
   retransmit_packet(sockfd, addr, i);
   gettimeofday(&last_transmission, NULL);
}
}

// Prevent CPU spinning
usleep(1000);
}
}