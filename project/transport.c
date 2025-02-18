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

#define BUFFER_SIZE 256  // Increased buffer size
#define FAST_RETRANSMIT_THRESHOLD 3
#define MAX_RETRANSMIT_ATTEMPTS 10  // Increased max retransmit attempts

// Global variables
int state = 0;
uint32_t seq = 0;
uint32_t ack = 0;
uint16_t last_ack = 0;
int dup_ack_count = 0;
uint16_t last_retransmit_seq = 0;
uint16_t recv_flow_window;
static int g_type = 0;

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

void debug_print(const char* message) {
    FILE* debug_file = fopen("client_debug.log", "a");
    if (debug_file) {
        fprintf(debug_file, "%s\n", message);
        fclose(debug_file);
    }
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
                syn_pkt.win    = htons(MIN_WINDOW);
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

                            // Process any piggybacked data from the SYN|ACK packet
                            uint16_t payload_len = ntohs(recv_pkt->length);
                            if (payload_len > 0) {
                                g_output(recv_pkt->payload, payload_len);
                            }

                            // Send final ACK
                            packet ack_pkt = {0};
                            ack_pkt.seq    = htons(*local_init_seq + 1);  // Next seq after SYN
                            ack_pkt.ack    = htons((*remote_init_seq) + 1);
                            ack_pkt.length = 0;
                            // Use MIN_WINDOW initially to match reference implementation
                            ack_pkt.win    = htons(MIN_WINDOW);
                            ack_pkt.flags  = ACK;
                            ack_pkt.unused = 0;
                            calculate_parity(&ack_pkt);
                            print_diag(&ack_pkt, SEND);
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
                    // Process any piggybacked data in the SYN packet 
                    uint16_t payload_len = ntohs(recv_pkt->length); 
                    if (payload_len > 0) { g_output(recv_pkt->payload, payload_len); }

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
    // In perform_handshake()
    char debug_msg[256];
    snprintf(debug_msg, sizeof(debug_msg), "Handshake: local_seq=%d, remote_seq=%d", 
            *local_init_seq, *remote_init_seq);
    debug_print(debug_msg);
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

// Add a packet to the send buffer
static bool buffer_add(Buffer *buf, packet *pkt) {
    if (buf->count >= BUFFER_SIZE) {
        debug_print("Buffer add failed: buffer is full");
        return false;
    }
    
    uint16_t pkt_len = ntohs(pkt->length);
    
    // Calculate bytes in flight only from unacknowledged packets
    size_t bytes_in_flight = 0;
    for (int i = 0; i < buf->count; i++) {
        bytes_in_flight += ntohs(buf->packets[i].length);
    }
    
    // Check if adding this packet would exceed window
    if (bytes_in_flight + pkt_len > buf->window_size) {
        char debug_msg[256];
        snprintf(debug_msg, sizeof(debug_msg), 
                "Buffer add failed: window exceeded. in_flight=%zu, new_len=%d, window=%d",
                bytes_in_flight, pkt_len, buf->window_size);
        debug_print(debug_msg);
        return false;
    }
    
    // Add packet to buffer
    memcpy(&buf->packets[buf->count], pkt, sizeof(packet) + pkt_len);
    gettimeofday(&buf->times[buf->count], NULL);
    buf->retransmit_count[buf->count] = 0;
    
    char debug_msg[256];
    snprintf(debug_msg, sizeof(debug_msg), 
            "Added packet to buffer: seq=%d, len=%d, pos=%d",
            ntohs(pkt->seq), pkt_len, buf->count);
    debug_print(debug_msg);
    
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

// Retransmit a packet at specific index
// Retransmit a packet at specific index
static void retransmit_packet(int sockfd, struct sockaddr_in *addr, int index)
{
    if (index < 0 || index >= send_buffer.count) 
        return;

    packet *pkt = (packet *)&send_buffer.packets[index];
    uint16_t seq_num = ntohs(pkt->seq);

    // CRITICAL FIX: Don't check against last_ack, but ensure the packet
    // is still part of our send window
    // This ensures we don't drop packets due to ACK misinterpretation

    if (send_buffer.retransmit_count[index] < MAX_RETRANSMIT_ATTEMPTS) {
        // When retransmitting, update the ACK field with current expected ACK
        // This ensures we're communicating the latest state
        pkt->ack = htons(ack);
        
        // Recalculate parity since we changed the ACK field
        calculate_parity(pkt);
        
        print_diag(pkt, RTOS);
        send_packet(sockfd, addr, pkt);
        gettimeofday(&send_buffer.times[index], NULL);
        send_buffer.retransmit_count[index]++;
        
        char debug_msg[256];
        snprintf(debug_msg, sizeof(debug_msg), 
                "Retransmitting packet %d of %d: seq=%d, ack=%d, attempt=%d", 
                index, send_buffer.count, seq_num, ack, 
                send_buffer.retransmit_count[index]);
        debug_print(debug_msg);
    } else {
        // Log that we've reached maximum attempts
        char debug_msg[256];
        snprintf(debug_msg, sizeof(debug_msg),
                "WARNING: Maximum retransmission attempts (%d) reached for packet seq=%d",
                MAX_RETRANSMIT_ATTEMPTS, seq_num);
        debug_print(debug_msg);
    }
}

// -------------- ACK Handling --------------
static void process_ack(int sockfd, struct sockaddr_in *addr, packet *recv_pkt) {
    // Remove the duplicate variable declarations
    uint16_t received_ack_val = ntohs(recv_pkt->ack);
    uint16_t received_win_val = ntohs(recv_pkt->win);
    
    // Debugging
    char debug_msg[256];
    snprintf(debug_msg, sizeof(debug_msg), "Processing ACK: received_ack=%d, last_ack=%d, buffer_count=%d",
             received_ack_val, last_ack, send_buffer.count);
    debug_print(debug_msg);
    
    // More conservative window adjustment to match reference implementation
    if (received_win_val >= MIN_WINDOW && received_win_val <= MAX_WINDOW) {
        // Don't immediately jump to max window - be more conservative
        if (g_type == CLIENT) {
            // For client, respect server's window exactly
            send_buffer.window_size = received_win_val;
        } else {
            // For server, increase window more gradually
            if (received_win_val > send_buffer.window_size) {
                // Increase by at most 500 bytes at a time
                uint16_t increase = received_win_val - send_buffer.window_size;
                if (increase > 500) increase = 500;
                send_buffer.window_size += increase;
            }
        }
    } else if (received_win_val > MAX_WINDOW) {
        send_buffer.window_size = MAX_WINDOW;
    }
    
    if (send_buffer.count == 0) return;
    
    int32_t diff_val = seq_diff(received_ack_val, last_ack);
    // Modify process_ack function:
    if (diff_val > 0) {
        // Valid new ACK
        last_ack = received_ack_val;
        dup_ack_count = 0;
        
        // Show buffer before removal
        debug_print("Send buffer before removal:");
        for (int i = 0; i < send_buffer.count; i++) {
            char msg[100];
            snprintf(msg, sizeof(msg), "  Buffer[%d]: seq=%d", 
                    i, ntohs(send_buffer.packets[i].seq));
            debug_print(msg);
        }
        
        // Count packets to remove
        int to_remove = 0;
        for (int i = 0; i < send_buffer.count; i++) {
            uint16_t seq_num = ntohs(send_buffer.packets[i].seq);
            if (seq_diff(received_ack_val, seq_num) > 0) {
                to_remove++;
            } else {
                break;
            }
        }
        
        // Log how many we'll remove
        char msg[100];
        snprintf(msg, sizeof(msg), "Will remove %d of %d packets, ack=%d", 
                to_remove, send_buffer.count, received_ack_val);
        debug_print(msg);
        
        // Remove acknowledged packets one by one
        for (int i = 0; i < to_remove; i++) {
            if (send_buffer.count == 0) break;
            
            packet *pkt = (packet *)&send_buffer.packets[0];
            uint16_t seq_num = ntohs(pkt->seq);
            buffer_remove_first(&send_buffer);
            
            snprintf(msg, sizeof(msg), "Removed packet: seq=%d, remaining=%d", 
                    seq_num, send_buffer.count);
            debug_print(msg);
        }
    }
   
}
// -------------- Data Handling --------------
static void process_data(int sockfd, struct sockaddr_in *addr, packet *pkt) {
    ack_sent = 0;
    uint16_t recv_seq = ntohs(pkt->seq);
    uint16_t recv_len = ntohs(pkt->length);
    
    // Handle pure ACK packets separately
    if (recv_seq == 0 && recv_len == 0) {
        if (pkt->flags & ACK) {
            process_ack(sockfd, addr, pkt);
        }
        return;
    }
    
    // CRITICAL FIX: Process data BEFORE handling ACK field
    // This fixes the issue where client acknowledges future packets
    
    // Only update ACK if this packet is the one we're expecting
    int32_t diff = seq_diff(recv_seq, ack);
    
    // Debug
    char debug_msg[256];
    snprintf(debug_msg, sizeof(debug_msg), 
            "Data packet: seq=%d, expected=%d, diff=%d", 
            recv_seq, ack, diff);
    debug_print(debug_msg);
    
    if (diff == 0) {  // In-order packet
        // Process current packet's data
        if (recv_len > 0) {
            g_output(pkt->payload, recv_len);
        }
        
        // Update our ACK to acknowledge this packet
        ack = (uint16_t)(recv_seq + 1);
        
        // Process any buffered packets that are now in sequence
        bool made_progress = true;
        while (made_progress && recv_buffer.count > 0) {
            made_progress = false;
            for (int i = 0; i < recv_buffer.count; i++) {
                packet *buf_pkt = (packet *)&recv_buffer.packets[i];
                uint16_t buf_seq = ntohs(buf_pkt->seq);
                
                if (buf_seq == ack) {
                    // Found next packet in sequence
                    uint16_t buf_len = ntohs(buf_pkt->length);
                    if (buf_len > 0) {
                        g_output(buf_pkt->payload, buf_len);
                    }
                    ack = (uint16_t)(buf_seq + 1);
                    
                    // Remove processed packet from buffer
                    memmove(&recv_buffer.packets[i], 
                           &recv_buffer.packets[i + 1],
                           (recv_buffer.count - i - 1) * sizeof(full_packet));
                    recv_buffer.count--;
                    made_progress = true;
                    break;
                }
            }
        }
    } else if (diff > 0) {  // Future packet - buffer it
        // Check if we already have this packet
        bool duplicate = false;
        for (int i = 0; i < recv_buffer.count; i++) {
            if (ntohs(recv_buffer.packets[i].seq) == recv_seq) {
                duplicate = true;
                break;
            }
        }
        
        if (!duplicate && recv_buffer.count < BUFFER_SIZE) {
            // Find position to insert (maintain sorted order)
            int insert_pos = 0;
            while (insert_pos < recv_buffer.count) {
                if (seq_diff(recv_seq, ntohs(recv_buffer.packets[insert_pos].seq)) < 0)
                    break;
                insert_pos++;
            }
            
            // Make space
            if (insert_pos < recv_buffer.count) {
                memmove(&recv_buffer.packets[insert_pos + 1],
                       &recv_buffer.packets[insert_pos],
                       (recv_buffer.count - insert_pos) * sizeof(full_packet));
            }
            
            // Insert packet
            memcpy(&recv_buffer.packets[insert_pos], pkt, 
                   sizeof(packet) + recv_len);
            recv_buffer.count++;
        }
    }
    
    // Now process ACK field
    if (pkt->flags & ACK) {
        process_ack(sockfd, addr, pkt);
    }
    
    // Send acknowledgment if we haven't yet
    if (!ack_sent) {
        packet ack_pkt = {0};
        ack_pkt.seq = 0;  // Use 0 for pure ACKs
        ack_pkt.ack = htons(ack);  // Important: only ACK what we've actually received
        ack_pkt.length = 0;
        
        static uint16_t window_growth = 0;
        if (window_growth < MAX_WINDOW - MIN_WINDOW) {
            window_growth += 500;
        }
        uint16_t current_window = MIN_WINDOW + window_growth;
        if (current_window > MAX_WINDOW) current_window = MAX_WINDOW;
        
        ack_pkt.win = htons(current_window);
        ack_pkt.flags = ACK;
        calculate_parity(&ack_pkt);
        print_diag(&ack_pkt, SEND);
        send_packet(sockfd, addr, &ack_pkt);
        ack_sent = 1;
    }
}

// -------------- Main I/O Loop --------------
void listen_loop(int sockfd, struct sockaddr_in* addr, int type,
                 ssize_t (*input_function)(uint8_t*, size_t),
                 void (*output_function)(uint8_t*, size_t))
{
    // Store function pointers globally
    g_type = type; // remember whether we're CLIENT or SERVER
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
    last_ack = seq;  // Important: initialize last_ack

    send_buffer.count = 0;
    recv_buffer.count = 0;

    // Use MIN_WINDOW initially to match reference implementation behavior
    send_buffer.window_size = MIN_WINDOW;
    recv_buffer.window_size = MIN_WINDOW;
    recv_flow_window = MIN_WINDOW;

    struct timeval last_transmission;
    gettimeofday(&last_transmission, NULL);

    char buffer[sizeof(packet) + MAX_PAYLOAD] = {0};
    struct sockaddr_in peer_addr;
    socklen_t addr_size = sizeof(peer_addr);

    //uint16_t current_window_size = MIN_WINDOW;  // Start with minimum window
    //uint16_t last_acknowledged_seq = 0;

    // Main Loop
    while (1) {
        struct timeval now;
        gettimeofday(&now, NULL);

        // 1) Read incoming packets (prioritize)
        addr_size = sizeof(peer_addr);
        int bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                      (struct sockaddr*)&peer_addr, &addr_size);
        if (bytes_received > 0) {
            packet *recv_pkt = (packet*)buffer;
            
            // Check parity
            if (!check_parity(recv_pkt)) {
                // Create a pure ACK for the last good packet
                packet ack_pkt = {0};
                ack_pkt.seq = 0;
                ack_pkt.ack = htons(ack);
                ack_pkt.length = 0;
                // Use current window size instead of jumping to max
                ack_pkt.win = htons(send_buffer.window_size);
                ack_pkt.flags = ACK;
                calculate_parity(&ack_pkt);
                send_packet(sockfd, addr, &ack_pkt);
                continue;
            }
            
            print_diag(recv_pkt, RECV);
            
            // Process the data/ACK
            process_data(sockfd, addr, recv_pkt);
        }
        
        // 2) Send new data if window allows
        size_t bytes_in_flight = 0;
        for (int i = 0; i < send_buffer.count; i++) {
            bytes_in_flight += ntohs(send_buffer.packets[i].length);
        }
        
        // Modified data transmission in listen_loop
        if (bytes_in_flight < send_buffer.window_size && send_buffer.count < BUFFER_SIZE) {
            size_t can_send = send_buffer.window_size - bytes_in_flight;
            if (can_send > MAX_PAYLOAD)
                can_send = MAX_PAYLOAD;
            
            uint8_t data[MAX_PAYLOAD];
            ssize_t local_bytes_read = g_input(data, can_send);
            
            // Debugging
            char debug_msg[256];
            snprintf(debug_msg, sizeof(debug_msg), "Sending packet: seq=%d, ack=%d, bytes_read=%zd, window=%d",
                    seq, ack, local_bytes_read, send_buffer.window_size);
            debug_print(debug_msg);
            
            // CRITICAL CHANGE: Ensure we actually read something
            if (local_bytes_read > 0) {
                packet send_pkt = {0};
                
                // Explicitly set sequence number
                send_pkt.seq = htons(seq);
                send_pkt.ack = htons(ack);
                send_pkt.length = htons(local_bytes_read);
                
                // Match reference server behavior - use MIN_WINDOW + incremental approach
                uint16_t current_window = MIN_WINDOW;
                if (type == CLIENT) {
                    // Start conservatively with MIN_WINDOW
                    current_window = MIN_WINDOW;
                } else {
                    // For server, gradually increase window based on successful delivery
                    static uint16_t window_growth = 0;
                    if (window_growth < MAX_WINDOW - MIN_WINDOW) {
                        window_growth += 500; // Increase window by 500 bytes, matching reference
                    }
                    current_window = MIN_WINDOW + window_growth;
                }
                send_pkt.win = htons(current_window);
                
                send_pkt.flags = ACK;  // Always set ACK flag
                memcpy(send_pkt.payload, data, local_bytes_read);

                calculate_parity(&send_pkt);
                
                // Careful buffer addition
                if (buffer_add(&send_buffer, &send_pkt)) {
                    print_diag(&send_pkt, SEND);
                    send_packet(sockfd, addr, &send_pkt);
                    
                    // CRITICAL: Only increment after successful send
                    seq = (uint16_t)(seq + 1);
                    
                    // Record transmission time
                    gettimeofday(&last_transmission, NULL);
                    
                    // Debug logging
                    char debug_msg[256];
                    snprintf(debug_msg, sizeof(debug_msg), 
                            "Sent packet: seq=%d, bytes=%zd, total_sent=%d", 
                            seq-1, local_bytes_read, send_buffer.count);
                    debug_print(debug_msg);
                } else {
                    // Log buffer add failure
                    debug_print("Failed to add packet to send buffer");
                }
            }
        }
        
    // 3) Retransmit if needed
        // Check for RTO-based retransmissions
         // 3) Check ALL packets for retransmission
        gettimeofday(&now, NULL);
        for (int i = 0; i < send_buffer.count; i++) {
            long elapsed = TV_DIFF(now, send_buffer.times[i]);
            if (elapsed >= RTO) {
                char debug_msg[256];
                uint16_t seq_num = ntohs(send_buffer.packets[i].seq);
                snprintf(debug_msg, sizeof(debug_msg), 
                        "Timeout detected: packet %d elapsed=%ld ms, seq=%d", 
                        i, elapsed, seq_num);
                debug_print(debug_msg);
                
                retransmit_packet(sockfd, addr, i);
                gettimeofday(&last_transmission, NULL);
            }
        }
        
        
        // 4) If nothing has been sent for a while, send a keep-alive ACK
        long since_last_transmission = TV_DIFF(now, last_transmission);
        if (since_last_transmission > RTO / 2 && send_buffer.count > 0) {
            packet ack_pkt = {0};
            ack_pkt.seq = 0;
            ack_pkt.ack = htons(ack);
            ack_pkt.length = 0;
            
            // Gradually increase window size in keep-alive ACKs
            static uint16_t window_increment = 0;
            if (window_increment < 9000) {  // Limit growth
                window_increment += 500;
            }
            uint16_t current_window = MIN_WINDOW + window_increment;
            if (current_window > MAX_WINDOW) current_window = MAX_WINDOW;
            
            ack_pkt.win = htons(current_window);
            ack_pkt.flags = ACK;
            calculate_parity(&ack_pkt);
            send_packet(sockfd, addr, &ack_pkt);
            gettimeofday(&last_transmission, NULL);
        }
    }
}