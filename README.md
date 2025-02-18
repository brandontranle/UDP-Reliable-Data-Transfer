# CS 118 Winter 25 Project 1

This repository contains starter code for [CS 118's Winter 25 Project
1](https://cs118.org/projects/project1).

For more information on how to use the local autograder, visit [the course 
website](https://cs118.org/misc/autograder).

# Our Thought Process
## Initial Design
The implementation started with a robust three-way handshake mechanism, focusing on establishing a reliable connection between client and server. The core design centered around implementing global tracking of sequence numbers and acknowledgments, which proved crucial for maintaining packet order and reliability.

# Our Decisions
- Implemented Buffer struct to manage send and receive windows
- Created a flexible handshake process that supports payload transmission during connection establishment
- Developed error handling mechanisms including parity checking for packet integrity, fast retransmit for handling packet loss, fequence number management


## Major Challenges
Initially, a circular queue approach was considered but proved too complex. Instead, a more straightforward Buffer struct was implemented with a maximum buffer size of 40 packets. This structure allowed for more predictable packet management and easier debugging.
As for payload handling, a critical insight came from carefully reviewing connection logs. The team discovered that initial test cases were actually testing payload transmission during the handshake process. This led to modifications allowing both client and server to detect and process piggybacked data during SYN and SYN-ACK packets.

To add reliability:
- We implemented fast retransmit to quickly recover from packet loss
- Added parity checking to ensure packet integrity
- Created a flexible windowing mechanism to control data flow

## Performance
We tried to balance reliability with performance by:
- Using non-blocking I/O
- Implementing adaptive retransmission timeouts
- Managing send and receive windows dynamically

## What we learned 
- Careful logging and diagnostic tools are crucial for debugging network protocols
- Handling edge cases in sequence number management is critical for reliable data transmission

## Future Improvements
- Better error handling
- More sophisticated congestion control
- Support for larger payloads and more complex network conditions