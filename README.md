# TCP Client-Server with AES GCM 256 Encryption

This project demonstrates a secure TCP client-server communication system using **AES GCM 256-bit encryption**. The server generates a cryptographic key and initialization vector (IV), which are sent to the client. The client encrypts a message and sends it to the server. The server decrypts the message, processes it, and responds with an encrypted acknowledgment.

## Features

- **AES GCM 256-bit encryption** for secure communication.
- **TCP Client-Server Model** for communication.
- **Latency Profiling** for various operations:
  - TCP send/receive times.
  - Encryption and decryption times.
- **Key Exchange**: The server sends a cryptographic key and IV to the client at the start of the communication.

## Prerequisites

- C++11 or later.
- OpenSSL (version 1.0.1 or higher recommended).

