# Recursive DNS Resolver (WIP, C)

A low-level DNS resolver being built from scratch in C, focusing on manual packet construction, parsing, and protocol-level understanding of networking.

## Current Status

This project is in early development.

At the moment, it focuses on:

- Raw packet structure definitions (Ethernet, IP, UDP, DNS)
- Manual parsing of IP headers
- DNS query packet construction
- Endianness handling and byte-level manipulation

This is not yet a fully functional recursive resolver.

## What This Project Aims To Become

A fully working recursive DNS resolver that:

- Sends DNS queries directly to root servers
- Performs iterative resolution (root → TLD → authoritative)
- Parses DNS responses manually
- Caches results for efficiency
- Handles multiple query types (A, AAAA, CNAME, etc.)

## Current Capabilities

- Packet Structures
  -  Ethernet (eth)
  -  IPv4 (ip, ip_details)
  -  UDP (udp)
  -  DNS header + question section

All structures are manually defined using packed memory layout.

## Packet Construction

-  Constructs DNS query manually (e.g., google.com)
-  Builds question section byte-by-byte
-  Sets query type (A) and class (IN)

## Endianness Handling

-  Custom byte-order conversion:
    -  `conv16()`
    -  `conv32()`
-  Runtime endianness detection


## How It Works (Current Flow)

1)  Define raw buffer
2)  Cast buffer into protocol structures
3)  Extract header fields manually
4)  Construct DNS query name (google.com) in wire format:

    -  ``` 6 google 3 com 0 ```

5)  Append DNS question tail
