# Service detection baseline

`/etc/services` and the IANA service registry are used as an inventory, never
as classification evidence. Sift identifies content independently of port;
requestor-provided ports may later adjust confidence but cannot create a match.

## Minimum useful set

| Family | Runtime coverage | Notes |
|---|---|---|
| HTTP/1, HTTP/2, HTTP/3 | covered | Plain/requestor metadata plus TLS or QUIC ALPN |
| TLS | covered | ClientHello and ServerHello structure |
| DTLS | covered | UDP ClientHello record and unfragmented handshake structure |
| QUIC | covered | Version 1 and 2 Initial long-header structure plus QUIC ALPN |
| SSH | covered | Duplex banners |
| FTP control | covered | Duplex greeting/`USER` plus TLS ALPN |
| SMTP, IMAP, POP3 | covered | Plain dialogues; IMAP and POP3 also have TLS ALPN |
| DNS | covered | TCP/UDP framing plus DoT, DoH and DoQ metadata evidence |
| SMB | covered | SMB1/2, encrypted SMB3 headers, and SMB TLS ALPN |
| LDAP | covered | Exact BER frame with message ID and application operation |
| Kerberos | covered | UDP BER application frames and TCP length framing |
| PostgreSQL | covered | SSLRequest, startup v3, authentication, and direct-TLS ALPN |
| MySQL | covered | Framed protocol-v10 server greeting and client handshake |
| Redis | covered | RESP command/response dialogue |
| BGP | covered | Marker, exact message length and message type |
| SNMP | covered | Exact BER frame with version, community and PDU tags |
| NTP | covered | Conservative 48-byte v3/v4 base packets and valid modes |
| RDP | covered | Exact TPKT framing and X.224 connection message type |
| Syslog | covered | Valid PRI plus RFC 3164 timestamp or RFC 5424 version/timestamp framing |
| SOCKS4, SOCKS5 | covered | Common CONNECT/no-auth negotiations |
| STUN | covered | Binding request, indication, success, and error with cookie and exact length |
| WireGuard | covered | Handshake, cookie reply, and transport-data message framing |
| DHCPv4 | covered | BOOTP/DHCP magic cookie at its normative offset |
| AJP13 | covered | Ping/cpong plus length-checked forward-request and shutdown frames |
| memcached | covered | ASCII commands and length-checked binary request/response headers |
| Diameter | covered | Version, exact message length, command code, and request/answer direction |
| GTP | covered | GTPv1 and GTPv2 version and exact message-length framing |
| RADIUS | covered | Access-Request/Accept code, direction, and exact packet length |
| Kafka | covered | Length-checked request header with bounded API key/version |
| IEC 60870-5-104 | covered | Length-checked I, S, and defined U control formats |
| MQTT | covered | CONNECT protocol name/version plus registered TLS ALPN |
| Modbus/TCP | covered | MBAP protocol identifier, exact length, and function code |
| OPC UA TCP | covered | HEL/ACK/ERR/RHE message types with exact little-endian size |
| CoAP | covered | UDP request/response header constraints plus TLS ALPN |
| FastCGI | covered | Fully constrained BEGIN_REQUEST record |
| HLS manifest | covered | Inspected HTTP path or standardized manifest media type |
| DASH manifest | covered | Inspected HTTP path or standardized manifest media type |
| Streaming media segment | covered | Explicit segment path or `video/iso.segment` media type |

## Promotion order

Further candidates are selected from the incubator by evidence quality and
runtime support rather than by assigned service port.

Coverage means a production YAML signature plus positive corpus replay. Short
text prefixes and common numeric greetings additionally require negative
vectors. Services without sufficiently discriminating payload evidence remain
planned rather than being guessed from their assigned port.
