# Service detection baseline

`/etc/services` and the IANA service registry are used as an inventory, never
as classification evidence. Sift identifies content independently of port;
requestor-provided ports may later adjust confidence but cannot create a match.

## Minimum useful set

| Family | Runtime coverage | Notes |
|---|---|---|
| HTTP/1, HTTP/2, HTTP/3 | covered | Plain/requestor metadata plus TLS or QUIC ALPN |
| TLS | covered | ClientHello and ServerHello structure |
| SSH | covered | Duplex banners |
| FTP control | covered | Duplex greeting and `USER` command |
| SMTP, IMAP, POP3 | covered | Plain dialogues; IMAP and POP3 also have TLS ALPN |
| DNS | covered | TCP/UDP framing, header constraints and question labels |
| SMB | covered | SMB1, SMB2 and encrypted SMB3 transport headers |
| LDAP, Kerberos | planned | ASN.1 framing must be validated before promotion |
| PostgreSQL | partial | SSLRequest negotiation only |
| MySQL | partial | Framed protocol-v10 server greeting |
| NTP, SNMP, BGP, Syslog | planned | Promote only with structural or duplex evidence |
| SOCKS4, SOCKS5 | covered | Common CONNECT/no-auth negotiations |

## Promotion order

```text
LDAP -> BGP -> NTP/SNMP -> fuller PostgreSQL/MySQL -> remaining entries
```

Coverage means a production YAML signature plus positive corpus replay. Short
text prefixes and common numeric greetings additionally require negative
vectors. Services without sufficiently discriminating payload evidence remain
planned rather than being guessed from their assigned port.
