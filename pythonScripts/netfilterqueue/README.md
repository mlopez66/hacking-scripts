# Netfilterqueue

## Prerequisites

```bash
iptables -I INPUT -j NFQUEUE --queue-num 0
iptables -I OUTPUT -j NFQUEUE --queue-num 0
iptables -I FORWARD -j NFQUEUE --queue-num 0
iptables --policy FORWARD ACCEPT
```