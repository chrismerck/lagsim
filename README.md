lagsim
======

High-Latency Network Emulation Tool

example
-------

INTERNET ---- (eth0) lagsim-box (eth1) ----- laptop

lagsim-box$ sudo ./lagsim --latency 2000 --jitter 1

laptop$ ping 192.168.1.1

64 bytes from 192.168.1.1: icmp_seq=193 ttl=64 time=4003.276 ms

64 bytes from 192.168.1.1: icmp_seq=194 ttl=64 time=4003.000 ms

64 bytes from 192.168.1.1: icmp_seq=195 ttl=64 time=4004.708 ms

64 bytes from 192.168.1.1: icmp_seq=196 ttl=64 time=4003.488 ms

64 bytes from 192.168.1.1: icmp_seq=197 ttl=64 time=4003.252 ms

64 bytes from 192.168.1.1: icmp_seq=198 ttl=64 time=4004.240 ms

64 bytes from 192.168.1.1: icmp_seq=199 ttl=64 time=4004.019 ms

64 bytes from 192.168.1.1: icmp_seq=200 ttl=64 time=4003.836 ms



Or, with --latency 0:

Speed test results to Speakeasy.com doesn't show any difference
between the lagsim connection and the direct inet connection:

Download Speed: 58257 kbps (7282.1 KB/sec transfer rate)

Upload Speed: 34517 kbps (4314.6 KB/sec transfer rate)

