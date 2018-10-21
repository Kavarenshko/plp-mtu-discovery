# plp-mtu-discovery
>  Perform Path MTU Discovery without relying on ICMP errors, which are often not delivered.

This program performs Packetization Layer Path MTU Discovery as described in [RFC 4821](https://tools.ietf.org/html/rfc4821), which is a more reliable way to detect MTU size in presence of [ICMP black holes](https://en.wikipedia.org/wiki/Path_MTU_Discovery#Problems).

### Rationale

While TCP connections automatically adjust MTU size over time depending on various indicators (network performance, packet loss, ICMP error messages, ...), this is not the case for connection-less protocols.

When performance is essential, **throughput**, **packet fragmentation** and **route reliability** are three key indicators to analyze in order to optimize stream performance. Since route reliability does not always depend on us, we should strive to maximize throughput while **NOT performing packet fragmentation**, which can severely degrade performance<sup>[[1](http://www.hpl.hp.com/techreports/Compaq-DEC/WRL-87-3.pdf)]</sup>.

The original proposal for Path MTU Discovery relied on `ICMP Fragmentation Needed` packets to be delivered when a IPv4 packet with *Don't Fragment* field set was too large to be propagated. Unfortunately, some routers do not generate these kind of errors but choose to silently ignore large packets instead. A client has no way to determine the cause of the packet loss.

### A safer approach

Since all hosts are mandated to support ICMP_ECHO queries, we can exploit the fact that ICMP messages accept an arbitrary amount of data and send different-sized packets to our server. If we turn on the *Don't Fragment* field in the IPv4 packet and listen for a response, we are *de facto* waiting for an ACK (in the form of an ICMP_ECHOREPLY packet) confirming that this MTU size is valid.

Now we just have to perform a binary search in respect to the size of the packets in order to find the maximum MTU size supported by this route.

### ICMP mode

When in ICMP mode, some **ICMP_ECHO** requests of different sizes are generated.
- If a response from the server is received, that MTU size is considered valid and the threshold is raised.
- If no response is received after several attempts or some kind of error is received (e.g.`ICMP Fragmentation Needed`), that MTU size is declared invalid and the threshold is lowered.

The only requirement of *ICMP mode* is that the host must be capable to reply to ping messages.

### UDP mode

The same algorithm applies to UDP packets, but you need to run a server (*udp_server.py*) on your receiving host in order to send back acknowledgment messages.

### Compiling & Running

This program should run fine on most Linux distributions and OSX.
```
gcc -Wall -Wextra mtu_discovery.c mtu.c -o plpmtu
```

It should not report warnings/errors. If it does, please open an issue.

If you want to run in **ICMP mode** type:
```
sudo ./plpmtu -p icmp -s <server-ipaddr>
```
If you want to run **UDP mode** instead:
```
sudo ./plpmtu -p udp -s <server-ipaddr:port>
```

Admin rights are required in order to use raw sockets.

### Command line arguments

| Specifier | Description |
| --- | --- |
| -p {icmp/udp} | Select in which mode to operate.
| -s &lt;addr[:port]&gt; | Specify server's address. If running in UDP mode, you must also specify the destination port by appending ':port' (e.g. `-s 8.8.8.8:12345`) |
| -l &lt;addr:port&gt; | Optional. Select on which address to bind(); used in UDP mode; might be removed. |
| -t &lt;timeout&gt; | Optional. Select the maximum time to wait for a response from the server, default is 1 second; time is expressed in milliseconds. |
| -r &lt;max-reqs&gt; | Optional. Select the maximum number of failed attempts needed to declare a MTU size invalid, default is 3 attempts. |

### Examples

```
sudo ./plpmtu -p icmp -s 184.12.26.131
```
Perform MTU discovery (ICMP mode) with 184.12.26.131. 
```
sudo ./plpmtu -p udp -s 184.12.26.131:24000 -t 1500 -r 5
```
Perform MTU discovery (UDP mode) with 184.12.26.131 on port 24000. If a response is not received within 1.5 seconds for 5 times in a row, reduce MTU threshold.

### Docs

- [RFC 791](https://tools.ietf.org/html/rfc791) : Internet Protocol version 4 (Sep 1981)
- [RFC 792](https://tools.ietf.org/html/rfc792) : Internet Control Message Protocol (Sep 1981)
- [RFC 1191](https://tools.ietf.org/html/rfc1191) : Path MTU Discovery (Nov 1990)
- [RFC 4821](https://tools.ietf.org/html/rfc4821) : Packetization Layer Path MTU Discovery (Mar 2007)
- <sup>1</sup>[Fragmentation considered harmful](http://www.hpl.hp.com/techreports/Compaq-DEC/WRL-87-3.pdf) (Dec 1987)
