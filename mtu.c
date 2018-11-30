#include <errno.h>
#include <stdio.h>
#include <string.h> // memset()
#include <unistd.h> // getpid()
#include <sys/time.h> // struct timeval
#include <sys/types.h> // getpid(), struct addrinfo

#include "mtu.h"

#define MAX_BUF MTU_MAXSIZE

uint16_t _net_checksum(void *h, int len) // len = (header + data)
{
	// this function implements the checksum function as defined in RFC 791 (can be used for both ICMP and IP)
	uint32_t sum;
	uint16_t *buf = h;

	for(sum = 0; len > 1; len -= 2)
		sum += *buf++;

	if (len == 1) // if odd
		sum += *(unsigned char*)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);

	return ~sum;
}

int _checkPacket(int protocol, struct mtu_ip_packet* p, struct sockaddr_in* dest, struct sockaddr_in* packet_source)
{
	// returns 1 if the packet comes from the specified host and it's valid

	if (protocol == MTU_PROTO_ICMP)
	{
		if (p->proto_hdr.icmp_hdr.type == ICMP_ECHOREPLY) // valid if the source addr is server's
		{
			if (packet_source->sin_addr.s_addr != dest->sin_addr.s_addr)
				return 0; // discard it
		}
		else if (p->proto_hdr.icmp_hdr.type == ICMP_DEST_UNREACH) // some kind of error occurred
		{
			return -(p->proto_hdr.icmp_hdr.code); // return error type
		}
		else // unhandled ICMP packet
			return -256;
	}
	else if (protocol == MTU_PROTO_UDP)
	{
		if (packet_source->sin_addr.s_addr != dest->sin_addr.s_addr) // packet originated from another host
			return 0; // discard it

		/*
			Some operating systems define the members of struct udphdr depending on the existence
			of the __FAVOR_BSD macro.

			https://stackoverflow.com/questions/21893601/no-member-th-seq-in-struct-tcphdr-working-with-pcap
		*/
		#if defined(__FAVOR_BSD) || defined(__APPLE__) || defined(__MACH__)
			if (p->proto_hdr.udp_hdr.uh_sport != dest->sin_port) // same host but different port
				return 0; // discard it
		#else
			if (p->proto_hdr.udp_hdr.source != dest->sin_port) // same host but different port
				return 0; // discard it
		#endif
	}
	else // unknown protocol
		return -256;

	return 1; // success
}

int _createUDPsock(struct sockaddr_in* source, int timeout_limit)
{
	// creates UDP raw socket, returns file descriptor if no errors are caught

	int fd, yes = 1;
	const int* val = &yes;
	struct timeval timeout = {timeout_limit / 1000, (timeout_limit % 1000) * 1000};

	if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) // create socket
	{
		perror("Error in socket(udp)");
		return MTU_ERR_SOCK;
	}

	if (source != NULL && bind(fd, (struct sockaddr*)source, sizeof(struct sockaddr_in)) < 0) // bind on given address
	{
		perror("Error in bind()");
		return MTU_ERR_SOCK;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) != 0) // set timeout to input operations
	{
		perror("Error in setsockopt(timeout/udp)");
		return MTU_ERR_SOCK;
	}

	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(yes)) != 0)
	{
		perror("Error in setsockopt(IP_HDRINCL)");
		return MTU_ERR_SOCK;
	}

	return fd;
}

int _createICMPsock(int timeout_limit)
{
	// creates ICMP raw socket, returns file descriptor if no errors are caught

	int fd, yes = 1;
	const int* val = &yes;
	struct timeval tv = {timeout_limit / 1000, (timeout_limit % 1000) * 1000};

	if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
	{
		perror("Error in socket(icmp)");
		return MTU_ERR_SOCK;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval)) != 0) // set timeout to input operations
	{
		perror("Error in setsockopt(SO_RCVTIMEO)");
		return MTU_ERR_SOCK;
	}

	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(yes)) != 0)
	{
		perror("Error in setsockopt(IP_HDRINCL)");
		return MTU_ERR_SOCK;
	}

	#if defined(__linux__)
		/*
			In some instances, linux can cache the value of a previous MTU limit to a certain address.
			This only happens when manually setting the IP header (IP_HDRINCL).

			As stated in man pages:
			"The kernel will reject (with EMSGSIZE) datagrams that are bigger than the known path MTU.", this is normal behaviour (expected and handled correctly).
			The tricky part is this one:
			"When PMTU discovery is enabled, the kernel automatically keeps track of the path MTU per destination host.".
			When using IP_HDRINCL, the kernel enables PMTU discovery by default: subsequent calls to sendto() might yield different result due to MTU caching.
			Disconnecting from the network or waiting several minutes resets the kernel info.

			When the cached result is used, EMSGSIZE is returned AND an ICMP type 3 message (DEST_UNREACH, Fragmentation Needed) is sent from this host to itself.
			This behaviour is not documented (and somewhat confusing).

			Since we don't want MTU caching, we set the IP_PMTUDISC_PROBE option, which totally ignores path MTU.
		*/
		int mtu_val = IP_PMTUDISC_PROBE;
		const int* mtu_preference = &mtu_val;
		if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, mtu_preference, 1) != 0)
		{
			perror("Error in setsockopt(IP_MTU_DISCOVER)");
			return MTU_ERR_SOCK;
		}
	#endif

	return fd;
}

void _setIPhdr(struct mtu_ip_packet* p, struct sockaddr_in* source, struct sockaddr_in* dest, int protocol)
{
	p->ip_hdr.ip_hl = 5; // IP header length
	p->ip_hdr.ip_v = 4; // IP version
	p->ip_hdr.ip_tos = 0; // type of service
	p->ip_hdr.ip_len = 0; // packet total length, filled in before every sendto()
	p->ip_hdr.ip_id = 0; // packet ID, filled in before every sendto()
	p->ip_hdr.ip_ttl = 255; // time to live
	p->ip_hdr.ip_p = protocol; // carried protocol
	p->ip_hdr.ip_sum = 0; // checksum, filled in before every sendto()
	p->ip_hdr.ip_src = source->sin_addr; // source address
	p->ip_hdr.ip_dst = dest->sin_addr; // destination address

	/*
		Set Don't Fragment field on.
		Since this field is 2 bytes long, we should use htons() to set it; however, some BSD versions
		and OSX require this field in host byte order.

		https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man4/ip.4.html
	*/
	#if defined(__APPLE__) || defined(__MACH__)
		p->ip_hdr.ip_off = IP_DF;
	#else
		p->ip_hdr.ip_off = htons(IP_DF);
	#endif
}

int mtu_discovery(struct sockaddr_in* source, struct sockaddr_in* dest, int protocol, int max_tries, int timeout)
{
	int fd, i;
	struct mtu_ip_packet s;
	struct mtu_ip_packet r;
	struct sockaddr_in from;

	if (dest == NULL)	{ return MTU_ERR_PARAM; }
	if (max_tries < 1)	{ return MTU_ERR_PARAM; }
	if (timeout < 0)	{ return MTU_ERR_PARAM; }

	memset(&s, 0, sizeof(struct mtu_ip_packet)); // avoid bracket initialization warnings
	memset(&r, 0, sizeof(struct mtu_ip_packet));
	memset(&from, 0, sizeof(struct sockaddr_in));
	for(i=0; i < MAX_BUF; i++) // message payload
		s.data[i] = 'a' + (i % 26);

	_setIPhdr(&s, source, dest, protocol); // fill in IP header information

	switch(protocol)
	{
		case MTU_PROTO_UDP:
			if ((fd = _createUDPsock(source, timeout)) < 0)
				return fd;
			// fill in UDP header
			#if defined(__FAVOR_BSD) || defined(__APPLE__) || defined(__MACH__) // refer to the comment above
				s.proto_hdr.udp_hdr.uh_sport = source->sin_port; // filled in by the kernel
				s.proto_hdr.udp_hdr.uh_dport = dest->sin_port;
			#else
				s.proto_hdr.udp_hdr.source = source->sin_port; // filled in by the kernel
				s.proto_hdr.udp_hdr.dest = dest->sin_port;
			#endif

			break;
		case MTU_PROTO_ICMP:
			if ((fd = _createICMPsock(timeout)) < 0)
				return fd;
			// fill in ICMP header
			s.proto_hdr.icmp_hdr.type = ICMP_ECHO;
			s.proto_hdr.icmp_hdr.un.echo.id = getpid(); // might remove in favour of something safer

			break;
		default:
			return MTU_ERR_PARAM;
	}

	uint16_t ip_identification, icmp_seqn;
	int mtu_lbound, mtu_current, mtu_ubound, mtu_best;
	int bytes, curr_tries, res;
	socklen_t from_size = sizeof(struct sockaddr_in);

	mtu_best   = MTU_ERR_TIMEOUT; // we do not know if the server is up and reachable
	mtu_lbound = MTU_MINSIZE;
	mtu_ubound = MTU_MAXSIZE;
	icmp_seqn = 0;
	ip_identification = 0; // IP header ID

	curr_tries = max_tries;
	while(mtu_lbound <= mtu_ubound) // binary search
	{
		mtu_current = (mtu_lbound + mtu_ubound) / 2;

		// fill in variable IP header fields
		s.ip_hdr.ip_id = htons(++ip_identification);
		s.ip_hdr.ip_len = mtu_current;

		// protocol-specific header fields
		if (protocol == MTU_PROTO_ICMP)
		{
			s.proto_hdr.icmp_hdr.un.echo.sequence = htons(++icmp_seqn);
			s.proto_hdr.icmp_hdr.checksum = 0; // checksum must be set to 0 before calculating it
			s.proto_hdr.icmp_hdr.checksum = _net_checksum(&s.proto_hdr.icmp_hdr, mtu_current - MTU_IPSIZE); // calculate ICMP checksum (header + data)
		}
		else if (protocol == MTU_PROTO_UDP)
		{
			#if defined(__FAVOR_BSD) || defined(__APPLE__) || defined(__MACH__)
				s.proto_hdr.udp_hdr.uh_ulen = htons(mtu_current - MTU_IPSIZE);
				s.proto_hdr.udp_hdr.uh_sum = 0; // checksum must be set to 0 before calculating it
				//s.proto_hdr.udp_hdr.uh_sum = _net_checksum(&s.proto_hdr.udp_hdr, mtu_current - MTU_IPSIZE); // calculate UDP checksum (header + data)
			#else
				s.proto_hdr.udp_hdr.len = htons(mtu_current - MTU_IPSIZE);
				s.proto_hdr.udp_hdr.check = 0; // checksum must be set to 0 before calculating it
				//s.proto_hdr.udp_hdr.check = _net_checksum(&s.proto_hdr.udp_hdr, mtu_current - MTU_IPSIZE); // calculate UDP checksum (header + data)
			#endif
		}
		s.ip_hdr.ip_sum = _net_checksum(&s, s.ip_hdr.ip_len); // is this necessary? Could be filled in by the kernel

		if (curr_tries == max_tries)
			printf("Testing MTU size %d bytes...", mtu_current);

		if ((bytes = sendto(fd, &s, mtu_current, 0, (struct sockaddr*)dest, sizeof(struct sockaddr_in))) == -1)
		{
			if (errno == EMSGSIZE) // packet too big for the local interface
			{
				printf("packet too big for local interface\n");
				mtu_ubound = mtu_current - 1; // update range
				continue;
			}
			perror("Error in sendto()");
			return MTU_ERR_SOCK;
		}

		if ((bytes = recvfrom(fd, &r, sizeof(struct mtu_ip_packet), 0, (struct sockaddr*)&from, &from_size)) < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK) // timeout: packet got lost or server is down
			{
				if (--curr_tries == 0) // after a sufficient number of tries this MTU size is declared too high, decrease it
				{
					printf("no response, invalid MTU size\n");

					curr_tries = max_tries;
					mtu_ubound = mtu_current - 1; // update range
				}
				continue;
			}
			perror("Error in recvfrom()");
			return MTU_ERR_SOCK;
		}

		// a packet has been received, check if it's valid
		res = _checkPacket(protocol, &r, dest, &from);
		if (res > 0) // success, the packet comes from the server and it's valid
		{
			printf("valid\n");

			curr_tries = max_tries; // server is up, mtu_current is valid: reset retry counter
			mtu_lbound = mtu_current + 1; // update range

			if (mtu_current > mtu_best)
				mtu_best = mtu_current;
		}
		else if (res == 0) // this packet comes from another source, discard it and retry
		{
			continue;
		}
		else // ICMP error message or unknown packet: either way, lower the range and go on
		{
			switch(res)
			{
				case -1:	printf("ICMP error, host unreachable\n"); break;
				case -3:	printf("ICMP error, port unreachable\n"); break;
				case -4:	printf("ICMP error, fragmentation needed\n"); break;
				case -256:	printf("unknown error\n"); break;
				default:	printf("unknown ICMP error\n"); break;
			}

			curr_tries = max_tries;
			mtu_ubound = mtu_current - 1; // update range
		}
	}

	return mtu_best;
}
