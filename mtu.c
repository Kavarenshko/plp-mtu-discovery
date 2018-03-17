#include <errno.h>
#include <stdio.h>
#include <unistd.h> // getpid()
#include <sys/time.h> // struct timeval
#include <sys/types.h> // getpid()

#include "mtu.h"

#define MAX_BUF MTU_MAXSIZE

uint16_t _icmp_checksum(void *h, int len) // len = (header + data)
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
		if (p->icmp_hdr.type == ICMP_ECHOREPLY) // valid if the source addr is server's
		{
			if (packet_source->sin_addr.s_addr != dest->sin_addr.s_addr)
				return 0; // discard it
		}
		else if (p->icmp_hdr.type == ICMP_DEST_UNREACH) // some kind of error occurred
		{
			return -(p->icmp_hdr.code); // return error type
		}
		else // unhandled ICMP packet
			return -256;
	}
	else if (protocol == MTU_PROTO_UDP)
	{
		if (packet_source->sin_addr.s_addr != dest->sin_addr.s_addr) // packet originated from another host
			return 0; // discard it
		if (packet_source->sin_port != dest->sin_port) // same host but different port
			return 0; // discard it
	}
	else // unknown protocol
		return -256;

	return 1; // success
}

int _setDF(int fd)
{
	int val;
	switch(MTU_PLATFORM_TYPE) // set DF flag depending on the OS
	{
		case 3: // linux
			val = IP_PMTUDISC_PROBE; // set DF flag and ignore MTU
			return setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
		default:
		/*
			val = 1; // set DF flag
			if (setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &val, sizeof(val)) < 0)
				return MTU_ERR_SOCK;
		*/
			perror("Platform not supported");
			return -1;
	}
}

int _createUDPsock(struct sockaddr_in* source, int timeout_limit)
{
	// creates UDP socket, returns file descriptor if no errors are caught

	int fd;
	struct timeval timeout = {timeout_limit / 1000, (timeout_limit % 1000) * 1000};

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) // create socket
	{
		perror("Error in socket(udp)");
		return MTU_ERR_SOCK;
	}

	if (source != NULL && bind(fd, (struct sockaddr*)source, sizeof(struct sockaddr_in)) < 0) // bind on given address
	{
		perror("Error in bind()");
		return MTU_ERR_SOCK;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) // set timeout to input operations
	{
		perror("Error in setsockopt(timeout/udp)");
		return MTU_ERR_SOCK;
	}

	if (_setDF(fd) < 0) // set Don't Fragment flag in IPv4 packet
	{
		perror("Error in setsockopt(DF)");
		return MTU_ERR_SOCK;
	}

	return fd;
}

int _createICMPsock(int timeout_limit)
{
	// creates raw socket, returns file descriptor if no errors are caught

	int fd;
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

	if (_setDF(fd) < 0) // set Don't Fragment flag in IPv4 packet
	{
		perror("Error in setsockopt(DF)");
		return MTU_ERR_SOCK;
	}

	return fd;
}

int mtu_discovery(struct sockaddr_in* source, struct sockaddr_in* dest, int protocol, int max_tries, int timeout)
{
	int fd;

	if (dest == NULL)	{ return MTU_ERR_PARAM; }
	if (max_tries < 1)	{ return MTU_ERR_PARAM; }
	if (timeout < 0)	{ return MTU_ERR_PARAM; }

	switch(protocol)
	{
		case MTU_PROTO_UDP:
			if ((fd = _createUDPsock(source, timeout)) < 0)
				return fd;
			break;
		case MTU_PROTO_ICMP:
			if ((fd = _createICMPsock(timeout)) < 0)
				return fd;
			break;
		default:
			return MTU_ERR_PARAM;
	}

	int mtu_lbound, mtu_current, mtu_ubound, mtu_best;
	int bytes, curr_tries, res, protocol_difference, *buf_addr_send, *buf_addr_recv;
	struct mtu_ip_packet s  = {0};
	struct mtu_ip_packet r  = {0};
	struct sockaddr_in from = {0};
	socklen_t from_size = sizeof(struct sockaddr_in);

	mtu_best   = MTU_ERR_TIMEOUT; // we do not know if the server is up and reachable
	mtu_lbound = MTU_MINSIZE;
	mtu_ubound = MTU_MAXSIZE;
	protocol_difference = (protocol == MTU_PROTO_UDP)? MTU_IPSIZE + MTU_UDPSIZE : MTU_IPSIZE; // UDP sock only sends data, ICMP socks requires ICMP header
	/*
		below we use a trick to shorten the code (we don't need to separate ICMP and UDP):
		if the protocol is ICMP send the whole packet (icmp_hdr + data, buf_addr_send set to s.icmp_hdr)
		if the protocol is UDP, only send the data attribute (buf_addr_send set to s.data)
	*/
	buf_addr_send = (protocol == MTU_PROTO_ICMP)? (void*)&s.icmp_hdr : (void*)s.data;
	buf_addr_recv = (protocol == MTU_PROTO_ICMP)? (void*)&r : (void*)r.data;

	s.icmp_hdr.type = ICMP_ECHO;
	s.icmp_hdr.un.echo.id = getpid();
	s.icmp_hdr.un.echo.sequence = 1;
	for(int i=0; i < MAX_BUF; i++)
		s.data[i] = 'a' + (i % 26);

	curr_tries = max_tries;
	while(mtu_lbound <= mtu_ubound) // binary search
	{
		mtu_current = (mtu_lbound + mtu_ubound) / 2;
		s.icmp_hdr.checksum = 0; // checksum must be set to 0 before calculating it
		s.icmp_hdr.checksum = _icmp_checksum(&s.icmp_hdr, mtu_current - MTU_IPSIZE); // calculate ICMP checksum (header + data)

		if (curr_tries == max_tries)
			printf("Testing MTU size %d bytes...", mtu_current);

		if ((bytes = sendto(fd, buf_addr_send, mtu_current - protocol_difference, 0, (struct sockaddr*)dest, sizeof(struct sockaddr_in))) < 0)
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

		if ((bytes = recvfrom(fd, buf_addr_recv, sizeof(struct mtu_ip_packet), 0, (struct sockaddr*)&from, &from_size)) < 0)
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
		res = _checkPacket(protocol, (struct mtu_ip_packet*)buf_addr_recv, dest, &from);
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