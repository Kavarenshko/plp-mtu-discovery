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

int _checkPacket(struct sockaddr_in* dest, struct sockaddr_in* packet_source)
{
	// returns 1 if the packet comes from the specified host
	if (packet_source->sin_addr.s_addr != dest->sin_addr.s_addr) // packet originated from another host
		return 0;
	if (packet_source->sin_port != dest->sin_port) // same host but different port (note: should not happen if UDP socket is bound to an address)
		return 0;
	return 1;
}

int _createUDPsock(struct sockaddr_in* source, int timeout_limit)
{
	int fd, val;
	struct timeval timeout = {timeout_limit / 1000, (timeout_limit % 1000) * 1000};

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) // create socket
	{
		perror("Error in socket()");
		return MTU_ERR_SOCK;
	}
	if (source != NULL && bind(fd, (struct sockaddr*)source, sizeof(struct sockaddr_in)) < 0) // bind on given address
	{
		perror("Error in bind()");
		return MTU_ERR_SOCK;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
	{
		perror("Error in setsockopt(timeout)");
		return MTU_ERR_SOCK;
	}

	switch(MTU_PLATFORM_TYPE) // set DF flag depending on the OS
	{
		case 3: // linux
			val = IP_PMTUDISC_PROBE; // set DF flag and ignore MTU
			if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val)) < 0)
			{
				perror("Error in setsockopt(MTU_PROBE)");
				return MTU_ERR_SOCK;
			}
			break;
		default:
		/*
			val = 1; // set DF flag
			if (setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &val, sizeof(val)) < 0)
				return MTU_ERR_SOCK;
		*/
			break;
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

			break;
		default:
			return MTU_ERR_PARAM;
	}

	int mtu_lbound, mtu_current, mtu_ubound, mtu_best;
	int bytes, curr_tries, *buf_addr_send, *buf_addr_recv;
	struct mtu_ip_packet s  = {0};
	struct mtu_ip_packet r  = {0};
	struct sockaddr_in from = {0};
	socklen_t from_size = sizeof(struct sockaddr_in);

	mtu_best   = MTU_ERR_TIMEOUT; // we do not know if the server is up and reachable
	mtu_lbound = MTU_MINSIZE;
	mtu_ubound = MTU_MAXSIZE - MTU_IPSIZE; // since the IP header is automatically filled in by the kernel, include its size
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
		s.icmp_hdr.checksum = _icmp_checksum(&s.icmp_hdr, mtu_current); // calculate ICMP checksum (header + data)

		if (curr_tries == max_tries)
			printf("Testing MTU size %d bytes...", mtu_current);

		if ((bytes = sendto(fd, buf_addr_send, mtu_current, 0, (struct sockaddr*)dest, sizeof(struct sockaddr_in))) < 0)
		{
			if (errno == EMSGSIZE) // packet too big for the local interface
			{
				printf("packet too big for local interface\n");
				mtu_ubound = mtu_current - 1;
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
					mtu_ubound = mtu_current - 1;
				}
				continue;
			}
			perror("Error in recvfrom()");
			return MTU_ERR_SOCK;
		}
		printf("valid\n");

		if (!_checkPacket(dest, &from)) // if the incoming packet comes from another source discard it
			continue;

		curr_tries = max_tries; // server is up, mtu_current is valid: reset retry counter
		mtu_lbound = mtu_current + 1;

		if (mtu_current > mtu_best)
			mtu_best = mtu_current;
	}

	return mtu_best;
}