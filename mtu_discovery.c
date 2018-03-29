
#include <netdb.h> // struct addrinfo
#include <stdio.h>
#include <string.h> // strcmp(), strcpy(), memset()
#include <unistd.h> // getopt()
#include <arpa/inet.h> // inet_pton()
#include <netinet/in.h> // struct sockaddr_in

#include "mtu.h"

int validateArgs(int argc, char** argv, struct sockaddr_in* lc_addr, struct sockaddr_in* sv_addr, int* proto, int* ms_timeout, int* max_retries)
{
	// this function returns 1 if the command line arguments are valid, 0 otherwise

	int opt, lc_port, sv_port, gai_ret;
	int pt_given = 0; // 1 if protocol is provided
	int lc_given = 0; // 1 if local addr is provided
	int sv_given = 0; // 1 if server addr is provided
	char lc_ip[256] = {0};
	char sv_ip[256] = {0};
	struct addrinfo resolve_hints;
	struct addrinfo *resolve_result, *resolve_rp;

	*ms_timeout  = MTU_DEFAULT_TIMEOUT;
	*max_retries = MTU_DEFAULT_RETRIES;

	lc_addr->sin_family = AF_INET;
	sv_addr->sin_family = AF_INET;
	lc_addr->sin_port = htons(25101); // arbitrary UDP port
	inet_pton(AF_INET, "0.0.0.0", &lc_addr->sin_addr); // default local address

	memset(&resolve_hints, 0, sizeof(struct addrinfo));
	resolve_hints.ai_family = AF_INET;
	resolve_hints.ai_socktype = 0;
	resolve_hints.ai_flags = 0;
	resolve_hints.ai_protocol = 0;
	resolve_hints.ai_canonname = NULL;
	resolve_hints.ai_addr = NULL;
	resolve_hints.ai_next = NULL;

	opterr = 0; // do not print any error message (default behavior of getopt())
	while((opt = getopt(argc, argv, "p:s:l:t:r:")) != -1)
	{
		switch(opt)
		{
			case 'p': // protocol
				pt_given = 1;
				if (strcmp(optarg, "udp") == 0)
					*proto = MTU_PROTO_UDP;
				else if (strcmp(optarg, "icmp") == 0)
					*proto = MTU_PROTO_ICMP;
				else
				{
					fprintf(stderr, "Invalid protocol: %s\n", optarg);
					return 0;
				}
				break;
			case 's': // server addr (address if protocol is ICMP, address:port if protocol is UDP)
				sv_given = 1;
				if (*proto == MTU_PROTO_UDP)
				{
					if (sscanf(optarg, "%[^:]:%d", sv_ip, &sv_port) == 2) // valid format
						break;
					fprintf(stderr, "Invalid server <ip:addr>: %s\n", optarg);
					return 0;
				}
				else if (*proto == MTU_PROTO_ICMP)
				{
					if (sscanf(optarg, "%[^:]:%d", sv_ip, &sv_port) == 2)
						fprintf(stderr, "Warning: port number should not be specified in ICMP mode.\n");
					else
						strcpy(sv_ip, optarg);
					break;
				}
				else // should not happen
					return 0;
			case 'l': // local addr (address:port)
				if (*proto == MTU_PROTO_UDP)
				{
					lc_given = 1;
					if (sscanf(optarg, "%[^:]:%d", lc_ip, &lc_port) == 2) // valid format
						break;
					fprintf(stderr, "Invalid local <ip:addr>: %s\n", optarg);
					return 0;
				}
				else if (*proto == MTU_PROTO_ICMP)
				{
					fprintf(stderr, "Warning: local server address should not be specified in ICMP mode.\n");
					break;
				}
				else // should not happen
					return 0;
			case 't': // timeout
				if (sscanf(optarg, "%d", ms_timeout) != 1)
				{
					fprintf(stderr, "Invalid timeout value: '%s'\n", optarg);
					return 0;
				}
				break;
			case 'r': // max retries
				if (sscanf(optarg, "%d", max_retries) != 1)
				{
					fprintf(stderr, "Invalid maxreq value: '%s'\n", optarg);
					return 0;
				}
				break;
			case '?': // missing or invalid argument
				return 0;
			default:
				fprintf(stderr, "Warning: unknown parameter '-%c'\n", opt);
				return 0;
		}
	}

	if (!pt_given || !sv_given)
		return 0;

	if (*ms_timeout < 0 || *ms_timeout > 1000000)
	{
		fprintf(stderr, "Invalid timeout value: '%d'\n", *ms_timeout);
		return 0;
	}

	if (*max_retries < 0 || *max_retries > 1000000)
	{
		fprintf(stderr, "Invalid maxreq value: '%d'\n", *max_retries);
		return 0;
	}

	if (lc_given)
	{
		if (*proto == MTU_PROTO_UDP)
		{
			if (lc_port < 1 || lc_port > 65535)
			{
				fprintf(stderr, "Invalid local port number: '%d'.\n", lc_port);
				return 0;
			}
			lc_addr->sin_port = htons(lc_port);
		}

		// hostname resolution
		if ((gai_ret = getaddrinfo(lc_ip, NULL, &resolve_hints, &resolve_result)) != 0) // this generates a memory leak on some systems
		{
			fprintf(stderr, "Could not resolve local address '%s': %s\n", lc_ip, gai_strerror(gai_ret));
			return 0;
		}

		for(resolve_rp = resolve_result; resolve_rp != NULL; resolve_rp = resolve_rp->ai_next)
		{
			struct sockaddr_in *ipv4_addr = (struct sockaddr_in *)resolve_rp->ai_addr;
			lc_addr->sin_addr = ipv4_addr->sin_addr;
		}
		freeaddrinfo(resolve_result);
	}

	if (*proto == MTU_PROTO_UDP)
	{
		if (sv_port < 1 || sv_port > 65535)
		{
			fprintf(stderr, "Invalid server port number: '%d'.\n", sv_port);
			return 0;
		}
		sv_addr->sin_port = htons(sv_port);
	}
	else
		sv_addr->sin_port = 0; // unused in ICMP

	// hostname resolution
	if ((gai_ret = getaddrinfo(sv_ip, NULL, &resolve_hints, &resolve_result)) != 0) // this generates a memory leak on some systems
	{
		fprintf(stderr, "Could not resolve server address '%s': %s\n", sv_ip, gai_strerror(gai_ret));
		return 0;
	}

	for(resolve_rp = resolve_result; resolve_rp != NULL; resolve_rp = resolve_rp->ai_next)
	{
		struct sockaddr_in *ipv4_addr = (struct sockaddr_in *)resolve_rp->ai_addr;
		sv_addr->sin_addr = ipv4_addr->sin_addr;
	}
	freeaddrinfo(resolve_result);

	return 1;
}

int main(int argc, char** argv)
{
	int ms_timeout, retries, protocol, res;
	char format_addr[16] = {0};
	struct sockaddr_in src;
	struct sockaddr_in dst;

	memset(&src, 0, sizeof(struct sockaddr_in));
	memset(&dst, 0, sizeof(struct sockaddr_in));

	setbuf(stdout, NULL); // unbuffered output

	if (!validateArgs(argc, argv, &src, &dst, &protocol, &ms_timeout, &retries))
	{
		fprintf(stderr, "Usage:\nICMP mode: sudo %s -p icmp -s <destination> [-t <timeout> -r <max-requests>]\nUDP mode: %s -p udp -s <destination:port> [-l <address:port> -t <timeout> -r <max-requests>]\n", argv[0], argv[0]);
		return 1;
	}

	res = mtu_discovery(&src, &dst, protocol, retries, ms_timeout);
	if (res < 0)
	{
		if (res == MTU_ERR_TIMEOUT)
			fprintf(stderr, "No reply from %s.\n", inet_ntop(AF_INET, &dst.sin_addr, format_addr, 16));
	}
	else
		printf("\nPLPMTUD to %s: %d bytes (20 IPv4 header + 8 %s header + %d data).\n", inet_ntop(AF_INET, &dst.sin_addr, format_addr, 16), res, protocol == MTU_PROTO_UDP? "UDP" : "ICMP", res - MTU_IPSIZE - MTU_UDPSIZE);
	return 0;
}
