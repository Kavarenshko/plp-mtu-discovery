
#include <stdio.h>
#include <string.h>
#include <unistd.h> // getopt()
#include <arpa/inet.h> // inet_pton()
#include <netinet/in.h> // struct sockaddr_in

#include "mtu.h"

int validateArgs(int argc, char** argv, struct sockaddr_in* lc_addr, struct sockaddr_in* sv_addr, int* proto, int* ms_timeout, int* max_retries)
{
	// this function returns 1 if the command line arguments are valid, 0 otherwise

	int opt, lc_port, sv_port;
	int pt_given = 0; // 1 if protocol is provided
	int lc_given = 0; // 1 if local addr is provided
	int sv_given = 0; // 1 if server addr is provided
	char lc_ip[16] = {0};
	char sv_ip[16] = {0};

	*ms_timeout  = MTU_DEFAULT_TIMEOUT;
	*max_retries = MTU_DEFAULT_RETRIES;

	lc_addr->sin_family = AF_INET;
	sv_addr->sin_family = AF_INET;

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
					return 0;
				break;
			case 's': // server addr (address)
				sv_given = 1;
				if (*proto == MTU_PROTO_UDP && sscanf(optarg, "%[^:]:%d", sv_ip, &sv_port) == 2)
					break;
				else if (*proto == MTU_PROTO_ICMP)
				{
					strcpy(sv_ip, optarg);
					break;
				}
				else // should not happen
					return 0;
			case 'l': // local addr (address:port)
				lc_given = 1;
				if (*proto == MTU_PROTO_UDP && sscanf(optarg, "%[^:]:%d", lc_ip, &lc_port) != 2)
					return 0;
				else if (*proto == MTU_PROTO_ICMP)
					strcpy(lc_ip, optarg);
				else // should not happen
					return 0;
				break;
			case 't': // timeout
				if (sscanf(optarg, "%d", ms_timeout) != 1)
					return 0;
				break;
			case 'r': // max retries
				if (sscanf(optarg, "%d", max_retries) != 1)
					return 0;
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

	if (*ms_timeout < 0)
	{
		fprintf(stderr, "Invalid timeout value '%d'\n", *ms_timeout);
		return 0;
	}

	if (*max_retries < 0)
	{
		fprintf(stderr, "Invalid retry value '%d'\n", *max_retries);
		return 0;
	}

	if (lc_given)
	{
		if (*proto == MTU_PROTO_UDP)
		{
			if (lc_port < 1 || lc_port > 65535)
			{
				fprintf(stderr, "Invalid local port number '%d'.\n", lc_port);
				return 0;
			}
			lc_addr->sin_port = htons(lc_port);
		}

		if (strcmp("localhost", lc_ip) == 0)
			inet_pton(AF_INET, "127.0.0.1", &lc_addr->sin_addr);
		else if (inet_pton(AF_INET, lc_ip, &lc_addr->sin_addr) == 0)
		{
			fprintf(stderr, "Invalid local address '%s'.\n", lc_ip);
			return 0;
		}
	}
	else
	{
		lc_addr->sin_port = 0; // filled in by the kernel when using UPD, unused in ICMP
		inet_pton(AF_INET, "0.0.0.0", &lc_addr->sin_addr);
	}

	if (*proto == MTU_PROTO_UDP)
	{
		if (sv_port < 1 || sv_port > 65535)
		{
			fprintf(stderr, "Invalid server port number '%d'.\n", sv_port);
			return 0;
		}
		sv_addr->sin_port = htons(sv_port);
	}
	else
		sv_addr->sin_port = 0; // filled in by the kernel when using UPD, unused in ICMP

	if (strcmp("localhost", sv_ip) == 0)
		inet_pton(AF_INET, "127.0.0.1", &sv_addr->sin_addr);
	else if (inet_pton(AF_INET, sv_ip, &sv_addr->sin_addr) == 0)
	{
		fprintf(stderr, "Invalid server address '%s'.\n", sv_ip);
		return 0;
	}

	return 1;
}

int main(int argc, char** argv)
{
	int ms_timeout, retries, protocol, res;
	char format_addr[16] = {0};
	struct sockaddr_in src = {0};
	struct sockaddr_in dst = {0};

	setbuf(stdout, NULL); // unbuffered output

	if (!validateArgs(argc, argv, &src, &dst, &protocol, &ms_timeout, &retries))
	{
		fprintf(stderr, "Usage:\nUDP discovery: %s -p udp -s <ip:port> [-l <ip:port> -t <timeout> -r <max-retries>]\nICMP discovery: sudo %s -p icmp -s <ip> [-l <ip> -t <timeout> -r <max-retries>]\n", argv[0], argv[0]);
		return 1;
	}

	res = mtu_discovery(&src, &dst, protocol, retries, ms_timeout);
	printf("\nPLPMTUD to %s: %d bytes (20 IPv4 header + 8 %s header + %d data).\n", inet_ntop(AF_INET, &dst.sin_addr, format_addr, 16), res, protocol == MTU_PROTO_UDP? "UDP" : "ICMP", res - 28);

	return 0;
}
