
#ifndef MTU_DISCOVERY_H
#define MTU_DISCOVERY_H

#include <sys/socket.h> // socket()
#include <netinet/ip.h> // struct ip
#include <netinet/ip_icmp.h> // struct icmphdr

#define MTU_ERR_PARAM    -1 // invalid parameter
#define MTU_ERR_TIMEOUT  -2 // timeout
#define MTU_ERR_SOCK     -3 // socket creation error

#define MTU_DEFAULT_RETRIES 3    // the number of times a packet is sent before declaring a MTU size invalid
#define MTU_DEFAULT_TIMEOUT 1000 // milliseconds

// packet size in bytes

#define MTU_IPSIZE   20 // IPv4 header size
#define MTU_UDPSIZE  8  // UDP header size
#define MTU_ICMPSIZE 8  // ICMP header size

#define MTU_MINSIZE  68     // minimum MTU size in bytes (RFC 1191, Sect.3)
#define MTU_MAXSIZE  65536  // maximum IPv4 size in bytes (RFC 791)

#if defined(__APPLE__) || defined(__MACH__)
	#define MTU_PLATFORM_TYPE 1
	struct icmphdr
	{
		u_int8_t type;
		u_int8_t code;
		u_int16_t checksum;
		union
		{
			struct
			{
				u_int16_t id;
				u_int16_t sequence;
			} echo;
			u_int32_t gateway;
			struct
			{
				u_int16_t __vunused;
				u_int16_t mtu;
			} frag;
		} un;
	};
#elif defined(_WIN32) || defined(_WIN64)
	#define MTU_PLATFORM_TYPE 2
#else
	#define MTU_PLATFORM_TYPE 3
#endif

struct mtu_ip_packet
{
	struct ip ip_hdr;        // IPv4 header (only used when receiving ICMP packets)
	struct icmphdr icmp_hdr; // ICMP header (used when sending and receiving ICMP packets)
	char data[MTU_MAXSIZE];  // payload for ICMP and UDP packets
};

typedef enum { MTU_PROTO_ICMP = 1, MTU_PROTO_UDP = 2 } mtu_protocol;

int mtu_discovery(struct sockaddr_in* source, struct sockaddr_in* dest, int protocol, int max_tries, int timeout);

#endif
