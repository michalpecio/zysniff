/*
 * zysniff 0.92.2
 *
 * Receives UDP packet trace from a ZyNOS-based router and feeds it to a TAP
 * interface for processing with your favourite sniffer.
 *
 * Zysniff should be easily portable to all *nixes with user space tunneling
 * support, but this version works only on Linux 2.6 because of differences in
 * TUN/TAP creation API.
 *
 *
 * USAGE:
 * zysniff <port> [<buf>]
 *     * port - UDP port to listen on
 *     * buf  - How much memory to allocate for incoming datagrams. Deafults to
 *              280 because my router doesn't capture more than the first 256
 *              bytes of every packet even if I tell it to create bigger trcp
 *              buffer. 24 extra bytes are for header added by ZyNOS.
 *
 * On the router:
 *
 * tc> sys trcpacket destroy
 * tc> sys trcpacket create 1 256	// create new buffer with one big entry
 * tc> sys trcpacket channel mpoa00 incoming
 * tc> sys trcpacket channel enet0 bothway
 * tc> sys trcpacket channel enet1 none
 * tc> sys trcpacket channel enet2 outgoing
 * tc> sys trcpacket udp addr 10.1.2.3	// destination IP address
 * tc> sys trcpacket udp port 1234	// and UDP port
 * tc> sys trcpacket udp switch on
 * tc> sys trcpacket switch on
 *
 *
 * Copyright (c) 2008-2011, Michal Pecio  < michal.pecio at google mail >
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#if defined ( __linux )		// TUN/TAP API is OS-specific
#include <linux/if.h>
#include <linux/if_tun.h>
#else
#error Your OS seems to be unsupported.
#endif


/*
 * This undocumented header prepends every packet sent by trcp. Thanks to SYNACK
 * from dslreports.com forum for decrypting most of it.
 * All fields are in network byte order.
 */
struct trcpacket_header {
	uint32_t	time;		// router's uptime in centiseconds
	uint32_t	tid;		// ID of task which sent this packet
	uint32_t	channel;	// channel ID
	uint16_t	id;		// just i++
	uint16_t	length;		// original length of captured packet

	uint16_t	call;		// ISP (re)connections count, 0 for enet
	uint8_t		direction;	// incoming/outgoing
	uint8_t		foo;		// ? (always 0x00)
	uint8_t		bar[3];		// ? (always 0x000000)
	uint8_t		link_proto;	// link layer protocol
} __attribute__ (( __packed__ ));

/*
 * Packet direction, always relative to the router.
 */
#define DIRECTION_IN	0x11
#define DIRECTION_OUT	0x12

/*
 * Link layer protocols.
 */
#define LINK_PROTO_ETH	0x04	// Ethernet
#define LINK_PROTO_PPP	0x02	// PPP with RFC1331 'Address' & 'Control' fields
#define LINK_PROTO_PPP2	0x01	// same as above
/*
 * mpoa channels emit pairs of verbatim 0x02 and 0x01 packets
 * I don't have any PPPoE device, but I've read somewhere that PPPoE emits 0x02
 * Currently zysniff discards 0x01 packets.
 */


/*
 * PPPoE header. PPP packets are PPPoE-encapsulated before writing to the TAP.
 */
struct pppoe_header {
	uint8_t		vertype;	// PPPoE version and type
	uint8_t		code;
	uint16_t	session_id;
	uint16_t	length;
} __attribute__ (( __packed__ ));

#define PPPOE_VERTYPE		0x11	// version 1 type 1
#define PPPOE_CODE_DATA		0x00	// data packet
#define ETHERTYPE_PPPOEDATA	0x8864

/*
 * These MAC addresses will be used to forge PPPoE frames from PPP packets.
 */
char local_MAC[]  = {0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x01};
char remote_MAC[] = {0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x02};

#define SID	0x1337	// PPPoE session ID for the forged frames


/*
 * Process RFC1331 PPP packet.
 * Returns fake ethernet frame and sets *n to it's length.
 */
char *ppp (char *buf, int *n) {
	if (*n <= sizeof(struct trcpacket_header) + 4) return NULL;
		// it shouldn't be that short

	struct trcpacket_header *trcp_header = (struct trcpacket_header*) buf;
	char *packet = buf + sizeof(*trcp_header) + 2;	// PPP packet with
	*n -= (sizeof(*trcp_header) + 2);		// protocol field

	char *fake_ether = malloc(*n + sizeof(struct ether_header)
					+ sizeof(struct pppoe_header));
	if (fake_ether == NULL) return NULL;

	struct ether_header *eheader = (struct ether_header*) fake_ether;

	eheader->ether_type = htons(ETHERTYPE_PPPOEDATA);

	if (trcp_header->direction == DIRECTION_IN) {
		memcpy(eheader->ether_shost, remote_MAC, ETH_ALEN);
		memcpy(eheader->ether_dhost, local_MAC, ETH_ALEN);
	} else {
		memcpy(eheader->ether_shost, local_MAC, ETH_ALEN);
		memcpy(eheader->ether_dhost, remote_MAC, ETH_ALEN);
	}

	struct pppoe_header *pheader = (struct pppoe_header*) &eheader[1];

	pheader->vertype = PPPOE_VERTYPE;
	pheader->code = PPPOE_CODE_DATA;	// data packet
	pheader->session_id = htons(SID);
	pheader->length = htons(*n);

	memcpy(&pheader[1], packet, *n);
	*n += sizeof(*eheader) + sizeof(*pheader);

	return fake_ether;
}


/*
 * Ethernet frames don't need any special handling. Just copy them to their new
 * home and return pointer.
 * We can't simply return buf+sizeof(struct trcpacket_header) because the packet
 * is going to be free()d in main().
 */
char *eth (char *buf, int *n) {
	*n -= sizeof(struct trcpacket_header);
	char *packet = malloc(*n);

	if (packet != NULL)
		memcpy(packet, buf + sizeof(struct trcpacket_header), *n);

	return packet;
}


#if defined ( __linux )
/*
 * This function creates TAP interface on Linux.
 */
int create_tap () {
	int tap = open("/dev/net/tun", O_RDWR);
	if (tap == -1) {
		int e = errno;
		perror("Opening /dev/net/tun failed");
		if (e == ENOENT) fputs("Try 'modprobe tun'.\n", stderr);
		return -1;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if (ioctl(tap, TUNSETIFF, (void*) &ifr) < 0) {
		perror("TAP creation failed");
		return -1;
	}

	printf(	"Interface %s created. Use these commands to activate it:\n"
		"\n"
		" iptables -t raw -I PREROUTING -i %s -j DROP\n"
		" ifconfig %s up\n"
		"\n"
		"Please note that you REALLY should drop everything coming "
		"from this interface.\n"
		"Failing to do so will make your kernel and applications "
		"respond to packets\n"
		"they shouldn't even know about, which may lead to weird and "
		"potentially \n"
		"destructive behaviour.\n"
		"This netfilter rule doesn't affect programs reading from raw "
		"sockets.\n"
		"\n"
		"\n",
		ifr.ifr_name, ifr.ifr_name, ifr.ifr_name);

	return tap;
}
#endif	/* defined ( __linux ) */


int main (int argc, char *argv []) {
	puts("zysniff 0.92.1\nCopyright (c) 2008-2011, Michal Pecio.\n");

	if ((argc < 2) || (argc > 3)) {
		fputs("USAGE:\nzysniff <port> [<buf>]\n", stderr);
		return -1;
	}

	if (geteuid() != 0)
		fputs("You are not root. This isn't going to work.\n", stderr);

	int sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		perror("socket() failed");
		return 1;
	}

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(atoi(argv[1]));
	if (bind(sock, (struct sockaddr*) &sin, sizeof(sin)) == -1) {
		perror("bind() failed");
		return 1;
	}

	int buflen = 280;		// default buflen = 24 + 256
	if (argc == 3) buflen = atoi(argv[2]);

	struct trcpacket_header *header;
	char *packet = NULL, *buf = NULL;
	int n;

	buf = malloc(buflen);
	if (buf == NULL) {
		perror("Buffer allocation failed");
		return 1;
	}

	int tap = create_tap();
	if (tap == -1) return 1;

	puts("Ready. Press ENTER to start.");
	getc(stdin);
	puts("======================================================");

	while (1)
	{
		n = read(sock, buf, buflen);
		if (n <= sizeof(struct trcpacket_header)) continue;

		fputs(".", stdout);
		fflush(stdout);

		/* hexdump all packets to stdout
		puts(".....................................................");
		int i;
		for (i = 0; i < n; i++) {
			if (i % 16 == 0) printf("\n");
			if (i % 4 == 0) printf(" ");
			if (i == 24) printf("\n                           ");
			printf(" %.2x", buf[i] & 0xff);
		}
		puts("\n");
		//*/

		header = (struct trcpacket_header*) buf;

		/* print some debug info
		printf("ID: %d\t%d bytes\tProto: 0x%2.2x\tCh: 0x%x\tDir: 0x%x\n",
			ntohs(header->id), ntohs(header->length),
			header->link_proto, ntohl(header->channel),
			header->direction);
		//*/


		/*
		 * Handle conversion to ethernet frame.
		 */
		switch (header->link_proto) {
			case LINK_PROTO_PPP:	packet = ppp (buf, &n); break;
			case LINK_PROTO_ETH:	packet = eth (buf, &n); break;
			default:		continue;
		}
		if (packet == NULL) continue;

		write(tap, packet, n);
		free(packet);
	}
}
