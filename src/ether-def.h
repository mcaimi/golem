/*-----------------------------------------------------------------------*/
/* Code file: ether-def.h                                                */
/* RFC Specifications for ethernet networks                              */
/*-----------------------------------------------------------------------*/

#ifndef ETHER_DEF_H
#define ETHER_DEF_H

/*
  IEEE 802.3 Ethernet magic constants.  The frame sizes omit the preamble
  and FCS/CRC (frame check sequence).
 */
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif
#ifndef ETH_ZLEN
#define ETH_ZLEN 60
#endif
#ifndef ETH_DATA_LEN
#define ETH_DATA_LEN 1500
#endif
#ifndef ETH_FRAME_LEN
#define ETH_FRAME_LEN 1514
#endif

/*
  These are the defined Ethernet Protocol ID's.
 */
#ifndef ETH_P_LOOP
#define ETH_P_LOOP 0x0060
#endif
#ifndef ETH_P_PUP
#define ETH_P_PUP 0x0200
#endif
#ifndef ETH_P_PUPAT
#define ETH_P_PUPAT 0x0201
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_X25
#define ETH_P_X25 0x0805
#endif
#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif
#ifndef ETH_P_BPQ
#define ETH_P_BPQ 0x08FF
#endif
#ifndef ETH_P_IEEEPUP
#define ETH_P_IEEEPUP 0x0a00
#endif
#ifndef ETH_P_IEEEPUPAT
#define ETH_P_IEEEPUPAT 0x0a01
#endif
#ifndef ETH_P_DEC
#define ETH_P_DEC 0x6000
#endif
#ifndef ETH_P_DNA_DL
#define ETH_P_DNA_DL 0x6001
#endif
#ifndef ETH_P_DNA_RC
#define ETH_P_DNA_RC 0x6002
#endif
#ifndef ETH_P_DNA_RT
#define ETH_P_DNA_RT 0x6003
#endif
#ifndef ETH_P_LAT
#define ETH_P_LAT 0x6004
#endif
#ifndef ETH_P_DIAG
#define ETH_P_DIAG 0x6005
#endif
#ifndef ETH_P_CUST
#define ETH_P_CUST 0x6006
#endif
#ifndef ETH_P_SCA
#define ETH_P_SCA 0x6007
#endif
#ifndef ETH_P_RARP
#define ETH_P_RARP 0x8035
#endif
#ifndef ETH_P_ATALK
#define ETH_P_ATALK 0x809B
#endif
#ifndef ETH_P_AARP
#define ETH_P_AARP 0x80F3
#endif
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_IPX
#define ETH_P_IPX 0x8137
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif
#ifndef ETH_P_PPP_DISC
#define ETH_P_PPP_DISC 0x8863
#endif
#ifndef ETH_P_PPP_SES
#define ETH_P_PPP_SES 0x8864
#endif
#ifndef ETH_P_ATMMPOA
#define ETH_P_ATMMPOA 0x884c
#endif
#ifndef ETH_P_ATMFATE
#define ETH_P_ATMFATE 0x8884
#endif

struct ETHER_packet_header {
  u_int8_t h_dest[ETH_ALEN];   // destination ethernet address (MAC)
  u_int8_t h_source[ETH_ALEN]; // source ether address (MAC)
  u_int16_t h_proto;           // packet type ID field
} __attribute__((packed));

typedef struct ETHER_packet_header e_header;

#endif
