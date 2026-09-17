
/*-----------------------------------------------------------------------*/
/* Code file: arp.h                                                      */
/* RFC for ARP network protocol                                          */
/*-----------------------------------------------------------------------*/

#ifndef ARP_H
#define ARP_H

/* ARP protocol HARDWARE identifiers. */
#ifndef ARPHRD_NETROM
#define ARPHRD_NETROM 0
#endif
#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1
#endif
#ifndef ARPHRD_EETHER
#define ARPHRD_EETHER 2
#endif
#ifndef ARPHRD_AX25
#define ARPHRD_AX25 3
#endif
#ifndef ARPHRD_PRONET
#define ARPHRD_PRONET 4
#endif
#ifndef ARPHRD_CHAOS
#define ARPHRD_CHAOS 5
#endif
#ifndef ARPHRD_IEEE802
#define ARPHRD_IEEE802 6
#endif
#ifndef ARPHRD_APPLETLK
#define ARPHRD_APPLETLK 8
#endif
#ifndef ARPHRD_DLCI
#define ARPHRD_DLCI 15
#endif
#ifndef ARPHRD_ATM
#define ARPHRD_ATM 19
#endif
#ifndef ARPHRD_METRICOM
#define ARPHRD_METRICOM 23
#endif
#ifndef ARPHRD_IEEE1394
#define ARPHRD_IEEE1394 24
#endif

/* Dummy types for non ARP hardware */
#ifndef ARPHRD_SLIP
#define ARPHRD_SLIP 256
#endif
#ifndef ARPHRD_CSLIP
#define ARPHRD_CSLIP 257
#endif
#ifndef ARPHRD_SLIP6
#define ARPHRD_SLIP6 258
#endif
#ifndef ARPHRD_CSLIP6
#define ARPHRD_CSLIP6 259
#endif
#ifndef ARPHRD_X25
#define ARPHRD_X25 271
#endif
#ifndef ARPHRD_HWX25
#define ARPHRD_HWX25 272
#endif
#ifndef ARPHRD_PPP
#define ARPHRD_PPP 512
#endif
#ifndef ARPHRD_CISCO
#define ARPHRD_CISCO 513
#endif
#ifndef ARPHRD_LAPB
#define ARPHRD_LAPB 516
#endif
#ifndef ARPHRD_DDCMP
#define ARPHRD_DDCMP 517
#endif
#ifndef ARPHRD_RAWHDLC
#define ARPHRD_RAWHDLC 518
#endif
#ifndef ARPHRD_TUNNEL
#define ARPHRD_TUNNEL 768
#endif
#ifndef ARPHRD_TUNNEL6
#define ARPHRD_TUNNEL6 769
#endif
#ifndef ARPHRD_FRAD
#define ARPHRD_FRAD 770
#endif
#ifndef ARPHRD_LOOPBACK
#define ARPHRD_LOOPBACK 772
#endif
#ifndef ARPHRD_LOCALTLK
#define ARPHRD_LOCALTLK 773
#endif
#ifndef ARPHRD_FDDI
#define ARPHRD_FDDI 774
#endif
#ifndef ARPHRD_IRDA
#define ARPHRD_IRDA 783
#endif

// FiberChannel ARP
#ifndef ARPHRD_FCPP
#define ARPHRD_FCPP 784
#endif
#ifndef ARPHRD_FCAL
#define ARPHRD_FCAL 785
#endif
#ifndef ARPHRD_FCPL
#define ARPHRD_FCPL 786
#endif
#ifndef ARPHRD_FCFABRIC
#define ARPHRD_FCFABRIC 787
#endif

/* 787->799 reserved for fibrechannel media types */
#ifndef ARPHRD_IEEE802_TR
#define ARPHRD_IEEE802_TR 800
#endif
#ifndef ARPHRD_IEEE80211
#define ARPHRD_IEEE80211 801
#endif
#ifndef ARPHRD_IEEE80211_PRISM
#define ARPHRD_IEEE80211_PRISM 802
#endif

// Void type
#ifndef ARPHRD_VOID
#define ARPHRD_VOID 0xFFFF
#endif

/* ARP protocol opcodes. */
#ifndef ARPOP_REQUEST
#define ARPOP_REQUEST 1
#endif
#ifndef ARPOP_REPLY
#define ARPOP_REPLY 2
#endif
#ifndef ARPOP_RREQUEST
#define ARPOP_RREQUEST 3
#endif
#ifndef ARPOP_RREPLY
#define ARPOP_RREPLY 4
#endif
#ifndef ARPOP_InREQUEST
#define ARPOP_InREQUEST 8
#endif
#ifndef ARPOP_InREPLY
#define ARPOP_InREPLY 9
#endif
#ifndef ARPOP_NAK
#define ARPOP_NAK 10
#endif

/* ARP Flag values. */
#ifndef ATF_COM
#define ATF_COM 0x02
#endif
#ifndef ATF_PERM
#define ATF_PERM 0x04
#endif
#ifndef ATF_PUBL
#define ATF_PUBL 0x08
#endif
#ifndef ATF_USETRAILERS
#define ATF_USETRAILERS 0x10
#endif
#ifndef ATF_NETMASK
#define ATF_NETMASK 0x20
#endif
#ifndef ATF_DONTPUB
#define ATF_DONTPUB 0x40
#endif

struct ARP_packet_header {
  unsigned short ar_hrd;   // Hardware type
  unsigned short ar_pro;   // Protocol format
  unsigned char ar_hln;    // Hardware address length
  unsigned char ar_pln;    // Protocol address length
  unsigned short ar_op;    // ARP command
  unsigned char ar_sha[6]; // Source MAC
  unsigned char ar_spa[4]; // Source IP
  unsigned char ar_tha[6]; // Target MAC
  unsigned char ar_tpa[4]; // Target IP
};

typedef struct ARP_packet_header a_header;

#endif
