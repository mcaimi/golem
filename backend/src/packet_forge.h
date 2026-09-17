
/*-----------------------------------------------------------------------*/
/* Code file: packet_forge.h                                             */
/* Packet generation framework                                           */
/*-----------------------------------------------------------------------*/

#ifndef PACKET_FORGE_H
#define PACKET_FORGE_H

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "arp.h"
#include "ether-def.h"
#include "platform.h"
#include "utils.h"

//  this structure works as a container for all infos gathered about a single
//  NIC
struct _NIC_info {
  in_addr_t ip_address;
  u_int8_t mac_address[ETHER_ADDR_LEN];
  unsigned char mac_address_string[18];
};

typedef struct _NIC_info nic_info_t;

//  defined in utils.c
extern void die(const char *format, ...);

//  forces the kernel to arp
void force_arp(in_addr_t dst);

//  gathers info about a local NIC
nic_info_t *get_hw_addr(char *iface);

//  gathers info about a remote NIC
nic_info_t *get_peer_hw_addr(char *ife, char *IP_addr);

//  Builds a new nic_info_t from data fed from command line
nic_info_t *new_nic_info_t(char *IPAddr, char *MACAddr);

//  builds a valid ARP header
void arp_forgery(int h_type, unsigned char e_len, unsigned char p_len,
                 unsigned char *source_hardware, unsigned char *target_hardware,
                 unsigned char *spa, unsigned char *tpa,
                 unsigned char ARP_ioctl_num, unsigned char *packet);

//  builds a valid ethernet frame header
void ether_forgery(int PTYPE, unsigned char *source_address,
                   unsigned char *target_address, unsigned char *packet);

#endif
