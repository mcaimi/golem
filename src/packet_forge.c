
/*-----------------------------------------------------------------------*/
/* Code file: packet_forge.c                                             */
/* Packet generation framework                                           */
/*-----------------------------------------------------------------------*/

#include "packet_forge.h"

/*
 * force_arp():
 * forces the kernel to make an arp request
 */
void force_arp(in_addr_t dst) {
  struct sockaddr_in sin;
  int fd;

  //  opening a socket
  if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    die("%s\n", "\033[1;33m[Packet Forge]\033[0m: packet_forge.c::force_arp(): "
                "cannot open a new socket!!\n");

  //  building a fake packet for host "dst"
  bzero(&sin, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = dst;
  sin.sin_port = htons(67); //  fake port, can be whatever you want

  //  force the kernel to arp.
  sendto(fd, NULL, 0, 0, (struct sockaddr *)&sin, sizeof(sin));
  close(fd);
}

/*
 * get_hw_addr()
 * Retrieves the MAC address of your local NIC by calling the system
 */
nic_info_t *get_hw_addr(char *iface) {
  nic_info_t *mac = (nic_info_t *)malloc(sizeof(nic_info_t));
  if (mac == NULL) {
    printf("%s\n", "\033[1;33m[Packet Forge]\033[0m: "
                   "packet_forge.c::get_hw_addr(): OUT OF MEMORY!\n");
    return NULL;
  }
  memset(mac, 0, sizeof(nic_info_t));

  if (platform_get_local_mac(iface, mac->mac_address) < 0) {
    printf("%s\n",
           "\033[1;33m[Packet Forge]\033[0m: packet_forge.c::get_hw_addr(): "
           "Cannot get HW ADDR, Try Again (wrong interface? typo?)\n");
    free(mac);
    return NULL;
  }

  sprintf(mac->mac_address_string, "%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx",
          mac->mac_address[0], mac->mac_address[1], mac->mac_address[2],
          mac->mac_address[3], mac->mac_address[4], mac->mac_address[5]);

  in_addr_t ip = platform_get_local_ip(iface);
  if (ip == INADDR_NONE) {
    printf("%s\n",
           "\033[1;33m[Packet Forge]\033[0m: packet_forge.c::get_hw_addr(): "
           "Cannot get IP ADDR, Try Again (wrong interface? typo?)\n");
    free(mac);
    return NULL;
  }
  mac->ip_address = ip;

  return mac;
}

/*
 * get_peer_hw_addr()
 * gathers info on the NIC at the specified address
 */
nic_info_t *get_peer_hw_addr(char *ife, char *IP_addr) {
  struct in_addr addr;

  if (!inet_aton(IP_addr, &addr)) {
    printf("%s\n", "\033[1;33m[Packet Forge]\033[0m: "
                   "packet_forge.c::get_peer_hw_addr(): Invalid IP\n");
    return NULL;
  }

  unsigned char mac_bytes[6];
  if (platform_get_arp_entry(ife, addr.s_addr, mac_bytes) < 0) {
    printf("%s\n", "\033[1;33m[Packet Forge]\033[0m: "
                   "packet_forge.c::get_peer_hw_addr(): ARP lookup failed");
    printf("%s\n",
           "\033[1;33m[Packet Forge]\033[0m: "
           "packet_forge.c::get_peer_hw_addr(): Trying a workaround...");
    force_arp(inet_addr(IP_addr));
    if (platform_get_arp_entry(ife, addr.s_addr, mac_bytes) < 0) {
      printf("%s\n",
             "\033[1;33m[Packet Forge]\033[0m: "
             "packet_forge.c::get_peer_hw_addr(): ARP lookup failed!!\n");
      printf("%s\n", "\033[1;33m[Packet Forge]\033[0m: "
                     "packet_forge.c::get_peer_hw_addr(): This is not fatal. "
                     "Try relaunching the prg.\n");
      return NULL;
    }
  }

  nic_info_t *hwaddr = (nic_info_t *)malloc(sizeof(nic_info_t));
  if (hwaddr == NULL) {
    printf("%s\n", "\033[1;33m[Packet Forge]\033[0m: "
                   "packet_forge.c::get_peer_hw_addr(): OUT OF MEMORY!\n");
    return NULL;
  }
  memset(hwaddr, 0, sizeof(nic_info_t));

  memcpy(hwaddr->mac_address, mac_bytes, 6);
  sprintf(hwaddr->mac_address_string,
          "%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx", mac_bytes[0],
          mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]);
  hwaddr->ip_address = inet_addr(IP_addr);

  if (strncmp(hwaddr->mac_address_string, "00:00:00:00:00:00",
              strlen("00:00:00:00:00:00")) == 0) {
    free(hwaddr);
    return NULL;
  }

  return hwaddr;
}

/*
 * new_nic_info_t():
 * Builds a new nic_info_t from data fed from command line
 *
 */
nic_info_t *new_nic_info_t(char *IPAddr, char *MACAddr) {
  nic_info_t *temp;
  u_int8_t mac_cyphers[ETHER_ADDR_LEN];
  memset(mac_cyphers, 0, ETHER_ADDR_LEN);
  struct in_addr addr;

  // STRTOK stuff...
  char delim[] = ":";

  //  sanity check on the specified IP address
  if (!inet_aton(IPAddr, &addr)) {
    printf("%s\n", "\033[1;33m[Packet Forge]\033[0m: "
                   "packet_forge.c::new_nic_info_t(): Invalid IP\n");
    return NULL;
  }

  // allocate space for a new nic descriptor
  temp = (nic_info_t *)malloc(sizeof(nic_info_t));
  if (temp == NULL) {
    printf("%s\n", "\033[1;33m[Packet Forge]\033[0m: "
                   "packet_forge.c::new_nic_info_t(): OUT OF MEMORY!\n");
    return NULL;
  }
  memset(temp, 0, sizeof(nic_info_t));

  // parse macaddress..
  mac_cyphers[0] = strtol(strtok(MACAddr, delim), NULL, 16);
  for (int i = 1; i < ETHER_ADDR_LEN; i++) {
    mac_cyphers[i] = strtol(strtok(NULL, delim), NULL, 16);
  }

  // parse IP address and fill data into the new nic descriptor
  temp->ip_address = inet_addr(IPAddr);
  memcpy(temp->mac_address, mac_cyphers, ETHER_ADDR_LEN);
  //  converting the mac address into a string
  sprintf(temp->mac_address_string, "%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx",
          mac_cyphers[0], mac_cyphers[1], mac_cyphers[2], mac_cyphers[3],
          mac_cyphers[4], mac_cyphers[5]);
  // return nic descriptor
  return temp;
}

/*
 * arp_forgery():
 * builds a valid arp header
 */
void arp_forgery(int h_type, unsigned char e_len, unsigned char p_len,
                 unsigned char *source_hardware, unsigned char *target_hardware,
                 unsigned char *spa, unsigned char *tpa,
                 unsigned char ARP_ioctl_num, unsigned char *packet) {
  struct ARP_packet_header arppacket;

  arppacket.ar_hrd = htons(h_type);       // Hardware type setting
  arppacket.ar_pro = htons(ETHERTYPE_IP); // Protocol type setting
  arppacket.ar_hln = e_len;               // Hardware MAC length
  arppacket.ar_pln = p_len;               // Protocol IP length
  arppacket.ar_op = htons(ARP_ioctl_num); // ARP ioctl code

  memcpy(arppacket.ar_sha, source_hardware,
         e_len); // arppacket->ar_sha = source_hardware;
  memcpy(arppacket.ar_tha, target_hardware,
         e_len);                        // arppacket->ar_tha = target_hardware;
  memcpy(arppacket.ar_spa, spa, p_len); // arppacket.ar_spa = spa;
  memcpy(arppacket.ar_tpa, tpa, p_len); // arppacket.ar_tpa = tpa;

  printf("%s\n", "\033[1;33m[Packet Forge]\033[0m: "
                 "packet_forge.c::arp_forgery(): ARP MATCHING Configuration");

  printf("\033[1;33m[Packet Forge]\033[0m: ");
  printf("SENDER IP: \033[1;32m%u.%u.%u.%u\033[0m\n", arppacket.ar_spa[0],
         arppacket.ar_spa[1], arppacket.ar_spa[2], arppacket.ar_spa[3]);

  printf("\033[1;33m[Packet Forge]\033[0m: ");
  printf("SENDER MAC: "
         "\033[1;32m%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx\033[0m\n",
         arppacket.ar_sha[0], arppacket.ar_sha[1], arppacket.ar_sha[2],
         arppacket.ar_sha[3], arppacket.ar_sha[4], arppacket.ar_sha[5]);
  printf("\033[1;33m[Packet Forge]\033[0m: ");
  printf("TARGET IP: \033[1;32m%u.%u.%u.%u\033[0m\n", arppacket.ar_tpa[0],
         arppacket.ar_tpa[1], arppacket.ar_tpa[2], arppacket.ar_tpa[3]);
  printf("\033[1;33m[Packet Forge]\033[0m: ");
  printf("TARGET MAC: "
         "\033[1;32m%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx\033[0m\n",
         arppacket.ar_tha[0], arppacket.ar_tha[1], arppacket.ar_tha[2],
         arppacket.ar_tha[3], arppacket.ar_tha[4], arppacket.ar_tha[5]);

  memcpy(packet, &arppacket, sizeof(struct ARP_packet_header));
}

/*
 * ether_forgery():
 * builds a valid ethernet frame header
 */
void ether_forgery(int PTYPE, unsigned char *source_address,
                   unsigned char *target_address, unsigned char *packet) {
  struct ETHER_packet_header ethframe;

  ethframe.h_proto = htons(PTYPE);              // Protocol type ID
  memcpy(ethframe.h_source, source_address, 6); // SOURCE MAC
  memcpy(ethframe.h_dest, target_address, 6);   // DEST MAC

  printf("%s\n", "\033[1;33m[Packet Forge]\033[0m: "
                 "packet_forge.c::ether_forgery(): MAC Configuration");
  printf("\033[1;33m[Packet Forge]\033[0m: ");
  printf("SENDER MAC: "
         "\033[1;32m%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx\033[0m\n",
         ethframe.h_source[0], ethframe.h_source[1], ethframe.h_source[2],
         ethframe.h_source[3], ethframe.h_source[4], ethframe.h_source[5]);

  printf("\033[1;33m[Packet Forge]\033[0m: ");
  printf("TARGET MAC: "
         "\033[1;32m%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx\033[0m\n",
         ethframe.h_dest[0], ethframe.h_dest[1], ethframe.h_dest[2],
         ethframe.h_dest[3], ethframe.h_dest[4], ethframe.h_dest[5]);
  memcpy(packet, &ethframe, sizeof(struct ETHER_packet_header));
}
