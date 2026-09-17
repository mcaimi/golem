
/*-----------------------------------------------------------------------*/
/* Code file: platform.c                                                 */
/* Platform abstraction layer for Linux/macOS portability                */
/*-----------------------------------------------------------------------*/

#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "ether-def.h"

/* ===================================================================== */
/*  Linux implementations                                                */
/* ===================================================================== */
#ifdef __linux__

#include <linux/if_packet.h>
#include <net/if_arp.h>

int platform_open_raw_socket(const char *interface) {
  int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
  if (fd < 0) return -1;

  unsigned int ifindex = if_nametoindex(interface);
  if (ifindex == 0) {
    close(fd);
    return -1;
  }

  struct sockaddr_ll sll;
  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = ifindex;
  sll.sll_protocol = htons(ETH_P_ARP);

  if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    close(fd);
    return -1;
  }

  return fd;
}

int platform_send_raw(int fd, const void *packet, int packet_len,
                      const char *interface) {
  unsigned int ifindex = if_nametoindex(interface);
  if (ifindex == 0) return -1;

  struct sockaddr_ll sll;
  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = ifindex;
  sll.sll_protocol = htons(ETH_P_ARP);

  return (int)sendto(fd, packet, packet_len, 0,
                     (struct sockaddr *)&sll, sizeof(sll));
}

void platform_close_raw(int fd) {
  close(fd);
}

int platform_get_local_mac(const char *interface, unsigned char *mac_out) {
  struct ifreq ifr;
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) return -1;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

  if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
    close(sock);
    return -1;
  }

  memcpy(mac_out, ifr.ifr_hwaddr.sa_data, 6);
  close(sock);
  return 0;
}

int platform_get_arp_entry(const char *interface, in_addr_t ip,
                           unsigned char *mac_out) {
  struct arpreq req;
  struct sockaddr_in *sin;
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) return -1;

  memset(&req, 0, sizeof(req));
  sin = (struct sockaddr_in *)&req.arp_pa;
  sin->sin_family = AF_INET;
  sin->sin_addr.s_addr = ip;
  strncpy(req.arp_dev, interface, sizeof(req.arp_dev) - 1);

  if (ioctl(sock, SIOCGARP, &req) < 0) {
    close(sock);
    return -1;
  }

  memcpy(mac_out, req.arp_ha.sa_data, 6);
  close(sock);
  return 0;
}

int platform_get_ip_forward(void) {
  FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "r");
  if (!f) return -1;
  int val;
  if (fscanf(f, "%d", &val) != 1) {
    fclose(f);
    return -1;
  }
  fclose(f);
  return val;
}

int platform_set_ip_forward(int enable) {
  FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "w");
  if (!f) return -1;
  fprintf(f, "%d", enable ? 1 : 0);
  fclose(f);
  return 0;
}

#endif /* __linux__ */

/* ===================================================================== */
/*  macOS implementations                                                */
/* ===================================================================== */
#ifdef __APPLE__

#include <fcntl.h>
#include <ifaddrs.h>
#include <net/bpf.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <sys/sysctl.h>

int platform_open_raw_socket(const char *interface) {
  char bpf_device[16];
  int fd = -1;

  for (int i = 0; i < 256; i++) {
    snprintf(bpf_device, sizeof(bpf_device), "/dev/bpf%d", i);
    fd = open(bpf_device, O_RDWR);
    if (fd >= 0) break;
  }
  if (fd < 0) return -1;

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name) - 1);
  if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
    close(fd);
    return -1;
  }

  int hdr_complete = 1;
  if (ioctl(fd, BIOCSHDRCMPLT, &hdr_complete) < 0) {
    close(fd);
    return -1;
  }

  return fd;
}

int platform_send_raw(int fd, const void *packet, int packet_len,
                      const char *interface) {
  (void)interface;
  return (int)write(fd, packet, packet_len);
}

void platform_close_raw(int fd) {
  close(fd);
}

int platform_get_local_mac(const char *interface, unsigned char *mac_out) {
  struct ifaddrs *ifap, *ifa;
  if (getifaddrs(&ifap) != 0) return -1;

  for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL) continue;
    if (ifa->ifa_addr->sa_family != AF_LINK) continue;
    if (strcmp(ifa->ifa_name, interface) != 0) continue;

    struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
    if (sdl->sdl_alen == 6) {
      memcpy(mac_out, LLADDR(sdl), 6);
      freeifaddrs(ifap);
      return 0;
    }
  }

  freeifaddrs(ifap);
  return -1;
}

#define ROUNDUP(a) \
  ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

int platform_get_arp_entry(const char *interface, in_addr_t ip,
                           unsigned char *mac_out) {
  (void)interface;
  int mib[6] = {CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO};
  size_t buflen;

  if (sysctl(mib, 6, NULL, &buflen, NULL, 0) < 0) return -1;
  if (buflen == 0) return -1;

  char *buf = malloc(buflen);
  if (buf == NULL) return -1;

  if (sysctl(mib, 6, buf, &buflen, NULL, 0) < 0) {
    free(buf);
    return -1;
  }

  char *end = buf + buflen;
  char *ptr = buf;

  while (ptr < end) {
    struct rt_msghdr *rtm = (struct rt_msghdr *)ptr;
    struct sockaddr_in *sin = (struct sockaddr_in *)(rtm + 1);

    if (sin->sin_addr.s_addr == ip) {
      struct sockaddr_dl *sdl = (struct sockaddr_dl *)
          ((char *)sin + ROUNDUP(sin->sin_len));
      if (sdl->sdl_alen == 6) {
        memcpy(mac_out, LLADDR(sdl), 6);
        free(buf);
        return 0;
      }
    }
    ptr += rtm->rtm_msglen;
  }

  free(buf);
  return -1;
}

int platform_get_ip_forward(void) {
  int val;
  size_t len = sizeof(val);
  if (sysctlbyname("net.inet.ip.forwarding", &val, &len, NULL, 0) < 0)
    return -1;
  return val;
}

int platform_set_ip_forward(int enable) {
  int val = enable ? 1 : 0;
  if (sysctlbyname("net.inet.ip.forwarding", NULL, NULL, &val, sizeof(val)) < 0)
    return -1;
  return 0;
}

#endif /* __APPLE__ */

/* ===================================================================== */
/*  Shared: platform_get_local_ip (works on both Linux and macOS)        */
/* ===================================================================== */

in_addr_t platform_get_local_ip(const char *interface) {
  struct ifreq ifr;
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) return INADDR_NONE;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
  ifr.ifr_addr.sa_family = AF_INET;

  if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
    close(sock);
    return INADDR_NONE;
  }

  struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
  in_addr_t ip = sin->sin_addr.s_addr;
  close(sock);
  return ip;
}
