
/*-----------------------------------------------------------------------*/
/* Code file: platform.h                                                 */
/* Platform abstraction layer for Linux/macOS portability                */
/*-----------------------------------------------------------------------*/

#ifndef PLATFORM_H
#define PLATFORM_H

#include <netinet/in.h>

int platform_open_raw_socket(const char *interface);
int platform_send_raw(int fd, const void *packet, int packet_len,
                      const char *interface);
void platform_close_raw(int fd);

int platform_get_local_mac(const char *interface, unsigned char *mac_out);
in_addr_t platform_get_local_ip(const char *interface);

int platform_get_arp_entry(const char *interface, in_addr_t ip,
                           unsigned char *mac_out);

int platform_set_ip_forward(int enable);
int platform_get_ip_forward(void);

#endif
