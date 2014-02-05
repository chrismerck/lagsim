/*
 *  inject.h
 */

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

struct inject_t
{
  int sock_fd;
  struct sockaddr_ll sock_addr;
};

inject_t *  inject_create(const char * iface_name);
int         inject_send(inject_t * p_i, const uint8_t * buffer, const int len);
