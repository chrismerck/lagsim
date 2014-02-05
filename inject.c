/*
 *  inject.c
 */

#include "inject.h"

inject_t * inject_create(const char * iface_name)
{
  inject_t * p_i = (inject_t*) malloc(sizeof(inject_t));
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll sock_addr;
	
	/* open raw socket */
	if ((p_i->sock_fd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) 
  {
	    perror("Error opening raw socket");
      fprintf(stderr,"Make sure you are root!\n");
      return NULL;
	}

	/* get the index of the desired interface */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, iface_name, IFNAMSIZ-1);
	if (ioctl(p_i->sock_fd, SIOCGIFINDEX, &if_idx) < 0)
  {
	    perror("Error getting index of interface");
      return NULL;
  }

	/* set index of interface in socket address */
	p_i->sock_addr.sll_ifindex = if_idx.ifr_ifindex;
	p_i->sock_addr.sll_halen = ETH_ALEN;

	/* Note: Destination MAC must be set before sending */

	return p_i;
}

int inject_send(inject_t * p_i, const uint8_t * buffer, const int len)
{
  /* set destination ethernet address */
  memcpy(p_i->sock_addr.sll_addr, buffer, 8);

	/* send packet */
	if (sendto(p_i->sock_fd, buffer, len, 0, (struct sockaddr*)&(p_i->sock_addr), sizeof(struct sockaddr_ll)) < 0)
  {
    perror("sendto()");
    return -1;
  }

  return 0;
}
