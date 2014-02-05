/*
 * inject-test.c
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "inject.h"
#include "outgoing-ping.eth.h"

#define IFACE "eth0"
#define MTU 1500

int main(int argc, char *argv[])
{
  inject_t * p_i;

  p_i = inject_create((char*)IFACE);
  if (p_i==NULL)
  {
    return -1;
  }

  //inject_send(p_i,(uint8_t*)packet,packet_length);
  for (int i=0; i<100; i++)
  {
    inject_send(p_i,(uint8_t*)"0123456789ABCDEFXXXX",20);
    printf("Packet successfully injected.\n");
    fflush(stdout);
  }
	return 0;
}
