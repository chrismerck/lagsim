/*
 * pcap-test.c
 */

#include<pcap/pcap.h>
#include<stdint.h>
#include"crc32.h"

//typedef void (*pcap_handler)(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
  char src[24];
  char dst[24];
  sprintf(dst,"%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
      bytes[0],bytes[1],bytes[2],bytes[3],
      bytes[4],bytes[5],bytes[6],bytes[7]);
  sprintf(src,"%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
      bytes[8],bytes[9],bytes[10],bytes[11],
      bytes[12],bytes[13],bytes[14],bytes[15]);
  //uint32_t crc32(uint32_t crc, const void *buf, size_t size);
  uint32_t crc = crc32(0/*initial value*/, bytes, h->caplen);
  printf("Got packet SRC: %s   DST: %s   CRC32: %08X\n",src,dst,crc);
}

#define IFACE_A "eth0"

int main(int argc, char* argv[])
{
  char errbuf[PCAP_ERRBUF_SIZE];
  int r;
  pcap_t* p_pcap;

  // get a new packet capture handle
  p_pcap = pcap_create(IFACE_A, errbuf);
  if (p_pcap==NULL)
  {
    fprintf(stderr,"Error: Failed to create pcap handle: %s",errbuf);
    return -1;
  }
 
  // capture packets of any size
  pcap_set_snaplen(p_pcap, 65535);

  // set promiscuous mode
  pcap_set_promisc(p_pcap, 1);

  // use high-precision host-synchronized timestamps from adaptor
  switch (pcap_set_tstamp_type(p_pcap, PCAP_TSTAMP_ADAPTER))
  {
    case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
      fprintf(stderr,"Warning: Interface does not support this timestamp type.\n");
      break;
    case PCAP_ERROR_CANTSET_TSTAMP_TYPE:
      fprintf(stderr,"Warning: Interface does not support setting the timestamp type.\n");
      break;
  }

  // activate the handle
  r = pcap_activate(p_pcap);
  if (r!=0)
  {
    fprintf(stderr,"Warning: Non-zero return from pcap_activate: %02X\n",r);
  }

  if (pcap_setdirection(p_pcap, PCAP_D_IN) != 0)
  {
    pcap_perror(p_pcap, (char*) "Error: Failed to set capture direction");
    // if we were to continue, we would cause a packet storm
    return -1;
  }

  // get linktype (should be LINKTYPE_ETHERNET)
  int i_linktype = pcap_datalink(p_pcap);
  fprintf(stderr,"Info: Linktype is %02X.\n",i_linktype);

  // capture packets until interrupt
  pcap_loop(p_pcap, 0/*infinity*/, callback, NULL/*user*/);
  printf("Finished.");

  // cleanup
  pcap_close(p_pcap);

  return 0;
}
