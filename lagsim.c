/*
 * lagsim.c
 */

#include<pcap/pcap.h>
#include<stdint.h>
#include<cstring>
#include<cstdlib>

void usage()
{
  printf("Usage: lagsim [OPTIONS]\n");
  printf("\n");
  printf("  --iface-a iface    specify interface A name\n");
  printf("  --iface-b iface    specify interface B name\n");
  printf("  --latency ms       average one-way latency\n");
  printf("  --jitter  ms       random variation latency (+-)\n");
  printf("  --loss    percent  base packet loss fraction\n");
  printf("  --mtu     bytes    set maximum transmit unit\n");
  /*
  printf("  --pep               run performance enhancing proxy (PEP)\n");
  printf("  --bandwidth kbps    simulate bandwidth limit \n");
  // TODO: support more advanced latency models
  // What about ICMP replies for
  */
}

int main(int argc, char* argv[])
{
  char * iface_a = NULL;
  char * iface_b = NULL;
  double latency = 0;
  double jitter = 0;
  double loss = 0;
  int mtu = 1500;

  // process command line options
  int len;
  int i=1;
  char* opt;
  char* parm;
  while (i<argc-1)
  {
    opt = argv[i];
    parm = argv[i+1];
    len = strlen(opt);
    if (strcmp(opt,"--iface-a")==0)
      iface_a = parm;
    else if (strcmp(opt,"--iface-b")==0)
      iface_b = parm;
    else if (strcmp(opt,"--latency")==0)
      latency = strtod(parm,NULL);
    else
    {
      fprintf(stderr,"Error processing options.\n\n");
      usage();
      return 1;
    }
    i+=2;
  }

  // validate settings
  if ((iface_a==NULL)||(iface_b==NULL))
  {
    fprintf(stderr,"Error: interface A and B must be specified.\n");
    usage();
    return 1;
  }


  // TODO: everything else...
  printf("%s-->%s, latency=%f\n",iface_a,iface_b,latency);

  return 0;
}

