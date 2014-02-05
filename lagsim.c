/*
 * lagsim.c
 */

#include<pcap/pcap.h>
#include<stdint.h>
#include<cstring>
#include<cstdlib>
#include<cstdio>
#include<pthread.h>

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

struct injector_conf_t
{
  int ifc;    // interface count
  const char** ifv; // list of interface names
};

void * injector_task(void* ptr)
{
  injector_conf_t * conf = (injector_conf_t *) ptr;
  printf("Hi, I'm the injector! ifc=%d\n",conf->ifc);
  for (int i=0; i<conf->ifc; i++)
  {
    printf("  %s\n",conf->ifv[i]);
  }

}

int main(int argc, char* argv[])
{
  const char * iface_a = "eth0";
  const char * iface_b = "eth1";
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

  // configure and launch injector task
  pthread_t injector_thread;
  injector_conf_t injector_conf;
  injector_conf.ifc = 2;
  injector_conf.ifv = (const char**) malloc(injector_conf.ifc*sizeof(char*));
  injector_conf.ifv[0] = iface_a;
  injector_conf.ifv[1] = iface_b;
  pthread_create(&injector_thread,NULL,injector_task,&injector_conf);

  // wait for tasks to finish
  pthread_join(injector_thread,NULL);

  return 0;
}

