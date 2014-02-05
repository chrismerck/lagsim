/*
 * lagsim.cpp
 */

#include<pcap/pcap.h>
#include<stdint.h>
#include<cstring>
#include<cstdlib>
#include<cstdio>
#include<ctime>
#include"unistd.h"
#include<pthread.h>

#include<queue> // std::priority_queue

#define QUEUE_TYPE priority_queue<queue_item_t, vector<queue_item_t>, less<queue_item_t> >


using namespace std;

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

struct queue_item_t
{
  // scheduled transmit time
  int xmit_time; 

  // interface of target interface
  int iface_dst;

  // packet length (bytes)
  int len;

  // pointer to packet data
  uint8_t* data;

  // comparison operator for priority queue ordering
  bool operator<(const queue_item_t &that) const
  {
    return xmit_time < that.xmit_time;
  }
};

struct injector_conf_t
{
  // interface count
  int ifc;                      

  // list of interface names
  const char** ifv;             

  // queue lock
  pthread_mutex_t * queue_mutex;  

  // queue update signal
  pthread_cond_t * queue_cond;   

  // datastructure holding packets
  QUEUE_TYPE * queue;  
};

void * injector_task(void* ptr)
{
  injector_conf_t * conf = (injector_conf_t *) ptr;
  queue_item_t next;

  printf("Hi, I'm the injector! ifc=%d\n",conf->ifc);
  for (int i=0; i<conf->ifc; i++)
  {
    printf("  %s\n",conf->ifv[i]);
  }

  while (1)
  {
    pthread_mutex_lock(conf->queue_mutex);
    if (!conf->queue->empty())
    {
      next = conf->queue->top();
      printf("NEXT xmit_time=%d\n",
          next.xmit_time);
      conf->queue->pop();
    }
    else
    {
      printf("EMPTY\n");
    }
    //pthread_cond_signal(conf->queue_cond);
    pthread_mutex_unlock(conf->queue_mutex);

    usleep(1000000);
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

  // setup packet queue and synchronization structures
  QUEUE_TYPE _queue;
  QUEUE_TYPE * queue = &_queue;
  pthread_mutex_t _queue_mutex;
  pthread_mutex_t * queue_mutex = &_queue_mutex;
  pthread_cond_t _queue_cond;
  pthread_cond_t * queue_cond = &_queue_cond;
  pthread_mutex_init(queue_mutex,NULL);
  pthread_cond_init(queue_cond,NULL);

  // configure and launch injector task
  injector_conf_t injector_conf;
  injector_conf.ifc = 2;
  injector_conf.ifv = (const char**) malloc(injector_conf.ifc*sizeof(char*));
  injector_conf.ifv[0] = iface_a;
  injector_conf.ifv[1] = iface_b;
  injector_conf.queue = queue;
  injector_conf.queue_mutex = queue_mutex;
  injector_conf.queue_cond = queue_cond;
  pthread_t injector_thread;
  pthread_create(&injector_thread,NULL,injector_task,&injector_conf);

  // test
  queue_item_t item;
  for (int i=0; i<30; i++)
  {
    item.xmit_time = i;

    pthread_mutex_lock(queue_mutex);
    queue->push(item);
    pthread_mutex_unlock(queue_mutex);

    usleep(100000);
  }

  // wait for tasks to finish
  pthread_join(injector_thread,NULL);

  // cleanup
  pthread_mutex_destroy(queue_mutex);
  pthread_cond_destroy(queue_cond);
  pthread_exit(NULL);
  return 0;
}

