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

#include"inject.h"

#include<queue> // std::priority_queue

#define QUEUE_TYPE priority_queue<queue_item_t, vector<queue_item_t>, less<queue_item_t> >

using namespace std;

bool verbose = false;

void usage()
{
  printf("Usage: lagsim [OPTIONS]\n");
  printf("\n");
  printf("  --iface-a  iface    specify interface A name (default = eth0)\n");
  printf("  --iface-b  iface    specify interface B name (default = eth1)\n");
  printf("  --latency  ms       network latency (default = 0ms)\n");
  printf("  --jitter   ms       network random jitter (default = 0ms)\n");
  printf("  --loss     percent  network packet loss (default = 0%)\n");
  printf("  --mtu      bytes    modem maximum transmit unit (default = 1500B)\n");
  printf("  --kbps     kbps     modem baud rate (default = infinite)\n");
  printf("  --queue    kB       modem queue size (default = 64kB)\n");
  printf("  --red      percent  Random Early Dropping threshold (default = 100%)\n");
  printf("  --verbose  0|1      verbosity level (default=0)\n");
  printf("\n");
  printf("Report bugs to chrismerck@gmail.com.\n");
  /*
  printf("  --pep               run performance enhancing proxy (PEP)\n");
  // TODO: support more advanced latency models
  // What about ICMP replies for
  */
}

bool compare_timeval(const timeval * a, const timeval * b)
{
  // returns true if a is earlier than b
  if (a->tv_sec < b->tv_sec)
  {
    return true;
  }
  else if (a->tv_sec > b->tv_sec)
  {
    return false;
  }
  else
  {
    return a->tv_usec < b->tv_usec;
  }
}

struct queue_item_t
{
  // scheduled transmit time
  timeval xmit_time; 

  // interface of target interface
  int if_dst;

  // packet length (bytes)
  int len;

  // pointer to packet data
  uint8_t* data;

  // comparison operator for priority queue ordering
  bool operator<(const queue_item_t &that) const
  {
    return compare_timeval(&that.xmit_time,&xmit_time);
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

void get_now(timeval * rv)
{
  // get time and convert to lower resolution timeval
  timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  rv->tv_sec = now.tv_sec;
  rv->tv_usec = now.tv_nsec/1000;
}


void * injector_task(void* ptr)
{
  injector_conf_t * conf = (injector_conf_t *) ptr;
  queue_item_t next;
  timeval now;
  timespec wake_time;

  fprintf(stderr,"Initializing Injector...\n",conf->ifc);

  // create injection sockets
  inject_t ** inj = (inject_t**) malloc(sizeof(inject_t*) * conf->ifc);
  for (int i=0; i<conf->ifc; i++)
  {
    inj[i] = inject_create(conf->ifv[i]);
    if (inj[i]==NULL)
    {
      return (void*)-1;
    }
  }

  // clear wake time signal
  wake_time.tv_sec = 0;

  // injection loop
  pthread_mutex_lock(conf->queue_mutex);
  while (1)
  {
    if (wake_time.tv_sec != 0)
    {
      // wait until the next packet is due,
      //  or until we are signaled
      pthread_cond_timedwait(conf->queue_cond,
          conf->queue_mutex,
          &wake_time);
    }
    else
    {
      // wait until signaled
      pthread_cond_wait(conf->queue_cond,
          conf->queue_mutex);
    }

    // clear wake time signal
    wake_time.tv_sec = 0;

    // is it due yet?
    get_now(&now);

    // lock the queue and send all due packets
    while (!conf->queue->empty())
    {
      // get next packet due
      next = conf->queue->top();

      if (compare_timeval(&next.xmit_time,&now))
      {
        // send now
        inject_send(inj[next.if_dst], next.data, next.len);
        free(next.data); 
        conf->queue->pop();
        if (verbose)
        {
          printf("INJECT %s %d qs=%d\n",
             conf->ifv[next.if_dst], next.len, conf->queue->size());
        }
      }
      else
      {
        // not yet due, schedule wake up
        wake_time.tv_sec = next.xmit_time.tv_sec;
        wake_time.tv_nsec = next.xmit_time.tv_usec*1000;
        break;
      }
    }

    // let producers work
#if 0 // TODO: profile with and without this block
    pthread_mutex_unlock(conf->queue_mutex);
    usleep(1);
    pthread_mutex_lock(conf->queue_mutex);
#endif
  }
}

struct modem_state_t
{
  // modem queue behavior and state
  int queue_max;      // bytes
  timeval next_free_time; 
  double kbps;        // kbits/s
  double red_thresh;  // 0-1

  // network behavior
  double latency; //ms
  double jitter;  //ms
  double loss;    //0-1
};

struct pcap_conf_t
{
  // interface number 
  int if_idx;                      

  // interface name
  const char* if_name;             

  // queue lock
  pthread_mutex_t * queue_mutex;  

  // queue update signal
  pthread_cond_t * queue_cond;   

  // datastructure holding packets
  QUEUE_TYPE * queue;  

  // modem state 
  modem_state_t modem;
};

timeval network_model(modem_state_t * modem, 
    timeval recv_time, const u_char *bytes, int len,
    const char * if_name)
{
  bool drop=false;
  // NOTE: queue simulated by 'next_free_time' variable 

  // handle idling queue
  if (compare_timeval(&modem->next_free_time,&recv_time))
  {
    modem->next_free_time = recv_time;
  }

  // packet queue delay, if kbps given
  double f_queuing_time = 0;
  if (modem->kbps != 0)
  {
    f_queuing_time = ((double)len*8./1000.)/modem->kbps;
  }
  timeval queuing_time;
  queuing_time.tv_sec = (long)f_queuing_time;
  queuing_time.tv_usec = (f_queuing_time-queuing_time.tv_sec)*1000000;
  timeradd(&modem->next_free_time,&queuing_time,&modem->next_free_time);

  // queue overflow
  timeval tmp;
  timersub(&modem->next_free_time,&recv_time,&tmp);
  double queue_delay = max(0.,tmp.tv_sec+tmp.tv_usec/1000000.);
  double queue_size = queue_delay*modem->kbps/8.;
  if (modem->queue_max && queue_size > (double)modem->queue_max)
  {
    // hard-drop
    drop = true;

    // restore queue to previous level
    timersub(&modem->next_free_time,&queuing_time,&modem->next_free_time);
  }

  // systemic latency (not due to queuing)
  long delta_us = (int) (modem->latency*1000);

  // systemic jitter (not due to queuing)
  int jitter_us = ((int)(modem->jitter*1000));
  if (jitter_us>0)
  {
    delta_us += rand()%jitter_us;
  }

  // compute absolute transmit time
  timeval xmit_time;
  timerclear(&xmit_time);
  if (!drop)
  {
    xmit_time.tv_sec = modem->next_free_time.tv_sec + (delta_us/1000000);
    xmit_time.tv_usec = modem->next_free_time.tv_usec + (delta_us%1000000);
  }

  if (verbose)
  {
    printf("NET_MODEL %s\t %d\t q_size %1.0f KB\t %s\n",if_name,len,queue_size,
        drop?"DROP":"");
  }

  return xmit_time;
}

void callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
  pcap_conf_t * conf = (pcap_conf_t *) user;
  queue_item_t item;
  queue_item_t next;

  // set transmit time
  item.xmit_time = network_model(&conf->modem,
      h->ts,bytes,h->caplen,
      conf->if_name);
  if (item.xmit_time.tv_sec==0)
  {
    // packet dropped
    return;
  }

  // set destination
  item.if_dst = (conf->if_idx==0) ? 1 : 0; 

  // copy packet 
  // (because *bytes may be disposed after callback returns)
  item.len = h->caplen;
  item.data = (uint8_t *) malloc(item.len);  
  memcpy(item.data, bytes, item.len);

  // enqueue to injector
  pthread_mutex_lock(conf->queue_mutex);
  bool was_empty = false;
  if (!conf->queue->empty())
  {
    next = conf->queue->top();
    was_empty = true;
  }
  conf->queue->push(item);
  timeval new_top_time = conf->queue->top().xmit_time;
  if (was_empty || conf->queue->top().xmit_time.tv_usec == item.xmit_time.tv_usec)
  {
    // wake up injector b/c new packet needs to be sent
    //  earlier than previous 'next' packet,
    //  or the queue was empty and injector is waiting indefinitely
    pthread_cond_broadcast(conf->queue_cond);
  }
  pthread_mutex_unlock(conf->queue_mutex);

  return;
}


void * pcap_task(void* ptr)
{
  pcap_conf_t * conf = (pcap_conf_t *) ptr;
  char errbuf[PCAP_ERRBUF_SIZE];
  int r;
  pcap_t* p_pcap;

  // TODO: ingore packets sent to iface MAC
  //  This would compete the pseudo-bridge

  // get a new packet capture handle
  p_pcap = pcap_create(conf->if_name, errbuf);
  if (p_pcap==NULL)
  {
    fprintf(stderr,"Error: Failed to create pcap handle: %s",errbuf);
    return (void*) -1;
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
    return (void*) -1;
  }

  // get linktype (should be LINKTYPE_ETHERNET)
  int i_linktype = pcap_datalink(p_pcap);
  fprintf(stderr,"Info: Linktype is %02X.\n",i_linktype);

  // capture packets until interrupt
  pcap_loop(p_pcap, 0/*infinity*/, callback, (u_char*) conf/*user*/);
  fprintf(stderr,"Warning: pcap_loop returned.\n");

  // cleanup
  pcap_close(p_pcap);

  return (void*) 0;
}


int main(int argc, char* argv[])
{
  const char * iface_a = "eth0";
  const char * iface_b = "eth1";
  double opt_latency = 0;
  double opt_jitter = 0;
  double opt_loss = 0;
  double opt_kbps = 0; // kbps
  double opt_red = 100;
  double opt_queue = 0; // KB

  // process command line options
  if (argc==1 || (argc%2)==0)
  {
    usage();
    return 1;
  }
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
      opt_latency = strtod(parm,NULL);
    else if (strcmp(opt,"--jitter")==0)
      opt_jitter = strtod(parm,NULL);
    else if (strcmp(opt,"--loss")==0)
      opt_loss = strtod(parm,NULL);
    else if (strcmp(opt,"--kbps")==0)
      opt_kbps = strtod(parm,NULL);
    else if (strcmp(opt,"--red")==0)
      opt_red = strtod(parm,NULL);
    else if (strcmp(opt,"--queue")==0)
      opt_queue = strtod(parm,NULL);
    else if (strcmp(opt,"--verbose")==0)
      verbose = (bool) atoi(parm);
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
  pthread_mutex_t _queue_mutex = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_t * queue_mutex = &_queue_mutex;
  pthread_cond_t _queue_cond = PTHREAD_COND_INITIALIZER;
  pthread_cond_t * queue_cond = &_queue_cond;

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

  // configure and launch pcap tasks
  pthread_t pcap_thread[2];
  pcap_conf_t pcap_conf[2];
  for (int i=0; i<2; i++)
  {
    pcap_conf[i].if_idx = i;
    pcap_conf[i].if_name = (i==0) ? iface_a : iface_b;
    pcap_conf[i].queue = queue;
    pcap_conf[i].queue_mutex = queue_mutex;
    pcap_conf[i].queue_cond = queue_cond;
    pcap_conf[i].modem.queue_max = opt_queue;
    timerclear(&pcap_conf[i].modem.next_free_time);
    pcap_conf[i].modem.kbps = opt_kbps;
    pcap_conf[i].modem.red_thresh = opt_red;
    pcap_conf[i].modem.latency = opt_latency;
    pcap_conf[i].modem.jitter = opt_jitter;
    pcap_conf[i].modem.loss = opt_loss;
    pthread_create(&pcap_thread[i],NULL,pcap_task,&pcap_conf[i]);
  }

  // wait for tasks to finish
  //pthread_join(injector_thread,NULL);
  while (true)
  {
    switch (getchar())
    {
      case 'q':
        printf("Exiting...\n");
        goto cleanup;
        break;
      default:
        printf("***Status***\n");
        for (int i=0; i<2; i++)
        {
          printf("  Interface %s\n", pcap_conf[i].if_name);
          modem_state_t modem = pcap_conf[i].modem;
          timeval tmp;
          get_now(&tmp);
          timersub(&modem.next_free_time,&tmp,&tmp);
          double queue_delay = max(0.,tmp.tv_sec+tmp.tv_usec/1000000.);
          printf("    Queue Delay: %1.0f ms\n",queue_delay*1000);
          printf("    Queue Size: %1.0f KB\n",queue_delay*modem.kbps*8);
        }
        printf("\n");

    }
  }

  // cleanup
cleanup:
  free(injector_conf.ifv);
  pthread_mutex_destroy(queue_mutex);
  pthread_cond_destroy(queue_cond);
  pthread_exit(NULL);
  return 0;
}

