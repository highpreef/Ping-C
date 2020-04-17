/***************************************************************************
 * *    Cloudflare Challenge: Systems
 * *
 * *    Author: David Jorge
 * *
 * *    Description: ping uses ECHO_REQUEST to mandatorily elicit an 
 * *                 ECHO_RESPONSE from a host or gateway.
 * *    Use: ping [-c count] [-i interval] [-p pattern] [-s packet_size]
 * *         [-t TTL] [-W recv_timeout]
 * *    Opts: 
 * *         -c %count
 * *             Stop after sending %count number of packets.
 * *         -i %interval
 * *             Wait %interval seconds between the sending of each packet.
 * *         -p %pattern
 * *             Fill out packet message with %pattern.
 * *         -s %packet_size
 * *             Specify number of total packet size to be sent 
 * *             (data bytes plus header). 
 * *         -t %TTL
 * *             Set time to live.
 * *         -W %recv_timeout
 * *             Set time to wait for response, in seconds.
 ***************************************************************************/
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netdb.h>
#include <netinet/ip_icmp.h> 
#include <time.h> 
#include <fcntl.h> 
#include <signal.h> 
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// packet constants 
// ping packet size (including header) (bytes)
#define PING_PKT_S 64 

// ttl default
#define TTL_VAL 64
   
// automatic port number 
#define PORT_NO 0  
  
// timeout delay for receiving packets (sec) 
#define RECV_TIMEOUT 1  

// interval between pings (usec)
long int PING_SLEEP = 1000000;
  
// define variable to allow ping sending
int ping_allow=1;

// checksum 
unsigned short checksum(void *b, int len) 
{    
  unsigned short *buf = b; 
  unsigned int sum=0; 
  unsigned short result; 
  
  for (sum = 0; len > 1; len -= 2) 
    sum += *buf++; 

  if (len == 1) 
    sum += *(unsigned char*)buf; 

  sum = (sum >> 16) + (sum & 0xFFFF); 
  sum += (sum >> 16); 
  result = ~sum; 
  return result; 
}

// interrupt handler 
void handler(int sig) 
{ 
    ping_allow=0; 
    return;
}

// structure for address storage
typedef struct {
  char* ip_addr;
  char* reverse_hostname;
  char* recv_host;
} ipaddr;

// opts structure
typedef struct {
  int count;
  int pattern;
  int pckt_size;
  int ttl;
  bool timestamp;
  bool verbose;
  int timeout;

  bool IP_in;
  bool non_looping;
} flags;

// lookup dns 
char* lookup_DNS(char *addr_host, struct sockaddr_in *addr_con) 
{ 
  struct hostent *host_entity; 
  char *ip=(char*)malloc(NI_MAXHOST*sizeof(char)); 
  int i; 
  
  if ((host_entity = gethostbyname(addr_host)) == NULL) { 
    printf("No IP found for hostname or invalid IP address: %s\n", addr_host);
    exit(-1);
  } 
      
  // populate address structure 
  strcpy(ip, inet_ntoa(*(struct in_addr *) host_entity->h_addr)); 
  
  (*addr_con).sin_family = host_entity->h_addrtype; 
  (*addr_con).sin_port = htons (PORT_NO); 
  (*addr_con).sin_addr.s_addr  = *(long*)host_entity->h_addr; 
  
  return ip;  
}

// reverse lookup of the hostname 
char* reverse_lookup_DNS(char *ip_addr) 
{ 
  struct sockaddr_in temp_addr;     
  socklen_t len; 
  char buf[NI_MAXHOST], *ret_buf; 
  
  temp_addr.sin_family = AF_INET; 
  temp_addr.sin_addr.s_addr = inet_addr(ip_addr); 
  len = sizeof(struct sockaddr_in); 
  
  if (getnameinfo((struct sockaddr *) &temp_addr, len, buf, sizeof(buf), NULL, 0, NI_NAMEREQD)) { 
    printf("Could not resolve reverse lookup of hostname\n"); 
    exit(-1);
  } 

  ret_buf = (char*)malloc((strlen(buf) +1)*sizeof(char)); 
  strcpy(ret_buf, buf); 
  return ret_buf; 
}

// make ping requests
void ping(int ping_sockfd, struct sockaddr_in *ping_addr, ipaddr* addresses, flags* opts) 
{ 
  // ping packet structure 
  struct ping_pckt { 
    struct icmphdr hdr; 
    char msg[opts->pckt_size-sizeof(struct icmphdr)]; 
  }; 

  int msg_count = 0;
  int addr_len; 
  bool sent;
  int msg_received_count = 0; 
  int msg_fail_count = 0;
      
  struct ping_pckt pckt; 
  struct sockaddr_in r_addr; 
  struct timespec time_start, time_end, tfs, tfe; 
  long double rtt_msec = 0, total_msec = 0; 
  struct timeval t_out; 
  t_out.tv_sec = opts->timeout; 
  t_out.tv_usec = 0; 

  //receive packet size 
  addr_len=sizeof(r_addr); 
  
  // start time
  clock_gettime(CLOCK_MONOTONIC, &tfs); 
  
  // set socket ip options to TTL
  if (setsockopt(ping_sockfd, SOL_IP, IP_TTL, &opts->ttl, sizeof(opts->ttl)) != 0) { 
    printf("\nSetting socket options to TTL failed!\n"); 
    exit(-1);
  } 
  
  // setting timeout for receiving packets
  setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t_out, sizeof t_out); 
  
  // send icmp packet in a (conditionally) infinite loop
  while(ping_allow && (msg_count < opts->count || !(opts->non_looping))) 
  { 
    // flag for whether packet was sent or not 
    sent = true; 
       
    // populate packet 
    bzero(&pckt, sizeof(pckt)); 
          
    pckt.hdr.type = ICMP_ECHO; 
    pckt.hdr.un.echo.id = getpid(); 
        
    int i;
    for (i = 0; i < sizeof(pckt.msg) - 1; i++) 
      pckt.msg[i] = opts->pattern;   
    pckt.msg[i] = 0; 
        
    pckt.hdr.un.echo.sequence = msg_count++; 
    pckt.hdr.checksum = checksum(&pckt, sizeof(pckt)); 
  
    // interval between packets (usec)
    usleep(PING_SLEEP); 
  
    // current packet time start 
    clock_gettime(CLOCK_MONOTONIC, &time_start); 

    // send packet
    if ( sendto(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*) ping_addr, sizeof(*ping_addr)) <= 0) { 
      msg_fail_count++;
      sent = false; 
    }
    
    // check for recv
    if ( recvfrom(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, &addr_len) <= 0) { 
      msg_fail_count++;
      continue;
    } else { 
      // calculate rtt
      clock_gettime(CLOCK_MONOTONIC, &time_end); 
              
      double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec)) / 1000000.0; 
      rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + timeElapsed; 
              
      // if packet was sent
      if(sent) { 
        if(pckt.hdr.type == 11) { 
          printf("TTL timeout\n");
        } else { 
          msg_received_count++; 

          if (opts->IP_in)
            printf("%d bytes from %s icmp_seq=%d ttl = %d rtt = %Lfms packet loss = %f%%.\n", opts->pckt_size, addresses->ip_addr, msg_count, opts->ttl, rtt_msec, (msg_fail_count / msg_count) * 100.0); 
          else
            printf("%d bytes from %s (%s) icmp_seq=%d ttl = %d rtt = %Lfms packet loss = %f%%.\n", opts->pckt_size, addresses->reverse_hostname, addresses->ip_addr, msg_count, opts->ttl, rtt_msec, (msg_fail_count / msg_count) * 100.0); 
        } 
      } 
    }     
  } 
  
  // calculate total time  
  clock_gettime(CLOCK_MONOTONIC, &tfe); 
  double timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec)) / 1000000.0; 
      
  total_msec = (tfe.tv_sec - tfs.tv_sec) * 1000.0 + timeElapsed; 
  
  // stats  
  if (opts->IP_in)
    printf("\n---%s ping statistics---", addresses->ip_addr); 
  else
    printf("\n---%s ping statistics---", addresses->recv_host); 
  printf("\n%d packets transmitted, %d received, %f%% packet loss, time: %Lfms.\n\n", msg_count, msg_received_count, ((msg_count - msg_received_count) / msg_count) * 100.0, total_msec);  
}

bool isValidIpAddress(char *ipAddress)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

int main(int argc, char** argv)
{
  // allocate structures and set default values
  flags* opts = malloc(sizeof(*opts));
  ipaddr* addresses = malloc(sizeof(*addresses));
  memset(opts, 0, sizeof(*opts));
  memset(addresses, 0, sizeof(*addresses));
  opts->pckt_size = PING_PKT_S;
  opts->ttl = TTL_VAL;
  opts->timeout = RECV_TIMEOUT;

  // parse command line options
  bool improper_args;
  int index;
  int c;

  opterr = 0;

  while ((c = getopt (argc, argv, "c:i:p:s:t:W:")) != -1) {
    switch (c)
    {
     	case 'c':
        if (atoi(optarg) > 0) {
       	  opts->count = atoi(optarg);
          opts->non_looping = true;
        } else {
          printf("Count needs to be a positive integer\n");
          improper_args = true;
        }
       	break;
     	case 'i':
        if (atoi(optarg) >= 0.2)
       	  PING_SLEEP = atoi(optarg) * 1000000;
        else {
          printf("Interval needs to be an integer no less than 0.2 (sec)\n");
          improper_args = true;
        }
       	break;
      case 'p':
       	opts->pattern = atoi(optarg);
       	break;
      case 's':
       	if (atoi(optarg) <= 8) {
          printf("Packet size needs to be positive (bytes minus ICMP header size)\n");
          exit(-1);
        } else {
          opts->pckt_size = atoi(optarg);
        }
        break;
      case 't':
        if (atoi(optarg) <= 1) {
          printf("TTL must be bigger than 1\n");
          exit(-1);
        } else {
          opts->ttl = atoi(optarg);
        }
       	break;
      case 'W':
        if (atoi(optarg) <= 0) {
          printf("Timeout needs to be bigger than 0\n");
          exit(-1);
        } else
       	  opts->timeout = atoi(optarg);
       	break;	
    	case '?':
       	if (optopt == 'c')
       		fprintf (stderr, "Option -%c requires an argument.\n", optopt);
       	else if (optopt == 'i')
       		fprintf (stderr, "Option -%c requires an argument.\n", optopt);
       	else if (optopt == 'p')
       		fprintf (stderr, "Option -%c requires an argument.\n", optopt);
       	else if (optopt == 's')
       		fprintf (stderr, "Option -%c requires an argument.\n", optopt);
       	else if (optopt == 't')
       		fprintf (stderr, "Option -%c requires an argument.\n", optopt);
       	else if (optopt == 'W')
       		fprintf (stderr, "Option -%c requires an argument.\n", optopt);
        else if (isprint (optopt))
       		fprintf (stderr, "Unknown option `-%c'.\n", optopt);
       	else
       		fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
       		return 1;
      	default:
        	abort();
    }

    if (improper_args) 
      exit(-1);
  }

  // define structures and variables
  int sockfd;
  struct sockaddr_in addr_con;
  int addrlen = sizeof(addr_con);
  char net_buf[NI_MAXHOST];

  // check only 1 non-option argument is passed
  if (optind + 1 == argc)
    addresses->recv_host = argv[optind];
  else {
    printf("\nToo many arguments\n");
    exit(-1);
  }

  // dns lookup and populate address structure
  addresses->ip_addr = lookup_DNS(addresses->recv_host, &addr_con);

  // reverse dns lookup for hostname only if not passed a valid IP address
  if (isValidIpAddress(addresses->recv_host)) {
    opts->IP_in = true;
  } else {
    addresses->reverse_hostname = reverse_lookup_DNS(addresses->ip_addr);
  }

  // create raw socket
  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sockfd < 0) {
    printf("\nFailed to create socket\n");
    exit(-1);
  } else {
    if (opts->IP_in)
      printf("PING %s (%s) with %d bytes of data\n", addresses->ip_addr, addresses->ip_addr, opts->pckt_size - (int) sizeof(struct icmphdr));
    else
      printf("PING %s (%s) with %d bytes of data\n", addresses->recv_host, addresses->ip_addr, opts->pckt_size - (int) sizeof(struct icmphdr));
  }

  // catch any user interrupt
  signal(SIGINT, handler);

  // build and send ICMP packets 
  ping(sockfd, &addr_con, addresses, opts);

  return 0;
}