#include "RTWABest.h"

char *Src_Hostname = NULL;
char *Dest_Hostname = NULL;
double Ce, Ab;
int PP_Num = 200;
int PT_Num = 400;
int Pkt_Size = MAX_PKT_SIZE;
int PT_Rate = 0;
int Send_Socket, Receive_Socket;
int Udp_Socket;
char Pkt_SYN[MAX_PKT_SIZE];
char Pkt_RST[MAX_PKT_SIZE];
struct sockaddr_in Src_Sockaddr, Dest_Sockaddr;
pthread_t pt_send_thread_tid;
pthread_t pt_recv_thread_tid;
FILE *log_file;

void init_sender(char *dest_hostname, int dest_port);
void init_receiver(void);
void init_packet(void);
unsigned short csum(unsigned short *,int);
void set_tcp_seq(char *packet, int seq);
void set_ip_id(char *packet, int id);
void send_packet(char *packet, int size);
void send_udp_packet(int size);
int receive_packet();
int is_feedback(char *buffer, int size);
int filter_rtt(int *rtt1, int *rtt2, double *ce, int size);
void *pt_send_thread(void * argv);
void *pt_recv_thread(void * argv);
void estimate_ce(void);
void estimate_ab(void);
void clear_up(int arg);
double calculateCe(double* ce, int ce_count);

void my_usleep(double usec);
int cmp_int(const void *a , const void *b );
int cmp_double(const void *a , const void *b );

int main(int argc, char **argv)
{
    struct timeval start_time, end_time;
    int total_time;
    //use getopt to parse the command line
    int c;
    while ((c = getopt(argc, argv, "p:h:s:n:m:r:")) != EOF)
    {
        switch (c)
        {
            case 'c'：
                Src_Hostname = optarg;
                break;
            case 'h':
                Dest_Hostname = optarg;
                break;
            case 's':
                printf("packet size: %d\n", atoi(optarg));
                Pkt_Size = atoi(optarg);
                if (Pkt_Size > MAX_PKT_SIZE){
                    Pkt_Size = MAX_PKT_SIZE;
                }
                else if(Pkt_Size < 60)
                {
                    Pkt_Size = 60;
                }
                break;
            case 'n':
                printf("number of packet pair: %d\n", atoi(optarg));
                PP_Num = atoi(optarg);
                if (PP_Num > MAX_PP_NUM / 2){
                    PP_Num = MAX_PP_NUM / 2;
                }
                break;
            case 'm':
                printf("number of packet train: %d\n", atoi(optarg));
                PT_Num = atoi(optarg);
                if (PT_Num > MAX_PT_NUM){
                    PT_Num = MAX_PT_NUM;
                }
                break;
            case 'r':
                printf("overwrite packet train rate: %d\n", atoi(optarg));
                PT_Rate = atoi(optarg);
                break;
            case '?':
                printf("Usage:\n");
                printf("%s -c src_ip -h dest_ip\n"
                        "\t[-s packet_size_bytes]\n"
                        "\t[-n num_packet_pair]\n"
                        "\t[-m train_length]\n"
                        "\t[-r packet_train_rate]\n", argv[0]);
                exit(1);
                break;
            default:
                printf("WARNING: no handler for option %c\n", c);
                printf("Usage:\n");
                printf("%s -c src_ip -h dest_ip\n"
                        "\t[-s packet_size_bytes]\n"
                        "\t[-n num_packet_pair]\n"
                        "\t[-m train_length]\n"
                        "\t[-r packet_train_rate]\n", argv[0]);
                exit(1);
                break;
            }
    }//end of parse the command line

    // Handle ctrl-C is not quit normally
    signal(SIGINT, clear_up);

    //open log file
    log_file = fopen("log.txt", "a+");
    if(log_file == NULL)
    {
        perror("open log file failed");
        exit(1);
    }

    init_sender(Dest_Hostname, DEST_PORT);
    init_receiver();
    init_packet();

    gettimeofday(&start_time,NULL);
    estimate_ce();
    estimate_ab();
    gettimeofday(&end_time,NULL);
    total_time = (end_time.tv_sec - start_time.tv_sec)*1000000
                + (end_time.tv_usec - start_time.tv_usec);
    printf("ce = %.2fMbps\tab = %.2fMbps\ttime = %dus\n",Ce, Ab, total_time);

    clear_up(0);
    return 0;
}

void init_sender(char *dest_hostname, int dest_port)
{
    struct hostent *hp;                          // Host entry
    bzero((void *) &Dest_Sockaddr, sizeof(Dest_Sockaddr));
    if ((hp = gethostbyname(dest_hostname)) == NULL)
    {
        perror("dest host name error");
        exit(1);
    }
    bcopy(hp->h_addr, (char *) &Dest_Sockaddr.sin_addr, hp->h_length);
    Dest_Sockaddr.sin_family = AF_INET;
    Dest_Sockaddr.sin_port = htons(dest_port);

    /*----- raw tcp socket -----*/
    Send_Socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(Send_Socket == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("failed to create socket");
        exit(1);
    }

    if (setsockopt (Send_Socket, IPPROTO_IP, IP_HDRINCL, (int[]){1}, sizeof (int)) < 0)
    {
        perror("set send_socket IP_HDRINCL failed");
        exit(1);
    }

    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    if (setsockopt(Send_Socket,SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0 )
    {
        perror("set send_socket send timeout failed!");
        exit(1);
    }

    /*----- udp socket -----*/
    Udp_Socket = socket(AF_INET,
    SOCK_DGRAM,   // Socket类型
    IPPROTO_UDP); // 协议

    if (Udp_Socket < 0){
        perror("Failed in creating UDP socket");
        clear_up(1);
    }
}

void init_receiver(void)
{
    struct timeval timeout;
    timeout.tv_usec = 0;
    timeout.tv_sec = 5;

    Receive_Socket = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(setsockopt(Receive_Socket,SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0 )
    {
        perror("set receive timeout failed!");
        exit(1);
    }
}

void init_packet(void)
{
    //get src ip
    struct hostent *hp;
    if ((hp = gethostbyname(Src_Hostname)) == NULL)
    {
        perror("src host name error");
        exit(1);
    }
    bcopy(hp->h_addr, (char *) &Src_Sockaddr.sin_addr, hp->h_length);

    //IP header
    struct iphdr *iph;
    //TCP header
    struct tcphdr *tcph;
    struct pseudo_header psh;

    //SYN
    iph = (struct iphdr *) Pkt_SYN;
    tcph = (struct tcphdr *) (Pkt_SYN + sizeof (struct ip));
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = Pkt_Size;
    iph->id = htons(0); //Id of this packet
    iph->protocol = IPPROTO_TCP;
    iph->frag_off |= htons(0);
    iph->ttl = 255;
    iph->check = 0;//Set to 0 before calculating checksum
    iph->saddr = Src_Sockaddr.sin_addr.s_addr;
    iph->daddr = Dest_Sockaddr.sin_addr.s_addr;
    iph->check = csum ((unsigned short *) Pkt_SYN, iph->ihl);
    tcph->source = htons(SRC_PORT);
    tcph->dest = htons(DEST_PORT);
    tcph->seq = htonl(0);
    tcph->ack_seq = htonl(0);
    tcph->doff = 5;  //tcp header size
    tcph->fin=0;
    tcph->syn=0;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons(3500); /* maximum allowed window size */
    tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;
    psh.source_address = Src_Sockaddr.sin_addr.s_addr;
    psh.dest_address = Dest_Sockaddr.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(Pkt_Size - sizeof(struct ip));
    int psize = Pkt_Size - sizeof(struct ip) + sizeof(struct pseudo_header) - sizeof(struct tcphdr);
    char buffer[2000];
    memcpy(buffer , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(buffer + sizeof(struct pseudo_header) , tcph , Pkt_Size - sizeof(struct ip));
    tcph->check = csum((unsigned short*)buffer , psize);
    //RST
    iph = (struct iphdr *) Pkt_RST;
    tcph = (struct tcphdr *) (Pkt_RST+ sizeof (struct ip));
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = Pkt_Size;
    iph->id = htons (0); //Id of this packet
    iph->protocol = IPPROTO_TCP;
    iph->frag_off |= htons(0);
    iph->ttl = 255;
    iph->check = 0;//Set to 0 before calculating checksum
    iph->saddr = Src_Sockaddr.sin_addr.s_addr;
    iph->daddr = Dest_Sockaddr.sin_addr.s_addr;
    iph->check = csum((unsigned short *) Pkt_RST, iph->ihl);
    tcph->source = htons(SRC_PORT);
    tcph->dest = htons (DEST_PORT);
    tcph->seq = htonl(0);
    tcph->ack_seq = htonl(0);
    tcph->doff = 5;  //tcp header size
    tcph->fin=0;
    tcph->syn=0;
    tcph->rst=1;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons(3500); /* maximum allowed window size */
    tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;
    psh.source_address = Src_Sockaddr.sin_addr.s_addr;
    psh.dest_address = Dest_Sockaddr.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(Pkt_Size - sizeof(struct ip));
    memcpy(buffer, (char*) &psh , sizeof (struct pseudo_header));
    memcpy(buffer + sizeof(struct pseudo_header) , tcph , Pkt_Size - sizeof(struct ip));
    tcph->check = csum( (unsigned short*)buffer, psize);
}

unsigned short csum(unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
    return (answer);
}

void set_tcp_seq(char *packet, int seq)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct pseudo_header psh;

    iph = (struct iphdr*) packet;
    tcph = (struct tcphdr *)(packet + sizeof (struct ip));
    tcph->seq = htonl(seq);

    tcph->check = 0;
    psh.source_address = Src_Sockaddr.sin_addr.s_addr;
    psh.dest_address = Dest_Sockaddr.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(Pkt_Size - sizeof(struct ip));
    int psize = Pkt_Size - sizeof(struct ip) + sizeof(struct pseudo_header) - sizeof(struct tcphdr);
    char buffer[2000];
    memcpy(buffer , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(buffer + sizeof(struct pseudo_header), tcph, Pkt_Size - sizeof(struct ip));
    tcph->check = csum((unsigned short*)buffer, psize);
}

void set_ip_id(char *packet, int id)
{
    struct iphdr *iph;
    iph = (struct iphdr*)packet;
    iph->id = htons(id);
    iph->check = 0;
    iph->check = csum((unsigned short *)packet, iph->ihl);
}


void send_packet(char *packet, int size)
{
    if(size > MAX_PKT_SIZE)
    {
        size = MAX_PKT_SIZE;
    }
    else if(size < 60)
    {
        size = 60;
    }

    if(sendto(Send_Socket, packet, size , 0,
        (struct sockaddr *)&Dest_Sockaddr, sizeof(Dest_Sockaddr)) < 0)
    {
        perror("sendto failed");
        clear_up(1);
    }
}

void send_udp_packet(int size)
{
    char data_buffer[DATA_LENGTH] = {0};
    if(sendto(Udp_Socket, data_buffer, size , 0,
        (struct sockaddr *)&Dest_Sockaddr, sizeof(Dest_Sockaddr)) < 0)
    {
        perror("sendto failed");
        clear_up(1);
    }
}

int receive_packet()
{
    int data_size, saddr_size;
    char receive_buffer[65536];
    struct sockaddr saddr;

    while(1)
    {
        data_size = recvfrom(Receive_Socket, receive_buffer, 65536,
                            0, &saddr, &saddr_size);
        if(data_size < 0)
        {
            perror("recvfrom timeout");
            return 1;
        }
        else
        {
            if(is_feedback(receive_buffer, data_size) == 1)
            {
                return 0;
            }
            else
            {
                continue;
            }
        }
    }
}

int is_feedback(char *buffer, int size)
{
    struct iphdr *iph = (struct iphdr*)buffer;
    unsigned short iphdrlen = iph->ihl*4;
    struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen);

    if (iph->protocol == 6 && ntohs(tcph->dest) == SRC_PORT)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int filter_rtt(int *rtt1, int *rtt2, double *ce, int size)
{
    int i;
    int valid_ce_count;
    int min_rtt1 = rtt1[0], min_rtt2 = rtt2[0];

    for(i = 1; i < size; i++)
    {
        if(min_rtt1 > rtt1[i])
        {
            min_rtt1 = rtt1[i];
        }
        if(min_rtt2 > rtt2[i])
        {
            min_rtt2 = rtt2[i];
        }
    }

    valid_ce_count = 0;
    for(i = 0; i < size; i++)
    {
        if(rtt1[i] < 2 * min_rtt1 && rtt2[i] < 2 * min_rtt2 && rtt2[i] > rtt1[i])
        {
            ce[valid_ce_count] = (double)Pkt_Size * 8 / (rtt2[i] - rtt1[i]);
            fprintf(log_file,"rtt1[%d]=%dus    \trtt2[%d]=%dus    \tce=%.2fMbps\n",
                    i,rtt1[i],i,rtt2[i],ce[valid_ce_count]);
            valid_ce_count++;
        }
        else
        {
            fprintf(log_file,"rtt1[%d]=%dus    \trtt2[%d]=%dus    \tabort\n",
                    i,rtt1[i],i,rtt2[i]);
        }
    }

    return valid_ce_count;
}

void estimate_ce(void)
{
    int pp_count = 0, ce_count = 0;
    int tcph_seq = 0, iph_id = 0;
    int disperse[MAX_PP_NUM/2];
    int rtt1[MAX_PP_NUM/2], rtt2[MAX_PP_NUM/2];
    double median_ce;
    double ce[MAX_PP_NUM/2];
    struct timeval time_send, time_receive;

    while(pp_count < PP_Num/2)
    {
        set_ip_id(Pkt_SYN, iph_id);
        set_tcp_seq(Pkt_SYN, tcph_seq);
        gettimeofday(&time_send, NULL);
        send_packet(Pkt_SYN, Pkt_Size);
        if(receive_packet() == 0)
        {
            gettimeofday(&time_receive, NULL);
            rtt1[pp_count] = (time_receive.tv_sec - time_send.tv_sec)*1000000
                            + (time_receive.tv_usec - time_send.tv_usec);
            pp_count++;
            iph_id++;
            tcph_seq++;
        }
        else
        {
            continue;
        }
    }
    pp_count = 0;
    while(pp_count < PP_Num/2)
    {
        set_ip_id(Pkt_RST, iph_id);
        set_tcp_seq(Pkt_RST, tcph_seq);
        iph_id++;
        tcph_seq++;
        set_ip_id(Pkt_SYN, iph_id);
        set_tcp_seq(Pkt_SYN, tcph_seq);
        gettimeofday(&time_send, NULL);
        send_packet(Pkt_RST, Pkt_Size);
        send_packet(Pkt_SYN, Pkt_Size);
        if(receive_packet() == 0)
        {
            gettimeofday(&time_receive, NULL);
            rtt2[pp_count] = (time_receive.tv_sec - time_send.tv_sec)*1000000
                            + (time_receive.tv_usec - time_send.tv_usec);
            disperse[pp_count] = rtt2[pp_count] - rtt1[pp_count];
            //printf("--- rtt1[%d] = %d, rtt2[%d] = %d ---\n",pp_count, rtt1[pp_count],pp_count,rtt2[pp_count]);
            iph_id++;
            tcph_seq++;
            pp_count++;
        }
        else
        {
            continue;
        }
    }

    ce_count = filter_rtt(rtt1, rtt2, ce, pp_count);
    qsort(ce, ce_count, sizeof(double), cmp_double);
    median_ce = ce[ce_count / 2];
    printf("--- median_ce = %.2f Mbps ---\n", median_ce);


    qsort(rtt1, pp_count, sizeof(int), cmp_int);
    qsort(rtt2, pp_count, sizeof(int), cmp_int);
    printf("--- min_rtt1 = %d min_rtt2 = %d ---\n",rtt1[0],rtt2[0]);
    fprintf(log_file,"***min_rtt1 = %dus min_rtt2 = %dus\n",rtt1[0],rtt2[0]);

    Ce = (double)Pkt_Size*8/(rtt2[0] - rtt1[0]);
    fprintf(log_file,"***ce = Pkt_Size*5/(min_rtt2-min_rtt1) = %.2fMbps\n", Ce);
    fprintf(log_file,"***median ce = %.2fMbps\n\n\n\n", median_ce);

    Ce = calculateCe(ce, ce_count);
}

double calculateCe(double* ce, int ce_count){
    int start_index = ce_count * 6 / 10;
    int end_index = ce_count * 9 / 10;
    int i;
    double sum = 0;
    for(i = start_index; i < end_index; i++){
        sum = sum + ce[i];
    }
    printf("start_index = %d end_index = %d\n", start_index, end_index);
    return sum / (end_index - start_index);
}


void *pt_send_thread(void * argv)
{
    int pt_count = 0;
    double rate, period;
    double total_time_pt;
    struct timeval time_pt_start, time_pt_end;
    double time_send_a_packet;
    struct timeval time_before_send, time_after_send;

    if(PT_Rate > 0)
    {
        rate = PT_Rate;
        Ce = PT_Rate;
    }
    else
    {
        rate = Ce;
    }
    period = Pkt_Size * 8 / rate;

    gettimeofday(&time_pt_start, NULL);
    //send the packet at rate
    set_ip_id(Pkt_SYN, pt_count);
    set_tcp_seq(Pkt_SYN, pt_count);
    send_packet(Pkt_SYN, Pkt_Size);
    while(pt_count < PT_Num)
    {
        gettimeofday(&time_before_send, NULL);
        if((pt_count+1) % PT_BLOCK_LENGTH == 0)
        {
            set_ip_id(Pkt_SYN, pt_count);
            set_tcp_seq(Pkt_SYN, pt_count);
            send_packet(Pkt_SYN, Pkt_Size);
        }
        else
        {
            set_ip_id(Pkt_RST, pt_count);
            set_tcp_seq(Pkt_RST, pt_count);
            //send_packet(Pkt_RST, Pkt_Size);
            send_udp_packet(DATA_LENGTH);
        }
        gettimeofday(&time_after_send, NULL);
        time_send_a_packet = (time_after_send.tv_sec - time_before_send.tv_sec) * 1000000
                            + (time_after_send.tv_usec - time_before_send.tv_usec);
        my_usleep(period - time_send_a_packet);
        pt_count++;
    }
    gettimeofday(&time_pt_end, NULL);
    total_time_pt = (time_pt_end.tv_sec - time_pt_start.tv_sec) * 1000000
                    + (time_pt_end.tv_usec - time_pt_start.tv_usec);
    printf("$$$ real send rate: %.2f $$$\n", PT_Num*Pkt_Size*8/total_time_pt);
}


void *pt_recv_thread(void * argv)
{
    int i;
    int recv_count = 0;
    int disperse[MAX_PT_NUM / PT_BLOCK_LENGTH];
    double r;//througput
    struct timeval time_recv[MAX_PT_NUM / PT_BLOCK_LENGTH + 1];

    while(recv_count < PT_Num / PT_BLOCK_LENGTH + 1)
    {
        if(receive_packet() == 0)
        {
            gettimeofday(&time_recv[recv_count], NULL);
            recv_count++;
        }
        else
        {
            printf("*** pt_recv error %d***\n", recv_count);
            break;
            //clear_up(1);
        }
    }

    for(i = 0; i < PT_Num / PT_BLOCK_LENGTH; i++)
    {
        disperse[i] = (time_recv[i+1].tv_sec - time_recv[i].tv_sec) * 1000000
                    + (time_recv[i+1].tv_usec - time_recv[i].tv_usec);
    }
    qsort(disperse, PT_Num / PT_BLOCK_LENGTH, sizeof(int), cmp_int);
    for(i = 0; i < PT_Num / PT_BLOCK_LENGTH; i++)
    {
        printf("### r[%d] = %.2f ###\n", i, (double)(PT_BLOCK_LENGTH)*Pkt_Size*8/disperse[i] * 1.2);
    }

    r = (double)(PT_BLOCK_LENGTH)*Pkt_Size*8/disperse[PT_Num / PT_BLOCK_LENGTH / 2] * 1.2;
    printf("+++ the throughput r: %.2f Mbps +++\n", r);
    Ab = Ce*(2-Ce/r);
}

void estimate_ab(void)
{
    if(pthread_create(&pt_recv_thread_tid, NULL, pt_recv_thread, NULL) != 0){
  	    printf("create pt_recv_thread error");
  	    clear_up(1);
  	}

 	if (pthread_create(&pt_send_thread_tid, NULL, pt_send_thread, NULL) != 0){
 	    printf("create pt_send_thread error");
 	    clear_up(1);
 	}

    if (pthread_join(pt_recv_thread_tid, NULL) != 0){
        printf("pthread_join error");
        clear_up(1);
    }
}



void clear_up(int arg)
{
    printf("\n*** Tobest stoped! ***\n");
    close(Send_Socket);
    close(Receive_Socket);
    fclose(log_file);
    exit(0);
}

void my_usleep(double usec)
{
    double time_duration;
    struct timeval time_start, time_current;
    gettimeofday(&time_start, NULL);
    while(1)
    {
        gettimeofday(&time_current, NULL);
        time_duration = (time_current.tv_sec - time_start.tv_sec) * 1000000
                        + (time_current.tv_usec - time_start.tv_usec);
        if(time_duration > usec)
        {
            break;
        }
    }
}

int cmp_int( const void *a , const void *b )
{
    return *(int *)a - *(int *)b;   //升序排序
    //return *(int *)b - *(int *)a; //降序排序
}

int cmp_double( const void *a , const void *b )
{
    return *(double *)a - *(double *)b;   //升序排序
    //return *(int *)b - *(int *)a; //降序排序
}
