#ifndef TOBEST_H
#define TOBEST_H

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>

#define MAX_PKT_SIZE 1500
#define MAX_PP_NUM 400
#define MAX_PT_NUM 400
#define PT_BLOCK_LENGTH 20
#define SRC_PORT 54321
#define DEST_PORT 54321
#define DATA_LENGTH 1460

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};


#endif //TOBEST_H
