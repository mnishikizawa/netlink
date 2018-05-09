#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <arpa/inet.h>
#include <time.h>

#define TCPF_ALL 0xFFF
enum{
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING
};

int main(int argc, char **argv) {
    static const char metric_name[] = "nginx.backlog";
    int port, sockfd, len;
    struct msghdr msg;
    struct {
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 req;
    } wbuf;
    struct nlmsghdr *nlh;
    struct sockaddr_nl sa;
    struct iovec iov[2];
    int ret = 0;
    static char rbuf[65535];
    struct rtattr *attr;
    struct tcp_info *info;
    struct inet_diag_msg *diag_msg;
    int rtalen;
    char local_addr_buf[INET6_ADDRSTRLEN];

    if (argc !=3) {
        fprintf(stderr, "Usage: %s -l <listen port>\n", argv[0]);
        exit(2);
    }

    while (2 < argc) {
        if (argv[1][0] != '-') {
            fprintf(stderr, "Usage: %s -l <listen port>\n", argv[0]);
            break;
        }
        if (strcmp(argv[1], "-l") == 0) {
            port = atoi(argv[2]);
            argc--;
        }
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[1]);
            return(-1);
        }
    }

    if((sockfd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) == -1){
        perror("socket ");
        return(-1);
    }

    memset(&msg, 0, sizeof(msg));
    memset(&sa, 0, sizeof(sa));
    memset(&wbuf.nlh, 0, sizeof(wbuf.nlh));
    memset(&wbuf.req, 0, sizeof(wbuf.req));

    sa.nl_family = AF_NETLINK;

    wbuf.req.sdiag_family = AF_INET;
    wbuf.req.sdiag_protocol = IPPROTO_TCP;
    wbuf.req.idiag_states = TCPF_ALL &
       ~((1<<TCP_SYN_RECV) | (1<<TCP_TIME_WAIT) | (1<<TCP_CLOSE) | (1<<TCP_CLOSE_WAIT) | (1<<TCP_ESTABLISHED));
    wbuf.req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));
    wbuf.req.id.idiag_sport = htons(port);
    wbuf.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(wbuf.req));
    wbuf.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    wbuf.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;

    iov[0].iov_base = (void*) &wbuf.nlh;
    iov[0].iov_len = sizeof(wbuf.nlh);
    iov[1].iov_base = (void*) &wbuf.req;
    iov[1].iov_len = sizeof(wbuf.req);

    msg.msg_name = (void*) &sa;
    msg.msg_namelen = sizeof(sa);
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;
    if((ret = sendmsg(sockfd, &msg, 0)) == -1){
      perror("sendmsg ");
      return(-1);
    }

    while(1){
    len = recv(sockfd, rbuf, sizeof(rbuf), 0);

      for(nlh=(struct nlmsghdr *)rbuf; NLMSG_OK(nlh, len); nlh=NLMSG_NEXT(nlh, len)){
        if(nlh->nlmsg_seq != wbuf.nlh.nlmsg_seq)
            continue;
        diag_msg = (struct inet_diag_msg *) NLMSG_DATA(nlh);
        rtalen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));

        if(nlh->nlmsg_type == NLMSG_ERROR){
          fprintf(stderr,"netlink msg error\n");
          return(-1);
        }
        if(nlh->nlmsg_type == NLMSG_DONE){
          return(0);
        }

        if(rtalen > 0){
          attr = (struct rtattr*) (diag_msg+1);
          while(RTA_OK(attr, rtalen)){
            if(attr->rta_type == INET_DIAG_INFO){
                info = (struct tcp_info*) RTA_DATA(attr);
                fprintf(stdout, "%s\t%u\t%d\n",
                        metric_name,
                        info->tcpi_unacked,
                        time(NULL));
            }
            attr = RTA_NEXT(attr, rtalen);
          }
        }
      }
    }
    return(0);
}

