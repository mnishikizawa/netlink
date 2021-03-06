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

#define TCPF_ALL 0xFFF

int main() {
    int sockfd, len;
    struct msghdr msg;
    struct { 
        struct nlmsghdr nlh;
        struct inet_diag_req_v2 req;
    } wbuf;
    struct nlmsghdr *nlh;
    struct sockaddr_nl sa;
    struct iovec iov[2];
    int ret = 0;

    struct rtattr rta;
    void *filter_mem = NULL;
    int filter_len = 0;

    static char rbuf[65535];
	struct rtattr *attr;
	struct tcp_info *info;
    struct inet_diag_msg *diag_msg;
	int rtalen;

    if((sockfd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_INET_DIAG)) == -1){
		perror("socket: ");
		return(-1);
	}

    memset(&msg, 0, sizeof(msg));
    memset(&sa, 0, sizeof(sa));
    memset(&wbuf.nlh, 0, sizeof(wbuf.nlh));
    memset(&wbuf.req, 0, sizeof(wbuf.req)); //これがないとrtalenが-になるな

    sa.nl_family = AF_NETLINK;

    wbuf.req.sdiag_family = AF_INET;
    wbuf.req.sdiag_protocol = IPPROTO_TCP;
    wbuf.req.idiag_states = TCPF_ALL & 
        ~((1<<TCP_SYN_RECV) | (1<<TCP_TIME_WAIT) | (1<<TCP_CLOSE));
    wbuf.req.idiag_ext |= (1 << (INET_DIAG_INFO - 1));
    
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
		perror("sendmsg:");
		return(-1);
	}

	while(1){
		len = recv(sockfd, rbuf, sizeof(rbuf), 0);	
		nlh = (struct nlmsghdr*)rbuf;
    
		while(NLMSG_OK(nlh, len)){
			if(nlh->nlmsg_type == NLMSG_DONE)
				return(0);

			if(nlh->nlmsg_type == NLMSG_ERROR){
				fprintf(stderr, "Error in netlink message\n");
 				return(-1);
			}
			diag_msg = (struct inet_diag_msg *) NLMSG_DATA(nlh);
			rtalen = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));
		  
			if(rtalen > 0){
				attr = (struct rtattr*) (diag_msg+1);
				while(RTA_OK(attr, rtalen)){
					if(attr->rta_type == INET_DIAG_INFO){	
						info = (struct tcp_info*) RTA_DATA(attr);
						fprintf(stdout, "State: %u RTT: %gms Recv.RTT: %gms cwnd: %u\n", 
								info->tcpi_state, 
								(double) info->tcpi_rtt/1000, 
								(double) info->tcpi_rcv_rtt/1000, 
								info->tcpi_snd_cwnd);
					}
					attr = RTA_NEXT(attr, rtalen);
				}
            }
			nlh = NLMSG_NEXT(nlh, len);
		}
	} 
	return(0);
}
