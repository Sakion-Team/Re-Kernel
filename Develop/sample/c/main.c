#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/netlink.h>
#include <netinet/tcp.h>
#include <unistd.h>

#define PACKET_SIZE      256
#define NETLINK_UNIT     22
#define USER_PORT        100
#define MAX_PLOAD        125
#define MSG_LEN          125

int main(int argc, char **argv)
{
    int skfd;
    int ret;
    user_msg_info u_info;
    socklen_t len;
    struct nlmsghdr *nlh = NULL;
    struct sockaddr_nl saddr, daddr;
    char *umsg = "Hello! Re:Kernel!";

    skfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_UNIT);
    if (skfd == -1)
    {
        perror("Create connection error\n");
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.nl_family = AF_NETLINK;
    saddr.nl_pid = USER_PORT;
    saddr.nl_groups = 0;
    if (bind(skfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0)
    {
        perror("Failed bind to connection\n");
        close(skfd);
        return -1;
    }

    memset(&daddr, 0, sizeof(daddr));
    daddr.nl_family = AF_NETLINK;
    daddr.nl_pid = 0;
    daddr.nl_groups = 0;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PLOAD));
    memset(nlh, 0, sizeof(struct nlmsghdr));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PLOAD);
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = saddr.nl_pid;

    memcpy(NLMSG_DATA(nlh), umsg, strlen(umsg));
    printf("Send msg to kernel:%s\n", umsg);
    ret = sendto(skfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr_nl));
    if (!ret) {
        perror("Failed send msg to kernel!\n");
        close(skfd);
        return -1;
    }
  
    while (1) {
        memset(&u_info, 0, sizeof(u_info));
        len = sizeof(struct sockaddr_nl);
        ret = recvfrom(skfd, &u_info, sizeof(user_msg_info), 0, (struct sockaddr *)&daddr, &len);
        if (!ret) {
            perror("Failed recv msg from kernel!\n");
            close(skfd);
            return -1;
        }

        printf("Message from kernel:%s\n", u_info.msg);
    }
  
    close(skfd);
    free((void *)nlh);
    return 0;
}
