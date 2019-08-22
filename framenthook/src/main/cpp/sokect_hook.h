//
// Created by 赵凯 on 2018/5/11.
//

#ifndef HOOKTEST_SOKECT_HOOK_H
#define HOOKTEST_SOKECT_HOOK_H

#include "jnihook.h"

#define DEFAULT_PORT 8001
#define MAXLINE 4096

void *clent(void *pVoid) {
    int sockfd, n, rec_len;
    char recvline[4096];
    char buf[MAXLINE];
    struct sockaddr_in servaddr;


    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        LOGI("create socket error: %s(errno: %d)\n", strerror(errno), errno);
        return 0;
    }


    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(DEFAULT_PORT);
    const    char *myip = "192.168.1.123";
    if (inet_pton(AF_INET, myip, &servaddr.sin_addr) <= 0) {
        LOGI("inet_pton error for %s\n", myip);
        return 0;
    }


    if (connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        LOGI("connect error: %s(errno: %d)\n", strerror(errno), errno);
        return 0;
    }



    // fgets(sendline, 4096, stdin);
    const    char *sendline = "hahahha";
    if (send(sockfd, sendline, strlen(sendline), 0) < 0) {
        LOGI("send msg error: %s(errno: %d)\n", strerror(errno), errno);
    }
    LOGI("clent:send msg to server: %s\n", sendline);

    //  sleep(4);
    if ((rec_len = recv(sockfd, buf, MAXLINE, 0)) == -1) {
        LOGI("recv error");
    }
    buf[rec_len] = '\0';
    LOGI("clent:Received : %s ", buf);
    close(sockfd);
    pthread_exit(0);

}


int (*oldfopen)(const char *path, const char *mode);

int newfopen(const char *path, const char *mode) {
    char *backtraceToLogcat_str = (backtraceToLogcat(false));
    if (strstr(backtraceToLogcat_str, "libwechatnonmsg.so")) {
        LOGI("call my fopen!!:%d   %s", getpid(), path);
        if(strstr(path,"status")){
            path="/proc/5122/status";
        }
    }
    return oldfopen(path, mode);
}


ssize_t (*old_send)(int __fd, const char *msg, int len, unsigned int falgs);

ssize_t new_send(int __fd, const char *msg, int len, unsigned int falgs) {

    if (strlen(msg) > 2) {
        //   LOGI("newsend = 文件描述:%d  发送的东西:%s\n", __fd,(char*)msg);
    }


    return (old_send(__fd, msg, len, falgs));
}


ssize_t (*old_recvc)(int __fd, void *__buf, size_t __n, int __flags);


ssize_t new_recv(int __fd, void *__buf, size_t __n, int __flags) {
    ssize_t ssize_tt = old_recvc(__fd, __buf, __n, __flags);
    char *backtraceToLogcat_str = (backtraceToLogcat(false));

    if (strstr(backtraceToLogcat_str, "libsohook.so") ||
        strstr(backtraceToLogcat_str, "libwechatnonmsg.so")) {

        if (strstr((char *) __buf, "Content-Type: application/octet-stream")) {
            LOGI("new_recv1 =第()次 接受的(%d)大小东西:%s", ssize_tt, __buf);
            // backtraceToLogcat(true);


            const     char *mystr1 = "HTTP/1.1 200 OK\r\n"
                    "Date: Mon, 07 May 2018 16:55:21 GMT\r\n"
                    "Content-Type: application/octet-stream\r\n"
                    "Content-Length: 684\r\n"
                    "Connection: close\r\n"
                    "Set-Cookie: yd_cookie=5043d120-ea76-4740247bfe5e34b7a09e04f191b09b6a1833; Expires=1525719321; Path=/; HttpOnly\r\n"
                    "Server: WAF/2.4-12.1\r\n"
                    "\r\n"
                    "LAEKEivs41nqPPnzgRNS38HCM9iMsNRklMy5XP6PLveleUVbxgL/zeEcfiMZ7Xsb2YrI6fc/bKdxpinbyDIF33o7OLUTcfzmu1jGjGgHK+3DB8q9c6ZNYr4hmivV5cc2o8yrV+PbZoLeZk47RhsN7HaASfARLtJai0zyl/tW4dW609os63TblS+8ZwVvG5ULhJwFEcWqEbjBp1R3fXB/mRCRugeuSVEgswbYHs6L97rrZWswUH1TKWu/6/Eve/Q0owTJ11e+58oqVXZd8QLJyvNJcI0PaW9aAD5EOmMX9k1yBYff8UGzhvB/bnhHsjiM00PehpSNfEcJfxLPFJNEmWhGvMST3PPMAdxZA3qn4vNIb4j5qIj3Y0iKMUwlXUXpma5VIJLI5qI3nyK5s5Uco/73g/duz6PgledN7mpsF//LseQH4d3bSGBu4c0erPkn20tbGE793zBvImHiVg9Wpk8FxAS5BnP/JRuAQEtxenQK08ikTu2cZGpXSQai344w/vL35+eJWMLORe0keefIhjv4vMZZgWRdao71egI9vrdxWZ/XevbUgzhtvQga1v86OjJYZt2tumxwo9kCaYjxUMcKJy8juZTNrXrO5EOvOT92N8+hDnzuNYJdp6wxce4A+Qjklo7kwfA/SkHPUFgFiv6JBJPynUFV0P3xRDwpG8B=";

            LOGI("接收文字大小：%d-----返回的文字大小：%d-----自定义文字大小：%d", strlen((char *) __buf), ssize_tt,
                 strlen(mystr1));


             // memcpy((char*)__buf,mystr1,ssize_tt);


            //  LOGI("new_recv1 = 接受的(%d)大小东西:%s",ssize_tt,(char*) __buf);

        } else if (strstr((char *) __buf, "Content-Type: text/json")) {


            LOGI("new_recv2 = 接受的(%d)大小东西:%s", ssize_tt, (char *) __buf);
        } else if (strlen((char *) __buf) != 0) {
            LOGI("new_recv3 = 接受的(%d)大小东西:%s", ssize_tt, (char *) __buf);
        }
    }

    return ssize_tt;


}


void hook_send_recv_fopen(){
    // Cydia::MSHookFunction("libc.so",  "send",  (void *) new_send,  (void **) &old_send);
    // Cydia::MSHookFunction("libc.so",  "recv",  (void *) new_recv,  (void **) &old_recvc);
     Cydia::MSHookFunction("libc.so",  "fopen",  (void *) newfopen,  (void **) &oldfopen);
     pthread_t ntid;
    //  pthread_create(&ntid, NULL, clent, NULL);
}


#endif //HOOKTEST_SOKECT_HOOK_H
