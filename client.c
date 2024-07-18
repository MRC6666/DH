#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "aes.h"
#include "DH.h"

#define MAX 1024

#define MAXN 50000

int vis[MAXN]; // 是否是 
int prime [MAXN]; // 素数序列 
int count = 0; // 素数
mpz_t ppri[MAXN];

void getprime();
int fenjie(mpz_t n);
void mpz_pow(mpz_t res, mpz_t x, mpz_t n, mpz_t mod);
void generate_g(mpz_t p,mpz_t g);

void exchange_dh_key(int sockfd, mpz_t s);
void trans_msg(int sockfd, unsigned char *key);
void psk(int sockfd);

int main(int argc, char **argv)
{
    if (3 != argc)
    {
        printf("USAGE: ./client ServerIP ServerPort\nExample: ./client 127.0.0.1 8888");
        return 0;
    }
    int sockfd, connfd;
    struct sockaddr_in serv_addr, cli;
    // create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        printf("Socket Failed!\n");
        exit(1);
    }
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(atoi(argv[2]));

    // connect to server
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("连接服务器失败!\n");
        exit(1);
    }
    else
        printf("成功连接服务器！!\n");
    /*
    // TODO: PSK Client
    // PSK
    printf("**************************************PSK**************************************\n");
    psk(sockfd);
    printf("*************************************PSK结束************************************\n\n\n");
*/
    printf("***************************************DH***************************************\n");
    mpz_t dh_s;
    mpz_init(dh_s);
    exchange_dh_key(sockfd, dh_s);

    // 声明AES加密解密及通信所需要的变量
    unsigned char key[33];
    mpz_get_str(key, 16, dh_s); // 将dh_s写入key
    gmp_printf("DH得出密钥为：%Zd\n\n", dh_s);
    // printf("对中间人的密钥：%s\n", key);
    mpz_clear(dh_s); // 清除dh_s
    printf("*************************************DH结束************************************\n\n\n");
    printf("**************************************AES**************************************\n");

    trans_msg(sockfd, key);

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

// 通过Diffie Hellman协议商讨出一个密钥s
void exchange_dh_key(int sockfd, mpz_t s)
{
    DH_key client_dh_key; // 客户端生成的密钥
    mpz_t server_pub_key; // 服务器公钥
    char buf[MAX];
    // 初始化mpz_t类型的变量
    mpz_inits(client_dh_key.p, client_dh_key.g, client_dh_key.pri_key,
              client_dh_key.pub_key, client_dh_key.s, server_pub_key, NULL);
    printf("将生成大素数p并发送(回车继续)...\n");
    getchar();
    generate_p(client_dh_key.p);
    // mpz_init_set_str(client_dh_key.p, "10780297253890107277869680735673710710762239076378863826711416227723695661275", 10);
    gmp_printf("p = %Zd\n\n", client_dh_key.p);
    // mpz_set_ui(client_dh_key.g, (unsigned long int)5); // base g
    generate_g(client_dh_key.p, client_dh_key.g);
    gmp_printf("g = %Zd\n\n", client_dh_key.g);
    // 将p发送给服务器
    bzero(buf, MAX);
    memcpy(buf, "pri", 3);
    mpz_get_str(buf + 3, 16, client_dh_key.p);
    // printf("buffer is :%s\n",buf);
    write(sockfd, buf, sizeof(buf));

    // 生成客户端的私钥a
    printf("即将生成客户端私钥与公钥（回车继续）...\n");
    getchar();
    generate_pri_key(client_dh_key.pri_key);
    //	mpz_init_set_str(client_dh_key.pri_key, "2131321313344212414",10); // a
    //	gmp_printf("\na = %Zd\n", client_dh_key.pri_key);
    gmp_printf("客户端的私钥为%Zd\n\n", client_dh_key.pri_key);

    // 计算客户端的公钥A
    mpz_powm(client_dh_key.pub_key, client_dh_key.g, client_dh_key.pri_key,
             client_dh_key.p);
    gmp_printf("客户端的公钥A为%Zd\n\n", client_dh_key.pub_key);
    
    // 接收服务器的公钥B
    bzero(buf, MAX);
    printf("等待接收服务器的公钥, 并发送客户端公钥...\n\n");
    read(sockfd, buf, sizeof(buf));
    	printf("server's pub key = %s\n",buf);
    mpz_set_str(server_pub_key, buf + 3, 16); // 按16进制将buf传递给server_pub_key
    gmp_printf("服务器的公钥B为%Zd\n\n", server_pub_key);

    // 将客户端公钥发送给服务器
    bzero(buf, MAX);
    memcpy(buf, "pub", 3);
    
    mpz_get_str(buf + 3, 16, client_dh_key.pub_key); // 按16进制将公钥传递给buf
    write(sockfd, buf, sizeof(buf));
	printf("client's pub key = %s\n",buf);
    // 客户端计算DH协议得到的密钥s
    printf("按下回车计算客户端经过DH协议得到的密钥...\n");
    getchar();
    mpz_powm(client_dh_key.s, server_pub_key, client_dh_key.pri_key,
             client_dh_key.p);
    mpz_set(s, client_dh_key.s); // 将密钥传递给s

    // 清除mpz_t变量
    mpz_clears(client_dh_key.p, client_dh_key.g, client_dh_key.pri_key,
               client_dh_key.pub_key, client_dh_key.s, server_pub_key, NULL);
}

// 客户端服务器发送接收加密后的消息
void trans_msg(int sockfd, unsigned char key[])
{
    psk(sockfd);
    unsigned char text[36];
    unsigned char expansion_key[15 * 16];
    memcpy(text, "msg", 3); // 标识消息头
    // 密钥扩展，生成轮密钥
    ScheduleKey(key, expansion_key, AES256_KEY_LENGTH, AES256_ROUND);
    printf("初始化轮密钥完成！\n\n");
    while (1)
    {
        // 输入要发送的明文
        bzero(text + 3, 33);
        printf("要发送的明文: ");
        scanf("%s", text + 3);
        // AES256加密
        AesEncrypt(text + 3, expansion_key, AES256_ROUND);
        // printf("\n jiami expansion_key is :%s\n", expansion_key);
        printf("密文为:\n");
        for (int i = 3; i < 35; ++i)
            printf("%02x ", text[i]);
        printf("\n");
        // 发送密文
        write(sockfd, text, sizeof(text));
        printf("发送成功！\n等待服务器回复...\n");
        
        // 接收服务器发送的密文
        bzero(text + 3, 33);
        read(sockfd, text, sizeof(text));
        printf("服务器端发送的密文：\n");
        for (int i = 3; i < 35; ++i)
            printf("%02x ", text[i]);
        printf("\n");
        // AES256解密
        Contrary_AesEncrypt(text + 3, expansion_key, AES256_ROUND);
        // printf("\njiemi expansion_key is :%s\n", expansion_key);
        printf("解密后的明文：");
        for (int i = 3; i < 35; ++i)
            printf("%c", text[i]);
        printf("\n\n\n");
    }
}

// 客户端psk
void psk(int sockfd)
{
    unsigned char text[36];                                           // 存放接收到的密文
    unsigned char key[32] = "0a12541bc5a2d6890f2536ffccab2e";         // 预共享密钥
    unsigned char expansion_key[15 * 16];                             // 扩展密钥
    ScheduleKey(key, expansion_key, AES256_KEY_LENGTH, AES256_ROUND); // 轮密钥
    bzero(text, 36);
    memcpy(text, "msg", 3);
    read(sockfd, text + 3, sizeof(text) - 3);
    printf("psk字符串为: %s\n\n", text + 3);
    // 对字符串加密并返回给服务器
    AesEncrypt(text + 3, expansion_key, AES256_ROUND);
    printf("加密后的密文：");
    for (int i = 3; i < 35; ++i)
        printf("%02x ", text[i]);
    printf("\n\n");
    printf("回车将加密后的字符串返回给服务器...\n");
    getchar();
    write(sockfd, text + 3, sizeof(text) - 3);
}

