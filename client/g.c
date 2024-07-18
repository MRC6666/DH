#include <stdio.h>
#include <gmp.h>
#include <string.h>

#define MAXN 50000

int vis[MAXN]; // 是否是 
int prime [MAXN]; // 素数序列 
int count = 0; // 素数
mpz_t ppri[MAXN];

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
int div(mpz_t n) {
    int cnt = 0, i;
    // 初始化 GMP 变量
    mpz_t x;
    mpz_init(x);
    mpz_set(x, n); // 复制 n 到 x

    for (i = 1; i <= MAXN; ++i) {
    	if (mpz_cmp_ui(x, prime[i] * prime[i]) < 0) break;
    	if (mpz_divisible_ui_p(x, prime[i])) {
    	    mpz_init(ppri[++cnt]);
    	    mpz_set_ui(ppri[cnt], prime[i]);
    	}
        while (mpz_divisible_ui_p(x, prime[i])) {
            mpz_divexact_ui(x, x, prime[i]);
        }
    }
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

int main() {
    mpz_t p, p_minus_1, a, t, res;
    int flag, cnt, i;
    mpz_inits(p, p_minus_1, a, t, res, NULL);

    //gmp_scanf("%Zd", p);
    mpz_init_set_str(p, "19260817", 10);
    getprime();
    /*
    for (i = 1; i <= count; ++i) 
    	printf("%d ", prime[i]);
    printf("\n");
    */
    mpz_sub_ui(p_minus_1, p, 1); // p-1
    cnt = div(p_minus_1); // p-1 的质因子个数
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
            //gmp_printf("g=%Zd\n", a);
            mpz_set_ui(client_dh_key.g, a)
            break;
        }
        mpz_add_ui(a, a, 1);
    }
    
    // 清理
    mpz_clears(p, p_minus_1, a, t, res, NULL);
    for (i = 0; i < MAXN; i++) {
        mpz_clear(ppri[i]);
    }
    return 0;
}


