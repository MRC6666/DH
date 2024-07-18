#include <stdio.h>
#include <string.h>
#include <gmp.h>

#define PSK_LEN 20 // psk随机生成字符串的长度

typedef struct
{
	mpz_t p;
	mpz_t g;
	mpz_t pri_key;
	mpz_t pub_key;
	mpz_t s; //g^(AB)
} DH_key;

void get_random_int(mpz_t z, mp_bitcnt_t n); // 随机生成一个规定范围内的整数
void get_random_str(unsigned char *ch);
void generate_pri_key(mpz_t a);				 // 生成密钥a

