#ifndef __NGX_SUB_SSL_H_INCLUDED__
#define __NGX_SUB_SSL_H_INCLUDED__

#include <ctype.h>
#include <math.h>
#include <string.h>

#include<ngx_config.h>
#include<ngx_core.h>
#include<ngx_http.h>

#include<openssl/rc4.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/engine.h>


#define ngx_strcat         strcat

#define ngx_rsa_t          RSA
#define ngx_bio_t          BIO

#define ngx_rsa_public_decrypt                RSA_public_decrypt
#define ngx_rsa_free                          RSA_free

#define ngx_bio_new_mem_buf                   BIO_new_mem_buf
#define ngx_pem_read_bio_rsa_pubkey           PEM_read_bio_RSA_PUBKEY
#define ngx_bio_free_buf                      BIO_free


#define ngx_htons(A)  ((((uint16_t)(A) & 0xff00) >> 8 ) | (((uint16_t)(A) & 0x00ff) << 8 ))

#define ngx_htonl(A)  ((((uint32_t)(A) & 0xff000000) >> 24)  | (((uint32_t)(A) & 0x00ff0000) >> 8 )   | \
                   (((uint32_t)(A) & 0x0000ff00) << 8 )  | (((uint32_t)(A) & 0x000000ff) << 24))


typedef struct {
    u_char                           key[40];
    u_char                           pub_key[240];
} ngx_http_sub_t;


ngx_int_t ngx_rc4_decrypt(u_char *decrypt_info, u_char *encrypt_info,
                                       ngx_int_t encrypt_len, u_char *rc4_key);

ngx_int_t ngx_hex_to_bin(u_char *dst, u_char *src);

void ngx_sub_validate(ngx_http_request_t *r, ngx_str_t *sub, u_char **data, ngx_http_sub_t *sub_key);

ngx_int_t ngx_check_cpu_endian();

ngx_int_t ngx_base62_encode (u_int64_t  val,    /* IN */
                         u_char    *str,    /* OUT */
                         size_t     len);   /* IN */

u_int64_t ngx_base62_decode (const char *str);  /* IN */

ngx_int_t ngx_md5_m(u_char *m, u_char *key);


#endif
