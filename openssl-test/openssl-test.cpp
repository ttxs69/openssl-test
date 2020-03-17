// openssl-test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <stdio.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/bio.h>

int main()
{
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();

    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Load config file, and other important initialisation */
    OPENSSL_config(NULL);

    /* ... Do some crypto stuff here ... */
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    char mess[] = "Test Message\n";
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;


    md = EVP_get_digestbyname("md5");

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, mess, strlen(mess));

    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    //EVP_MD_CTX_free(mdctx);

    printf("Digest is: ");
    for (i = 0; i < md_len; i++)
        printf("%02x", md_value[i]);
    printf("\n");


    /*Generate 2048 bit RSA key */
    EVP_PKEY_CTX* pctx;
    EVP_PKEY* pkey = NULL;
    ENGINE *e = ENGINE_by_id("ACME");
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, e);
    if (!pctx)
        /* Error occurred */
        exit(-1);
    if (EVP_PKEY_keygen_init(pctx) <= 0)
        /* Error */
        exit(-1);
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0)
        /* Error */
        exit(-1);
        /* Generate key */
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
        /* Error */
        exit(-1);

    /* Sign */
    unsigned char sigret[1000];
    size_t sig_len;
    EVP_MD_CTX_set_pkey_ctx(mdctx, pctx);
    EVP_DigestSignInit(mdctx, &pctx, md, e, pkey);
    EVP_DigestSignUpdate(mdctx, md_value, md_len);
    EVP_DigestSignFinal(mdctx,sigret,&sig_len);

    /* BASE64 */
    BIO* bio, * b64;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_push(b64, bio);
    BIO_write(b64, sigret, sig_len);
    BIO_flush(b64);

    BIO_free_all(b64);
    /* Clean up */
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_CTX_free(pctx);
    /* Removes all digests and ciphers */
    EVP_cleanup();

    /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
    CRYPTO_cleanup_all_ex_data();

    /* Remove error strings */
    ERR_free_strings();
    return 0;
}