#include <crypto/internal/skcipher.h> 
#include <linux/crypto.h> 
#include <linux/module.h> 
#include <linux/random.h> 
#include <linux/scatterlist.h> 
#include "my-aes.h"

#define SYMMETRIC_KEY_LENGTH 32 
#define CIPHER_BLOCK_SIZE 16 
 
struct tcrypt_result { 
    struct completion completion; 
    int err; 
}; 
 
struct skcipher_def { 
    struct crypto_skcipher *tfm; 
    struct skcipher_request *req; 
    struct scatterlist sg; 
    struct tcrypt_result result; 
    char *scratchpad; 
    char *ciphertext; 
    char *ori_ivdata; 
    char *ivdata; 
};

static struct skcipher_def sk = 
{
	.tfm = NULL,
	.req = NULL,
	.scratchpad = NULL,
	.ciphertext = NULL,
	.ori_ivdata = NULL,
	.ivdata = NULL,
};

static void test_skcipher_finish(struct skcipher_def *sk) 
{ 
    if (sk->tfm) 
        crypto_free_skcipher(sk->tfm); 
    if (sk->req) 
        skcipher_request_free(sk->req); 
    if (sk->ivdata) 
        kfree(sk->ivdata); 
    if (sk->scratchpad) 
        kfree(sk->scratchpad); 
    if (sk->ciphertext) 
        kfree(sk->ciphertext); 
    if (sk->ori_ivdata) 
        kfree(sk->ori_ivdata); 
}

static int test_skcipher_result(struct skcipher_def *sk, int rc) 
{ 
    switch (rc) { 
    case 0:
        break; 

    case -EINPROGRESS || -EBUSY: 
        rc = wait_for_completion_interruptible(&sk->result.completion); 
        if (!rc && !sk->result.err) { 
            reinit_completion(&sk->result.completion); 
            break; 
        } 
        my_aes_info("skcipher encrypt returned with %d result %d\n", rc, 
                sk->result.err); 
        break; 

    default: 
        my_aes_info("skcipher encrypt returned with %d result %d\n", rc, 
                sk->result.err); 
        break; 
    } 
 
    init_completion(&sk->result.completion); 
 
    return rc; 
}

static void test_skcipher_callback(struct crypto_async_request *req, int error) 
{ 
    struct tcrypt_result *result = req->data; 
 
    if (error == -EINPROGRESS) 
        return; 
 
    result->err = error; 
    complete(&result->completion); 
    my_aes_info("%s: Encryption finished successfully\n", __func__); 
}

static int test_skcipher(char *text, char *password, 
                                 struct skcipher_def *sk, int enc) 
{
	int ret = -EFAULT; 
	unsigned char key[SYMMETRIC_KEY_LENGTH]; 
 
	if (enc) 
		my_aes_info("Encrypt:\n");
	else
		my_aes_info("Decrypt:\n");

    if (!sk->tfm) { 
        sk->tfm = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0); 
        if (IS_ERR(sk->tfm)) { 
            my_aes_err("could not allocate skcipher handle\n"); 
            return PTR_ERR(sk->tfm); 
        } 
    } 
 
    if (!sk->req) { 
        sk->req = skcipher_request_alloc(sk->tfm, GFP_KERNEL); 
        if (!sk->req) { 
            my_aes_err("could not allocate skcipher request\n"); 
            ret = -ENOMEM; 
            goto out; 
        } 
    } 
 
    skcipher_request_set_callback(sk->req, CRYPTO_TFM_REQ_MAY_BACKLOG, 
                                  test_skcipher_callback, &sk->result); 
 
    /* clear the key */ 
    memset((void *)key, '\0', SYMMETRIC_KEY_LENGTH); 
 
    /* Use the world's favourite password */ 
    sprintf((char *)key, "%s", password); 
 
    /* AES 256 with given symmetric key */ 
    if (crypto_skcipher_setkey(sk->tfm, key, SYMMETRIC_KEY_LENGTH)) { 
        my_aes_info("key could not be set\n"); 
        ret = -EAGAIN; 
        goto out; 
    }

    my_aes_info("Symmetric key: %s\n", key); 
 
    if (!sk->ivdata) { 
        /* see https://en.wikipedia.org/wiki/Initialization_vector */ 
        sk->ivdata = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL); 
        if (!sk->ivdata) { 
            my_aes_err("could not allocate ivdata\n"); 
            goto out; 
        } 
        get_random_bytes(sk->ivdata, CIPHER_BLOCK_SIZE); 
    } 

	if (enc) {
		if (!sk->ori_ivdata) { 
			sk->ori_ivdata = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL); 
			if (!sk->ori_ivdata) { 
				my_aes_err("could not allocate ori_ivdata\n"); 
				goto out; 
			} 

			memcpy(sk->ori_ivdata, sk->ivdata, CIPHER_BLOCK_SIZE);
			my_aes_info("Before encrypt IV: %s\n", sk->ori_ivdata); 
		} 
	} else {
		if (!sk->ori_ivdata) {
				my_aes_err("no  ori_ivdata\n"); 
				goto out;
		} else {
			memcpy(sk->ivdata, sk->ori_ivdata, CIPHER_BLOCK_SIZE);
			my_aes_info("Before decrypt IV: %s\n", sk->ivdata); 
		}
	}
 
    if (!sk->scratchpad) { 
        /* The text to be encrypted */ 
        sk->scratchpad = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL); 
        if (!sk->scratchpad) { 
            my_aes_err("could not allocate scratchpad\n"); 
            goto out; 
        } 
    } 
	
	if (enc) {
		my_aes_info("Before encrypt: %s\n", text); 
		sprintf((char *)sk->scratchpad, "%s", text); 
	} else {
		my_aes_info("Before decrypt: %s\n", text); 
		sprintf((char *)sk->scratchpad, "%s", text); 
	}
 
    sg_init_one(&sk->sg, sk->scratchpad, CIPHER_BLOCK_SIZE); 
    skcipher_request_set_crypt(sk->req, &sk->sg, &sk->sg, CIPHER_BLOCK_SIZE, 
                               sk->ivdata); 
    init_completion(&sk->result.completion); 
 
	if (enc) {
		/* encrypt data */ 
		ret = crypto_skcipher_encrypt(sk->req); 
		ret = test_skcipher_result(sk, ret); 
		if (ret) 
			goto out; 

		my_aes_info("Encryption request successful\n"); 
		
		/* Keep ciphertext */
		if (!sk->ciphertext) { 
			/* The text after encrypted */ 
			sk->ciphertext = kmalloc(CIPHER_BLOCK_SIZE, GFP_KERNEL); 
			if (!sk->ciphertext) { 
				my_aes_err("could not allocate ciphertext\n"); 
				goto out; 
			} 
		}

		memcpy(sk->ciphertext, sk->scratchpad, CIPHER_BLOCK_SIZE);
		my_aes_info("After encrypt: %s\n", sk->ciphertext); 
	} else {
		/* decrypt data */ 
		ret = crypto_skcipher_decrypt(sk->req); 
		ret = test_skcipher_result(sk, ret); 
		if (ret) 
			goto out; 

		my_aes_info("Decryption request successful\n"); 
		/* Print result */
		my_aes_info("After decrypt: %s\n", sk->scratchpad); 
	}
 
out: 
    return ret;
}

static int cryptoapi_init(void) 
{ 
	char *plaintext = "Testing";

    /* The world's favorite password */ 
    char *password = "password123"; 
 
    test_skcipher(plaintext, password, &sk, 1); 
    test_skcipher(sk.ciphertext, password, &sk, 0); 
    return 0; 
} 
 
static void cryptoapi_exit(void) 
{ 
    my_aes_info("cryptoapi_exit\n"); 
    test_skcipher_finish(&sk); 
} 
 
module_init(cryptoapi_init); 
module_exit(cryptoapi_exit); 
 
MODULE_DESCRIPTION("Symmetric key encryption example"); 
MODULE_LICENSE("GPL");
