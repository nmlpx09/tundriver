// SPDX-License-Identifier: GPL-2.0
/*
 * tnet - encrypt/decrypt (ChaCha20-Poly1305 AEAD)
 *
 * Wire format per packet:
 *   [nonce(12)][ciphertext(N)][tag(16)]
 *
 * The 96-bit nonce is built as: 4-byte prefix (direction bit + random salt)
 * followed by an 8-byte big-endian atomic counter. The direction bit
 * (server = 1, client = 0) keeps the two peers' nonce spaces disjoint even
 * though they share the same key, preventing nonce reuse across directions.
 *
 * Copyright (c) 2026 nlmpx09 <nmlpx09@duck.com>
 */

#include <crypto/aead.h>
#include <linux/base64.h>
#include <linux/compiler.h>
#include <linux/crypto.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/printk.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>

#include "impl.h"

#define KEY_SIZE       CRYPT_KEY_SIZE
#define NONCE_SIZE     CRYPT_NONCE_SIZE
#define TAG_SIZE       CRYPT_TAG_SIZE
#define KEY_B64_LEN    BASE64_CHARS(KEY_SIZE)  /* unpadded; +1 for '=' */
#define NONCE_PREFIX_L (NONCE_SIZE - sizeof(u64))  /* 4 bytes */

static struct crypto_aead* aead;
static atomic64_t nonce_ctr;
static u8 nonce_prefix[NONCE_PREFIX_L];

int crypt_init(const char* key_b64)
{
    u8 key[KEY_SIZE + 4];
    int klen, decoded, err;

    err = -EINVAL;
    if (!key_b64) {
        pr_err("tnet: key is required (base64)\n");
        goto out;
    }

    klen = strlen(key_b64);
    if (klen < KEY_B64_LEN || klen > KEY_B64_LEN + 1) {
        pr_err("tnet: key must be %d (or %d padded) base64 chars\n",
               KEY_B64_LEN, KEY_B64_LEN + 1);
        goto out;
    }

    decoded = base64_decode(key_b64, klen, key);
    if (decoded != KEY_SIZE) {
        pr_err("tnet: invalid base64 key\n");
        goto out;
    }

    request_module("chacha20poly1305");

    aead = crypto_alloc_aead("chacha20-poly1305", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(aead)) {
        err = PTR_ERR(aead);
        pr_err("tnet: alloc chacha20-poly1305 failed: %d (enable CONFIG_CRYPTO_CHACHA20POLY1305)\n", err);
        aead = NULL;
        goto out;
    }

    err = crypto_aead_setauthsize(aead, TAG_SIZE);
    if (err) {
        pr_err("tnet: setauthsize failed: %d\n", err);
        crypto_free_aead(aead);
        aead = NULL;
        goto out;
    }

    err = crypto_aead_setkey(aead, key, KEY_SIZE);
    if (err) {
        pr_err("tnet: setkey failed: %d\n", err);
        crypto_free_aead(aead);
        aead = NULL;
        goto out;
    }

    get_random_bytes(nonce_prefix, sizeof(nonce_prefix));
#ifdef SERVER
    nonce_prefix[0] |= 0x80;
#else
    nonce_prefix[0] &= 0x7F;
#endif

    atomic64_set(&nonce_ctr, 0);

out:
    memzero_explicit(key, sizeof(key));
    return err;
}

void crypt_exit(void)
{
    if (aead) {
        crypto_free_aead(aead);
        aead = NULL;
    }
}

static void build_nonce(u8* out)
{
    __be64 be = cpu_to_be64(atomic64_inc_return(&nonce_ctr));

    memcpy(out, nonce_prefix, sizeof(nonce_prefix));
    memcpy(out + sizeof(nonce_prefix), &be, sizeof(be));
}

int encrypt(struct sk_buff* skb)
{
    struct scatterlist sg;
    struct aead_request* req;
    size_t plain_len, reqsz;
    int err;

    if (unlikely(!aead || !skb)) {
        return -EINVAL;
    }

    if (unlikely(skb_linearize(skb))) {
        return -ENOMEM;
    }

    plain_len = skb->len;

    err = pskb_expand_head(skb, NONCE_SIZE, TAG_SIZE, GFP_ATOMIC);
    if (unlikely(err)) {
        return err;
    }

    build_nonce(skb_push(skb, NONCE_SIZE));
    skb_put(skb, TAG_SIZE);

    reqsz = sizeof(*req) + crypto_aead_reqsize(aead);
    req = kzalloc(reqsz, GFP_ATOMIC);
    if (unlikely(!req)) {
        return -ENOMEM;
    }

    aead_request_set_tfm(req, aead);
    sg_init_one(&sg, skb->data + NONCE_SIZE, plain_len + TAG_SIZE);
    aead_request_set_crypt(req, &sg, &sg, plain_len, skb->data);
    aead_request_set_ad(req, 0);

    err = crypto_aead_encrypt(req);

    kfree(req);
    return err;
}

int decrypt(struct sk_buff* skb)
{
    struct scatterlist sg;
    struct aead_request* req;
    size_t total, ct_len, reqsz;
    int err;

    if (unlikely(!aead || !skb)) {
        return -EINVAL;
    }

    if (unlikely(skb_linearize(skb))) {
        return -ENOMEM;
    }

    total = skb->len;
    if (unlikely(total < NONCE_SIZE + TAG_SIZE)) {
        return -EINVAL;
    }

    ct_len = total - NONCE_SIZE - TAG_SIZE;

    reqsz = sizeof(*req) + crypto_aead_reqsize(aead);
    req = kzalloc(reqsz, GFP_ATOMIC);
    if (unlikely(!req)) {
        return -ENOMEM;
    }

    aead_request_set_tfm(req, aead);
    sg_init_one(&sg, skb->data + NONCE_SIZE, ct_len + TAG_SIZE);
    aead_request_set_crypt(req, &sg, &sg, ct_len + TAG_SIZE, skb->data);
    aead_request_set_ad(req, 0);

    err = crypto_aead_decrypt(req);

    kfree(req);

    if (unlikely(err)) {
        return err;
    }

    skb_pull(skb, NONCE_SIZE);
    skb_trim(skb, ct_len);

    return 0;
}
