struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc init_sdesc(struct crypto_shash *alg)
{
    struct sdesc sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    sdesc->shash.flags = 0x0;
    return sdesc;
}

static int calc_hash(struct crypto_shashalg,
             const unsigned chardata, unsigned int datalen,
             unsigned chardigest) {
    struct sdesc sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("trusted_key: can't alloc %s\n", hash_alg);
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}