#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "hash.h"
#include "wots.h"
#include "hash_address.h"
#include "params.h"
#include "uintx.h"
#include "assert.h"
/**
 * Helper method for pseudorandom key generation.
 * Expands an n-byte array into a len*n byte array using the `prf_keygen` function.
 */
static void expand_seed(const xmss_params *params,
                        unsigned char *outseeds, const unsigned char *inseed, 
                        const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;
    unsigned char buf[params->n + 32];

    set_hash_addr(addr, 0);
    set_key_and_mask(addr, 0);
    memcpy(buf, pub_seed, params->n);
    for (i = 0; i < params->wots_len; i++) {
        set_chain_addr(addr, i);
        addr_to_bytes(buf + params->n, addr);
        prf_keygen(params, outseeds + i*params->n, buf, inseed);
    }
}

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */
static void gen_chain(const xmss_params *params,
                      unsigned char *out, const unsigned char *in,
                      unsigned int start, unsigned int steps,
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, params->n);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start+steps) && i < params->wots_w; i++) {
        set_hash_addr(addr, i);
        thash_f(params, out, out, pub_seed, addr);
    }
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
void encode(int *out, uint512_t *x, int l, int w)
{

    static int done = 0;
    static uint512_t dp[200][200*32 + 1];
    int s = l * (w - 1) / 2;

    if (!done)
    {
        set1_u512(&dp[0][0]);
        for (int i = 1; i <= l; i++)
            for (int j = 0; j <= s; j++)
            {
                set0_u512(&dp[i][j]);
                for (int k = 0; k < w && k <= j; k++)
                    add_u512(&dp[i][j], (const uint512_t *)&dp[i][j], (const uint512_t *)&dp[i - 1][j - k]);
            }

        done = 1;
    }


    for (int i = l - 1; i >= 0; i--)
    {
        int t = -1;
        for (int j = 0; j < w && j <= s; j++)
        {
            if (!less_u512((const uint512_t *)x, (const uint512_t *)&dp[i][s - j]))
            {
                sub_u512(x, (const uint512_t *)x, (const uint512_t *)&dp[i][s - j]);
            }
            else
            {
                t = j;
                break;
            }
        }
        assert(t!=-1);
        
        out[l - 1 - i] = t;
        s -= t;
    }
}


/* Takes a message and derives the matching chain lengths. */
static void chain_lengths(const xmss_params *params,
                          int *lengths, const unsigned char *msg)
{
    uint512_t m;

    set0_u512(&m);
    
    for (int i = 0; i < (int) params->n/8; i++)
    {
        m[i] = bytes_to_ull(msg+i*8,8);
    }

    encode(lengths, &m, params->wots_len, params->wots_w);
    
}

/**
 * WOTS key generation. Takes a 32 byte seed for the private key, expands it to
 * a full WOTS private key and computes the corresponding public key.
 * It requires the seed pub_seed (used to generate bitmasks and hash keys)
 * and the address of this WOTS key pair.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pkgen(const xmss_params *params,
                unsigned char *pk, const unsigned char *seed,
                const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;

    /* The WOTS+ private key is derived from the seed. */
    expand_seed(params, pk, seed, pub_seed, addr);

    for (i = 0; i < params->wots_len; i++) {
        set_chain_addr(addr, i);
        gen_chain(params, pk + i*params->n, pk + i*params->n,
                  0, params->wots_w - 1, pub_seed, addr);
    }
}

/**
 * Takes a n-byte message and the 32-byte seed for the private key to compute a
 * signature that is placed at 'sig'.
 */
void wots_sign(const xmss_params *params,
               unsigned char *sig, const unsigned char *msg,
               const unsigned char *seed, const unsigned char *pub_seed,
               uint32_t addr[8])
{
    int lengths[params->wots_len];
    uint32_t i;

    chain_lengths(params, lengths, msg);

    /* The WOTS+ private key is derived from the seed. */
    expand_seed(params, sig, seed, pub_seed, addr);

    for (i = 0; i < params->wots_len; i++) {
        set_chain_addr(addr, i);
        gen_chain(params, sig + i*params->n, sig + i*params->n,
                  0, lengths[i], pub_seed, addr);
    }
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig(const xmss_params *params, unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    int lengths[params->wots_len];
    uint32_t i;

    chain_lengths(params, lengths, msg);

    for (i = 0; i < params->wots_len; i++) {
        set_chain_addr(addr, i);
        gen_chain(params, pk + i*params->n, sig + i*params->n,
                  lengths[i], params->wots_w - 1 - lengths[i], pub_seed, addr);
    }
}
