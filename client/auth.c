
#define _POSIX_C_SOURCE 200809L

#include "auth.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <string.h>


#define DEVKEY_SALT "*E^o2Zse@!_rQp:kL%{4qL.~!v[n&HS)"
#define DEVKEY_ITER 16384
#define HMAC_KEY_LEN 32



static inline int fits_in_int(size_t value) {
    return value <= (size_t) INT_MAX;
}


static char *xstrdup(const char *value) {
    char *copy = strdup(value);
    if (copy == NULL) {
        perror("strdup");
        exit(EXIT_FAILURE);
    }
    return copy;
}


static char *base64_encode(const unsigned char *data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = malloc(out_len + 1);
    if (out == NULL) {
        return NULL;
    }
    if (!fits_in_int(len)) {
        free(out);
        return NULL;
    }
    if (EVP_EncodeBlock((unsigned char *) out, data, (int) len) < 0) {
        free(out);
        return NULL;
    }
    out[out_len] = '\0';
    return out;
}



static int derive_device_key(const char *secret, unsigned char *key, size_t key_len) {
    size_t secret_len = strlen(secret);
    size_t salt_len = strlen(DEVKEY_SALT);

    if (!fits_in_int(secret_len) || !fits_in_int(salt_len) || !fits_in_int(key_len)) {
        return -1;
    }
    if (PKCS5_PBKDF2_HMAC(secret,
                          (int) secret_len,
                          (const unsigned char *) DEVKEY_SALT,
                          (int) salt_len,
                          DEVKEY_ITER,
                          EVP_sha256(),
                          (int) key_len,
                          key) != 1) {
        return -1;
    }
    return 0;
}





int append_header(struct curl_slist **headers, const char *value) {
    struct curl_slist *next = curl_slist_append(*headers, value);
    if (next == NULL) {
        return -1;
    }
    *headers = next;
    return 0;
}



static int sha256_base64(const char *body, size_t len, char **digest_b64) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *ctx = NULL;
    int ret = -1;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, body, len) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, NULL) != 1) {
        goto cleanup;
    }

    *digest_b64 = base64_encode(digest, sizeof(digest));
    ret = *digest_b64 == NULL ? -1 : 0;

cleanup:
    EVP_MD_CTX_free(ctx);
    return ret;
}



int make_auth_header(const Config *cfg,
                            const unsigned char *key,
                            size_t key_len,
                            const char *body,
                            size_t body_len,
                            char **header_out) {
    unsigned char nonce[8];
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;
    char *nonce_b64 = NULL;
    char *body_hash_b64 = NULL;
    char *mac_b64 = NULL;
    char *payload = NULL;
    char *header = NULL;
    size_t payload_len;
    size_t header_len;
    int ret = -1;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, "Failed to generate nonce\n");
        return -1;
    }

    nonce_b64 = base64_encode(nonce, sizeof(nonce));
    if (nonce_b64 == NULL) {
        goto cleanup;
    }

    if (body_len > 0) {
        if (sha256_base64(body, body_len, &body_hash_b64) != 0) {
            goto cleanup;
        }
    } else {
        body_hash_b64 = xstrdup("");
    }

    payload_len = strlen(nonce_b64) + strlen(body_hash_b64);
    payload = malloc(payload_len + 1);
    if (payload == NULL) {
        goto cleanup;
    }
    strcpy(payload, nonce_b64);
    strcat(payload, body_hash_b64);

    if (!fits_in_int(key_len) ||
        HMAC(EVP_sha256(),
             key,
             (int) key_len,
             (const unsigned char *) payload,
             payload_len,
             mac,
             &mac_len) == NULL) {
        fprintf(stderr, "Failed to compute HMAC\n");
        goto cleanup;
    }

    mac_b64 = base64_encode(mac, mac_len);
    if (mac_b64 == NULL) {
        goto cleanup;
    }

    if (cfg->role != NULL && cfg->role[0] != '\0') {
        header_len = strlen("Authorization: Arctic-Hmac ") + strlen(cfg->userid) +
                     strlen(nonce_b64) + strlen(mac_b64) + strlen(cfg->role) + 5;
    } else {
        header_len = strlen("Authorization: Arctic-Hmac ") + strlen(cfg->userid) +
                     strlen(nonce_b64) + strlen(mac_b64) + 4;
    }

    header = malloc(header_len);
    if (header == NULL) {
        goto cleanup;
    }

    if (cfg->role != NULL && cfg->role[0] != '\0') {
        snprintf(header,
                 header_len,
                 "Authorization: Arctic-Hmac %s;%s;%s;%s",
                 cfg->userid,
                 nonce_b64,
                 mac_b64,
                 cfg->role);
    } else {
        snprintf(header,
                 header_len,
                 "Authorization: Arctic-Hmac %s;%s;%s",
                 cfg->userid,
                 nonce_b64,
                 mac_b64);
    }

    *header_out = header;
    header = NULL;
    ret = 0;

cleanup:
    free(nonce_b64);
    free(body_hash_b64);
    free(mac_b64);
    free(payload);
    free(header);
    return ret;
}




int obtain_auth_key(const Config *cfg, unsigned char **key, size_t *key_len) {
    if (cfg->shared_secret == NULL || cfg->shared_secret[0] == '\0') {
        fprintf(stderr, "Missing shared_secret in config\n");
        return -1;
    }

    *key = malloc(HMAC_KEY_LEN);
    if (*key == NULL) {
        return -1;
    }
    if (derive_device_key(cfg->shared_secret, *key, HMAC_KEY_LEN) != 0) {
        fprintf(stderr, "Failed to derive device key\n");
        free(*key);
        *key = NULL;
        return -1;
    }
    *key_len = HMAC_KEY_LEN;
    return 0;
}
