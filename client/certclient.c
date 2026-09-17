#define _POSIX_C_SOURCE 200809L

#include "config.h"

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#define DEVKEY_SALT "*E^o2Zse@!_rQp:kL%{4qL.~!v[n&HS)"
#define DEVKEY_ITER 16384
#define HMAC_KEY_LEN 32

typedef struct {
    char *data;
    size_t len;
} Buffer;

static void buffer_free(Buffer *buf) {
    free(buf->data);
    buf->data = NULL;
    buf->len = 0;
}

static char *xstrdup(const char *value) {
    char *copy = strdup(value);
    if (copy == NULL) {
        perror("strdup");
        exit(EXIT_FAILURE);
    }
    return copy;
}

static int fits_in_int(size_t value) {
    return value <= (size_t) INT_MAX;
}

static int read_file(const char *path, Buffer *buf) {
    FILE *fp;
    long length;
    size_t read_len;

    memset(buf, 0, sizeof(*buf));
    fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    length = ftell(fp);
    if (length < 0) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    buf->data = malloc((size_t) length + 1);
    if (buf->data == NULL) {
        fclose(fp);
        return -1;
    }

    read_len = fread(buf->data, 1, (size_t) length, fp);
    fclose(fp);
    if (read_len != (size_t) length) {
        buffer_free(buf);
        return -1;
    }

    buf->data[read_len] = '\0';
    buf->len = read_len;
    return 0;
}

static int write_file(const char *path, const char *data, size_t len) {
    size_t path_len = strlen(path);
    const char suffix[] = ".tmpXXXXXX";
    char *tmp_path = malloc(path_len + sizeof(suffix));
    int fd;
    FILE *fp;

    if (tmp_path == NULL) {
        return -1;
    }
    memcpy(tmp_path, path, path_len);
    memcpy(tmp_path + path_len, suffix, sizeof(suffix));

    fd = mkstemp(tmp_path);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s for writing: %s\n", path, strerror(errno));
        free(tmp_path);
        return -1;
    }
    fp = fdopen(fd, "wb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s for writing: %s\n", path, strerror(errno));
        close(fd);
        unlink(tmp_path);
        free(tmp_path);
        return -1;
    }
    if (fwrite(data, 1, len, fp) != len) {
        fprintf(stderr, "Failed to write %s\n", path);
        fclose(fp);
        unlink(tmp_path);
        free(tmp_path);
        return -1;
    }
    if (fclose(fp) != 0) {
        fprintf(stderr, "Failed to close %s\n", path);
        unlink(tmp_path);
        free(tmp_path);
        return -1;
    }
    if (rename(tmp_path, path) != 0) {
        fprintf(stderr, "Failed to move %s into place: %s\n", path, strerror(errno));
        unlink(tmp_path);
        free(tmp_path);
        return -1;
    }
    free(tmp_path);
    return 0;
}

static int validate_csr_pem(const char *pem, size_t len) {
    BIO *bio;
    X509_REQ *req = NULL;
    int ok = -1;

    if (!fits_in_int(len)) {
        fprintf(stderr, "CSR input is too large\n");
        return -1;
    }
    bio = BIO_new_mem_buf(pem, (int) len);
    if (bio == NULL) {
        return -1;
    }
    req = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    if (req != NULL) {
        ok = 0;
    } else {
        fprintf(stderr, "CSR input is not valid PEM encoded CSR data\n");
    }
    X509_REQ_free(req);
    BIO_free(bio);
    return ok;
}

static int validate_cert_pem(const char *pem, size_t len) {
    BIO *bio;
    X509 *cert = NULL;
    int ok = -1;

    if (!fits_in_int(len)) {
        fprintf(stderr, "Certificate response is too large\n");
        return -1;
    }
    bio = BIO_new_mem_buf(pem, (int) len);
    if (bio == NULL) {
        return -1;
    }
    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (cert != NULL) {
        ok = 0;
    } else {
        fprintf(stderr, "Server response is not a valid PEM encoded certificate\n");
    }
    X509_free(cert);
    BIO_free(bio);
    return ok;
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

static char *join_url(const char *base, const char *path) {
    size_t base_len = strlen(base);
    size_t path_len = strlen(path);
    bool base_has_slash = base_len > 0 && base[base_len - 1] == '/';
    bool path_has_slash = path_len > 0 && path[0] == '/';
    size_t total = base_len + path_len + 2;
    char *url = malloc(total);

    if (url == NULL) {
        return NULL;
    }

    strcpy(url, base);
    if (base_has_slash && path_has_slash) {
        strcat(url, path + 1);
    } else if (!base_has_slash && !path_has_slash) {
        strcat(url, "/");
        strcat(url, path);
    } else {
        strcat(url, path);
    }
    return url;
}

static char *append_days_query(const char *url, long days) {
    CURLU *curlu = curl_url();
    char query[64];
    char *result = NULL;

    if (curlu == NULL) {
        return NULL;
    }
    if (curl_url_set(curlu, CURLUPART_URL, url, 0) != CURLUE_OK) {
        goto cleanup;
    }
    if (snprintf(query, sizeof(query), "days=%ld", days) < 0) {
        goto cleanup;
    }
    if (curl_url_set(curlu, CURLUPART_QUERY, query, CURLU_APPENDQUERY) != CURLUE_OK) {
        goto cleanup;
    }
    if (curl_url_get(curlu, CURLUPART_URL, &result, 0) != CURLUE_OK) {
        result = NULL;
    }

cleanup:
    curl_url_cleanup(curlu);
    return result;
}

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    Buffer *buf = userdata;
    size_t chunk;
    size_t new_len;
    char *new_data;

    if (size != 0 && nmemb > SIZE_MAX / size) {
        return 0;
    }
    chunk = size * nmemb;
    if (chunk > SIZE_MAX - buf->len - 1) {
        return 0;
    }
    new_len = buf->len + chunk;
    new_data = realloc(buf->data, new_len + 1);
    if (new_data == NULL) {
        return 0;
    }

    buf->data = new_data;
    memcpy(buf->data + buf->len, ptr, chunk);
    buf->len = new_len;
    buf->data[buf->len] = '\0';
    return chunk;
}

static int apply_tls_options(CURL *curl, const Config *cfg) {
    if (cfg->ca_file != NULL && cfg->ca_file[0] != '\0') {
        curl_easy_setopt(curl, CURLOPT_CAINFO, cfg->ca_file);
    }
    if (cfg->insecure_tls) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    return 0;
}

static int append_header(struct curl_slist **headers, const char *value) {
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

static int make_auth_header(const Config *cfg,
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

static int obtain_auth_key(const Config *cfg, unsigned char **key, size_t *key_len) {
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

static int request_certificate(const Config *cfg,
                               const char *csr_body,
                               size_t csr_len,
                               const unsigned char *key,
                               size_t key_len,
                               Buffer *response) {
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    char *sign_url = NULL;
    char *auth_header = NULL;
    char *url_with_query = NULL;
    long status = 0;
    CURLcode rc;
    int ret = -1;

    curl = curl_easy_init();
    if (curl == NULL) {
        return -1;
    }

    sign_url = join_url(cfg->service_url, cfg->sign_path);
    if (sign_url == NULL) {
        goto cleanup;
    }

    if (cfg->days > 0) {
        url_with_query = append_days_query(sign_url, cfg->days);
        if (url_with_query == NULL) {
            goto cleanup;
        }
    }

    if (make_auth_header(cfg, key, key_len, csr_body, csr_len, &auth_header) != 0) {
        goto cleanup;
    }

    if (append_header(&headers, auth_header) != 0 ||
        append_header(&headers, "Content-Type: application/x-pem-file") != 0 ||
        append_header(&headers, "Accept: application/x-pem-file") != 0) {
        goto cleanup;
    }

    memset(response, 0, sizeof(*response));
    curl_easy_setopt(curl, CURLOPT_URL, url_with_query ? url_with_query : sign_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, csr_body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t) csr_len);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    apply_tls_options(curl, cfg);

    rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        fprintf(stderr, "Certificate request failed: %s\n", curl_easy_strerror(rc));
        goto cleanup;
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (status != 200) {
        fprintf(stderr, "Certificate request failed with HTTP %ld\n", status);
        if (response->data != NULL && response->len > 0) {
            fprintf(stderr, "%s\n", response->data);
        }
        goto cleanup;
    }

    ret = 0;

cleanup:
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(sign_url);
    free(auth_header);
    curl_free(url_with_query);
    return ret;
}

int main(int argc, char **argv) {
    Config cfg;
    const char *config_path = "certclient.ini";
    Buffer csr = {0};
    Buffer cert = {0};
    unsigned char *key = NULL;
    size_t key_len = 0;
    int ret = EXIT_FAILURE;

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [config-file]\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (argc == 2) {
        config_path = argv[1];
    }

    if (config_init(&cfg) != 0 ||
        parse_config_file(config_path, &cfg) != 0 ||
        validate_config(&cfg) != 0) {
        goto cleanup;
    }

    if (read_file(cfg.csr_file, &csr) != 0) {
        fprintf(stderr, "Failed to read CSR file %s\n", cfg.csr_file);
        goto cleanup;
    }
    if (validate_csr_pem(csr.data, csr.len) != 0) {
        goto cleanup;
    }

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
        fprintf(stderr, "Failed to initialize libcurl\n");
        goto cleanup;
    }

    OpenSSL_add_all_algorithms();

    if (obtain_auth_key(&cfg, &key, &key_len) != 0) {
        goto cleanup_curl;
    }

    if (request_certificate(&cfg, csr.data, csr.len, key, key_len, &cert) != 0) {
        goto cleanup_curl;
    }
    if (validate_cert_pem(cert.data, cert.len) != 0) {
        goto cleanup_curl;
    }
    if (write_file(cfg.cert_file, cert.data, cert.len) != 0) {
        goto cleanup_curl;
    }

    printf("Certificate written to %s\n", cfg.cert_file);
    ret = EXIT_SUCCESS;

cleanup_curl:
    curl_global_cleanup();
cleanup:
    free(key);
    buffer_free(&csr);
    buffer_free(&cert);
    config_free(&cfg);
    return ret;
}
