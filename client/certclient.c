#define _POSIX_C_SOURCE 200809L

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define DEVKEY_SALT "*E^o2Zse@!_rQp:kL%{4qL.~!v[n&HS)"
#define DEVKEY_ITER 16384
#define HMAC_KEY_LEN 32

typedef struct {
    char *service_url;
    char *sign_path;
    char *login_path;
    char *csr_file;
    char *cert_file;
    char *userid;
    char *password;
    char *session_key;
    char *shared_secret;
    char *role;
    char *ca_file;
    long days;
    int insecure_tls;
} Config;

typedef struct {
    char *data;
    size_t len;
} Buffer;

static void config_init(Config *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->sign_path = strdup("/cacert/sign");
    cfg->login_path = strdup("/directLogin");
    cfg->days = 0;
}

static void config_free(Config *cfg) {
    free(cfg->service_url);
    free(cfg->sign_path);
    free(cfg->login_path);
    free(cfg->csr_file);
    free(cfg->cert_file);
    free(cfg->userid);
    free(cfg->password);
    free(cfg->session_key);
    free(cfg->shared_secret);
    free(cfg->role);
    free(cfg->ca_file);
}

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

static char *trim(char *s) {
    char *end;
    while (*s != '\0' && isspace((unsigned char)*s)) {
        s++;
    }
    if (*s == '\0') {
        return s;
    }
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end-- = '\0';
    }
    return s;
}

static int set_config_value(char **field, const char *value) {
    char *copy = strdup(value);
    if (copy == NULL) {
        return -1;
    }
    free(*field);
    *field = copy;
    return 0;
}

static int parse_bool(const char *value, int *out) {
    if (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0 ||
        strcasecmp(value, "yes") == 0 || strcasecmp(value, "on") == 0) {
        *out = 1;
        return 0;
    }
    if (strcasecmp(value, "false") == 0 || strcmp(value, "0") == 0 ||
        strcasecmp(value, "no") == 0 || strcasecmp(value, "off") == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

static int contains_ctl_chars(const char *value) {
    const unsigned char *p = (const unsigned char *) value;
    while (*p != '\0') {
        if (*p < 32 || *p == 127) {
            return 1;
        }
        p++;
    }
    return 0;
}

static int contains_auth_delimiter(const char *value) {
    return strchr(value, ';') != NULL;
}

static int parse_config_file(const char *path, Config *cfg) {
    FILE *fp;
    char line[4096];
    unsigned long lineno = 0;

    fp = fopen(path, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open config file %s: %s\n", path, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *key;
        char *value;
        char *equals;
        lineno++;

        key = trim(line);
        if (*key == '\0' || *key == '#' || *key == ';') {
            continue;
        }
        if (*key == '[') {
            continue;
        }

        equals = strchr(key, '=');
        if (equals == NULL) {
            fprintf(stderr, "Malformed config line %lu\n", lineno);
            fclose(fp);
            return -1;
        }

        *equals = '\0';
        value = trim(equals + 1);
        key = trim(key);

        if (strcmp(key, "service_url") == 0) {
            if (set_config_value(&cfg->service_url, value) != 0) {
                fclose(fp);
                return -1;
            }
        } else if (strcmp(key, "sign_path") == 0) {
            if (set_config_value(&cfg->sign_path, value) != 0) {
                fclose(fp);
                return -1;
            }
        } else if (strcmp(key, "login_path") == 0) {
            if (set_config_value(&cfg->login_path, value) != 0) {
                fclose(fp);
                return -1;
            }
        } else if (strcmp(key, "csr_file") == 0) {
            if (set_config_value(&cfg->csr_file, value) != 0) {
                fclose(fp);
                return -1;
            }
        } else if (strcmp(key, "cert_file") == 0) {
            if (set_config_value(&cfg->cert_file, value) != 0) {
                fclose(fp);
                return -1;
            }
        } else if (strcmp(key, "userid") == 0) {
            if (set_config_value(&cfg->userid, value) != 0) {
                fclose(fp);
                return -1;
            }
        } else if (strcmp(key, "password") == 0) {
            if (set_config_value(&cfg->password, value) != 0) {
                fclose(fp);
                return -1;
            }
        } else if (strcmp(key, "session_key") == 0) {
            if (set_config_value(&cfg->session_key, value) != 0) {
                fclose(fp);
                return -1;
            }
        } else if (strcmp(key, "shared_secret") == 0) {
            if (set_config_value(&cfg->shared_secret, value) != 0) {
                fclose(fp);
                return -1;
            }
        } else if (strcmp(key, "role") == 0) {
            if (set_config_value(&cfg->role, value) != 0) {
                fclose(fp);
                return -1;
            }
        } else if (strcmp(key, "ca_file") == 0) {
            if (set_config_value(&cfg->ca_file, value) != 0) {
                fclose(fp);
                return -1;
            }
        } else if (strcmp(key, "days") == 0) {
            char *endptr = NULL;
            errno = 0;
            cfg->days = strtol(value, &endptr, 10);
            if (errno != 0 || endptr == value || *trim(endptr) != '\0' || cfg->days < 0) {
                fprintf(stderr, "Invalid days value on line %lu\n", lineno);
                fclose(fp);
                return -1;
            }
        } else if (strcmp(key, "insecure_tls") == 0) {
            if (parse_bool(value, &cfg->insecure_tls) != 0) {
                fprintf(stderr, "Invalid insecure_tls value on line %lu\n", lineno);
                fclose(fp);
                return -1;
            }
        } else {
            fprintf(stderr, "Unknown config key '%s' on line %lu\n", key, lineno);
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

static int validate_config(const Config *cfg) {
    int auth_modes = 0;

    if (cfg->service_url == NULL || cfg->service_url[0] == '\0') {
        fprintf(stderr, "Missing service_url in config\n");
        return -1;
    }
    if (cfg->csr_file == NULL || cfg->csr_file[0] == '\0') {
        fprintf(stderr, "Missing csr_file in config\n");
        return -1;
    }
    if (cfg->cert_file == NULL || cfg->cert_file[0] == '\0') {
        fprintf(stderr, "Missing cert_file in config\n");
        return -1;
    }
    if (cfg->userid == NULL || cfg->userid[0] == '\0') {
        fprintf(stderr, "Missing userid in config\n");
        return -1;
    }
    if (contains_ctl_chars(cfg->userid)) {
        fprintf(stderr, "userid contains invalid control characters\n");
        return -1;
    }
    if (contains_auth_delimiter(cfg->userid)) {
        fprintf(stderr, "userid must not contain ';'\n");
        return -1;
    }
    if (cfg->role != NULL && contains_ctl_chars(cfg->role)) {
        fprintf(stderr, "role contains invalid control characters\n");
        return -1;
    }
    if (cfg->role != NULL && contains_auth_delimiter(cfg->role)) {
        fprintf(stderr, "role must not contain ';'\n");
        return -1;
    }
    if (cfg->sign_path != NULL && strchr(cfg->sign_path, '#') != NULL) {
        fprintf(stderr, "sign_path must not contain a URL fragment\n");
        return -1;
    }

    if (cfg->password != NULL && cfg->password[0] != '\0') {
        auth_modes++;
    }
    if (cfg->session_key != NULL && cfg->session_key[0] != '\0') {
        auth_modes++;
    }
    if (cfg->shared_secret != NULL && cfg->shared_secret[0] != '\0') {
        auth_modes++;
    }

    if (auth_modes == 0) {
        fprintf(stderr, "Configure exactly one of password, session_key, or shared_secret\n");
        return -1;
    }
    if (auth_modes > 1) {
        fprintf(stderr, "Only one of password, session_key, or shared_secret may be configured\n");
        return -1;
    }
    return 0;
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
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s for writing: %s\n", path, strerror(errno));
        return -1;
    }
    if (fwrite(data, 1, len, fp) != len) {
        fprintf(stderr, "Failed to write %s\n", path);
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0) {
        fprintf(stderr, "Failed to close %s\n", path);
        return -1;
    }
    return 0;
}

static int validate_csr_pem(const char *pem, size_t len) {
    BIO *bio = BIO_new_mem_buf(pem, (int) len);
    X509_REQ *req = NULL;
    int ok = -1;

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
    BIO *bio = BIO_new_mem_buf(pem, (int) len);
    X509 *cert = NULL;
    int ok = -1;

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
    if (EVP_EncodeBlock((unsigned char *) out, data, (int) len) < 0) {
        free(out);
        return NULL;
    }
    out[out_len] = '\0';
    return out;
}

static int base64_decode(const char *text, unsigned char **data, size_t *len) {
    size_t raw_len = strlen(text);
    size_t normalized_len = raw_len;
    size_t input_len;
    size_t alloc_len = 0;
    unsigned char *buf = NULL;
    char *normalized = NULL;
    int out_len;
    int padding = 0;

    if (raw_len == 0 || raw_len % 4 == 1) {
        return -1;
    }

    input_len = raw_len + ((4 - (raw_len % 4)) % 4);
    normalized = malloc(input_len + 1);
    alloc_len = (input_len / 4) * 3 + 3;
    buf = malloc(alloc_len);
    if (normalized == NULL || buf == NULL) {
        free(normalized);
        free(buf);
        return -1;
    }

    memcpy(normalized, text, normalized_len);
    while (normalized_len < input_len) {
        normalized[normalized_len++] = '=';
    }
    normalized[input_len] = '\0';

    if (input_len >= 1 && normalized[input_len - 1] == '=') {
        padding++;
    }
    if (input_len >= 2 && normalized[input_len - 2] == '=') {
        padding++;
    }

    out_len = EVP_DecodeBlock(buf, (const unsigned char *) normalized, (int) input_len);
    if (out_len < 0) {
        free(normalized);
        free(buf);
        return -1;
    }

    free(normalized);
    *data = buf;
    *len = (size_t) out_len - (size_t) padding;
    return 0;
}

static int derive_device_key(const char *secret, unsigned char *key, size_t key_len) {
    if (PKCS5_PBKDF2_HMAC(secret,
                          (int) strlen(secret),
                          (const unsigned char *) DEVKEY_SALT,
                          (int) strlen(DEVKEY_SALT),
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

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    Buffer *buf = userdata;
    size_t chunk = size * nmemb;
    char *new_data = realloc(buf->data, buf->len + chunk + 1);

    if (new_data == NULL) {
        return 0;
    }

    buf->data = new_data;
    memcpy(buf->data + buf->len, ptr, chunk);
    buf->len += chunk;
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

static char *trimmed_copy(const Buffer *buf) {
    char *copy;
    char *start;
    char *end;

    if (buf->data == NULL) {
        return NULL;
    }

    copy = xstrdup(buf->data);
    start = trim(copy);
    if (start != copy) {
        memmove(copy, start, strlen(start) + 1);
    }
    end = copy + strlen(copy);
    while (end > copy && isspace((unsigned char) end[-1])) {
        *--end = '\0';
    }
    return copy;
}

static char *url_encode(CURL *curl, const char *value) {
    char *encoded = curl_easy_escape(curl, value, 0);
    char *copy;
    if (encoded == NULL) {
        return NULL;
    }
    copy = xstrdup(encoded);
    curl_free(encoded);
    return copy;
}

static int append_header(struct curl_slist **headers, const char *value) {
    struct curl_slist *next = curl_slist_append(*headers, value);
    if (next == NULL) {
        return -1;
    }
    *headers = next;
    return 0;
}

static int fetch_session_key(const Config *cfg, Buffer *response) {
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    char *login_url = NULL;
    char *username = NULL;
    char *password = NULL;
    char *post_data = NULL;
    long status = 0;
    CURLcode rc;
    int ret = -1;

    if (cfg->password == NULL || cfg->password[0] == '\0') {
        return -1;
    }

    curl = curl_easy_init();
    if (curl == NULL) {
        return -1;
    }

    login_url = join_url(cfg->service_url, cfg->login_path);
    username = url_encode(curl, cfg->userid);
    password = url_encode(curl, cfg->password);
    if (login_url == NULL || username == NULL || password == NULL) {
        goto cleanup;
    }

    post_data = malloc(strlen(username) + strlen(password) + 32);
    if (post_data == NULL) {
        goto cleanup;
    }
    snprintf(post_data,
             strlen(username) + strlen(password) + 32,
             "username=%s&" "pass" "word=%s",
             username,
             password);

    if (append_header(&headers, "Content-Type: application/x-www-form-urlencoded") != 0) {
        goto cleanup;
    }

    memset(response, 0, sizeof(*response));
    curl_easy_setopt(curl, CURLOPT_URL, login_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) strlen(post_data));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    apply_tls_options(curl, cfg);

    rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        fprintf(stderr, "Login request failed: %s\n", curl_easy_strerror(rc));
        goto cleanup;
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (status != 200) {
        fprintf(stderr, "Login failed with HTTP %ld\n", status);
        if (response->data != NULL && response->len > 0) {
            fprintf(stderr, "%s\n", response->data);
        }
        goto cleanup;
    }

    ret = 0;

cleanup:
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(login_url);
    free(username);
    free(password);
    free(post_data);
    return ret;
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

    if (HMAC(EVP_sha256(),
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

    header = malloc(strlen("Authorization: Arctic-Hmac ") + strlen(cfg->userid) +
                    strlen(nonce_b64) + strlen(mac_b64) +
                    (cfg->role ? strlen(cfg->role) + 1 : 0) + 4);
    if (header == NULL) {
        goto cleanup;
    }

    if (cfg->role != NULL && cfg->role[0] != '\0') {
        sprintf(header,
                "Authorization: Arctic-Hmac %s;%s;%s;%s",
                cfg->userid,
                nonce_b64,
                mac_b64,
                cfg->role);
    } else {
        sprintf(header,
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
    Buffer login_response;
    char *session_key = NULL;
    int ret = -1;

    memset(&login_response, 0, sizeof(login_response));

    if (cfg->session_key != NULL && cfg->session_key[0] != '\0') {
        session_key = xstrdup(cfg->session_key);
    } else if (cfg->shared_secret != NULL && cfg->shared_secret[0] != '\0') {
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
    } else {
        if (fetch_session_key(cfg, &login_response) != 0) {
            goto cleanup;
        }
        session_key = trimmed_copy(&login_response);
        if (session_key == NULL || session_key[0] == '\0') {
            fprintf(stderr, "Login response did not contain a session key\n");
            goto cleanup;
        }
    }

    if (base64_decode(session_key, key, key_len) != 0) {
        fprintf(stderr, "Failed to decode session key\n");
        goto cleanup;
    }
    ret = 0;

cleanup:
    free(session_key);
    buffer_free(&login_response);
    return ret;
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
        const char *sep = strchr(sign_url, '?') == NULL ? "?" : "&";
        int needed = snprintf(NULL, 0, "%s%sdays=%ld", sign_url, sep, cfg->days);
        url_with_query = malloc((size_t) needed + 1);
        if (url_with_query == NULL) {
            goto cleanup;
        }
        snprintf(url_with_query, (size_t) needed + 1, "%s%sdays=%ld", sign_url, sep, cfg->days);
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
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) csr_len);
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
    free(url_with_query);
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

    config_init(&cfg);

    if (parse_config_file(config_path, &cfg) != 0 ||
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
