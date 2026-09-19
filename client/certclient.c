
#define _POSIX_C_SOURCE 200809L

#include "config.h"
#include "auth.h"

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

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


#define CONFIG_PATH "/etc/polaric-certauth/client.ini"


typedef struct {
    char *data;
    size_t len;
} Buffer;



static void buffer_free(Buffer *buf) {
    free(buf->data);
    buf->data = NULL;
    buf->len = 0;
}



static inline int fits_in_int(size_t value) {
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
    Buffer csr = {0};
    Buffer cert = {0};
    unsigned char *key = NULL;
    size_t key_len = 0;
    int ret = EXIT_FAILURE;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s csr-path output-path\n", argv[0]);
        return EXIT_FAILURE;
    }
    char* csr_file = argv[1];
    char* cert_file = argv[2];

    if (config_init(&cfg) != 0 ||
        parse_config_file(CONFIG_PATH, &cfg) != 0 ||
        validate_config(&cfg) != 0) {
        goto cleanup;
    }

    if (read_file(csr_file, &csr) != 0) {
        fprintf(stderr, "Failed to read CSR file %s\n", csr_file);
        goto cleanup;
    }
    if (validate_csr_pem(csr.data, csr.len) != 0) 
        goto cleanup;
    

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
        fprintf(stderr, "Failed to initialize libcurl\n");
        goto cleanup;
    }

    OpenSSL_add_all_algorithms();

    if (obtain_auth_key(&cfg, &key, &key_len) != 0) 
        goto cleanup_curl;
    
    if (request_certificate(&cfg, csr.data, csr.len, key, key_len, &cert) != 0) 
        goto cleanup_curl;

    if (validate_cert_pem(cert.data, cert.len) != 0) 
        goto cleanup_curl;

    if (write_file(cert_file, cert.data, cert.len) != 0) 
        goto cleanup_curl;
    

    printf("Certificate written to %s\n", cert_file);
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
