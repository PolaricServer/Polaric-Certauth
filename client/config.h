#ifndef CONFIG_H
#define CONFIG_H

typedef struct {
    char *service_url;
    char *sign_path;
    char *csr_file;
    char *cert_file;
    char *userid;
    char *shared_secret;
    char *role;
    char *ca_file;
    long days;
    int insecure_tls;
} Config;

/*
 * Initialize a Config before any other config_* call.
 * String members are heap-owned by the Config and must be released with
 * config_free after any successful or partial initialization/parsing flow.
 */
int config_init(Config *cfg);
/* Release all heap-owned Config members after success or failure. */
void config_free(Config *cfg);
/*
 * Parse path into an initialized Config, returning 0 on success and -1 on error.
 * The caller still owns the Config and must call config_free even after failure.
 */
int parse_config_file(const char *path, Config *cfg);
/*
 * Validate an initialized Config, returning 0 on success and -1 on error.
 * The caller still owns the Config and must call config_free after failure.
 */
int validate_config(const Config *cfg);

#endif
