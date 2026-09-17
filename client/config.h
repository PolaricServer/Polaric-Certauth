#ifndef CONFIG_H
#define CONFIG_H

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

int config_init(Config *cfg);
void config_free(Config *cfg);
int parse_config_file(const char *path, Config *cfg);
int validate_config(const Config *cfg);

#endif
