#define _POSIX_C_SOURCE 200809L

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static char *trim(char *s) {
    char *end;
    while (*s != '\0' && isspace((unsigned char) *s)) {
        s++;
    }
    if (*s == '\0') {
        return s;
    }
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char) *end)) {
        *end-- = '\0';
    }
    return s;
}

static void wipe_and_free(char *value);

static int set_config_value(char **field, const char *value) {
    char *copy = strdup(value);
    if (copy == NULL) {
        return -1;
    }
    free(*field);
    *field = copy;
    return 0;
}

static int set_secret_config_value(char **field, const char *value) {
    char *copy = strdup(value);
    if (copy == NULL) {
        return -1;
    }
    wipe_and_free(*field);
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

static void wipe_and_free(char *value) {
    volatile unsigned char *p;

    if (value == NULL) {
        return;
    }
    for (p = (volatile unsigned char *) value; *p != '\0'; ++p) {
        *p = 0;
    }
    free(value);
}

int config_init(Config *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->sign_path = strdup("/cacert/sign");
    cfg->login_path = strdup("/directLogin");
    cfg->days = 0;
    if (cfg->sign_path == NULL || cfg->login_path == NULL) {
        config_free(cfg);
        return -1;
    }
    return 0;
}

void config_free(Config *cfg) {
    free(cfg->service_url);
    free(cfg->sign_path);
    free(cfg->login_path);
    free(cfg->csr_file);
    free(cfg->cert_file);
    free(cfg->userid);
    wipe_and_free(cfg->password);
    wipe_and_free(cfg->session_key);
    wipe_and_free(cfg->shared_secret);
    free(cfg->role);
    free(cfg->ca_file);
}

int parse_config_file(const char *path, Config *cfg) {
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
            if (set_secret_config_value(&cfg->password, value) != 0) {
                fclose(fp);
                return -1;
            }
        } else if (strcmp(key, "session_key") == 0) {
            if (set_secret_config_value(&cfg->session_key, value) != 0) {
                fclose(fp);
                return -1;
            }
        } else if (strcmp(key, "shared_secret") == 0) {
            if (set_secret_config_value(&cfg->shared_secret, value) != 0) {
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

int validate_config(const Config *cfg) {
    int auth_modes = 0;

    if (cfg->service_url == NULL || cfg->service_url[0] == '\0') {
        fprintf(stderr, "Missing service_url in config\n");
        return -1;
    }
    if (strchr(cfg->service_url, '#') != NULL) {
        fprintf(stderr, "service_url must not contain a URL fragment\n");
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
    if (cfg->login_path != NULL && strchr(cfg->login_path, '#') != NULL) {
        fprintf(stderr, "login_path must not contain a URL fragment\n");
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
