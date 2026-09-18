#ifndef AUTH_H
#define AUTH_H

#include "config.h"
#include <stdlib.h>
#include <curl/curl.h>


int append_header(struct curl_slist **headers, const char *value);

int make_auth_header(const Config *cfg,
                     const unsigned char *key,
                     size_t key_len,
                     const char *body,
                     size_t body_len,
                     char **header_out);

int obtain_auth_key(const Config *cfg, unsigned char **key, size_t *key_len);


#endif
