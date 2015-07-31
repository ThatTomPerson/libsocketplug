#ifndef SOCKETPLUG_CORE_HTTP_H
#define SOCKETPLUG_CORE_HTTP_H
#include <curl/curl.h>

#include "bstrlib.h"
#include "util.h"

void http_init();

void http_destroy();

bstring http_put(char *url, bstring *post);

bstring http_post(char *url, bstring *post);

bstring http_get(char *url);


#endif //SOCKETPLUG_CORE_HTTP_H
