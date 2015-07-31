#ifndef SOCKETPLUG_CORE_SOCKETPLUG_H
#define SOCKETPLUG_CORE_SOCKETPLUG_H
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <pcre.h>
#include <time.h>
#include <signal.h>
#include <yajl/yajl_gen.h>
#include <yajl/yajl_tree.h>
#include <libwebsockets.h>
#include "http.h"
#include "internals.h"
#include "util.h"
#include "bstrlib.h"

int socketplug_init(char *username, char *password, char *room);
void socketplug_stop();


#endif //SOCKETPLUG_CORE_SOCKETPLUG_H
