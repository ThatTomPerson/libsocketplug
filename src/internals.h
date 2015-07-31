#ifndef SOCKETPLUG_CORE_INTERNALS_H
#define SOCKETPLUG_CORE_INTERNALS_H
#include "bstrlib.h"
#include "util.h"

void init_messages();

void add_message(bstring *message);

bstring *pop_message();

int messages_empty();

#endif //SOCKETPLUG_CORE_INTERNALS_H

