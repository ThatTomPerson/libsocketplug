#include "socketplug.h"

int main(int argc, char *argv[])
{
    socketplug_init(argv[1], argv[2], argv[3]);

    socketplug_stop();

    return 0;
}