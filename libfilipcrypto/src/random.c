#include "random.h"

int generate_random_bytes(unsigned char *outbuf, const int len)
{
    if (RAND_poll() != 1)
    {
        printf("RAND_poll\n");
        return 1;
    }

    if (RAND_bytes(outbuf, len) != 1)
    {
        printf("RAND_bytes\n");
        return 1;
    }

    return 0;
}

