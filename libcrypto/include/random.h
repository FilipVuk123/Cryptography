
#ifndef __RANDOM_H__
#define __RANDOM_H__


#include <stdio.h>
#include <openssl/rand.h>


int generate_random_bytes(unsigned char *outbuf, const int len);


#endif