#include <stdlib.h>

#include "parser.h"

struct conn {
    struct header *hdr;
};

void free_conn(struct conn *c)
{
    free(c->hdr);
    free(c);
}
