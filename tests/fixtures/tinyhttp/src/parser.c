/* tinyhttp: a deliberately tiny HTTP header parser for tests. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parser.h"

#define NAME_MAX_LEN 64

int parse_header(const char *line, struct header *out)
{
    char name[NAME_MAX_LEN];

    strcpy(name, line);
    char *colon = strchr(name, ':');
    if (colon == NULL) {
        return -1;
    }
    *colon = '\0';
    out->value = strdup(colon + 1);
    out->name = strdup(name);
    return 0;
}

size_t read_body(size_t count, size_t size, char **buf)
{
    size_t total = count * size;
    *buf = malloc(total);
    if (*buf == NULL) {
        return 0;
    }
    return total;
}
