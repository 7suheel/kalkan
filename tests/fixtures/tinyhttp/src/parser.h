#ifndef TINYHTTP_PARSER_H
#define TINYHTTP_PARSER_H

#include <stddef.h>

struct header {
    char *name;
    char *value;
};

int parse_header(const char *line, struct header *out);
size_t read_body(size_t count, size_t size, char **buf);

#endif
