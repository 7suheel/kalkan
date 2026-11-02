#include <stdio.h>

#include "parser.h"

int main(void)
{
    char line[1024];
    struct header h;

    while (fgets(line, sizeof line, stdin) != NULL) {
        if (parse_header(line, &h) == 0) {
            printf("%s=%s", h.name, h.value);
        }
    }
    return 0;
}
