# Heap buffer overflow in parse_header()

## Affected version
v1.2.0 (also tested on commit a1b2c3d)

## Description
The function `parse_header()` in src/parser.c copies the header name into a
fixed 64-byte buffer without checking its length (src/parser.c:14).

```c
    strcpy(name, line);
```

## Steps to reproduce
1. Build the project with `make`.
2. Run `./tinyhttp < poc.txt` where poc.txt contains a 200-byte header name.

## Proof of concept
```
python3 -c "print('A'*200 + ': x')" > poc.txt
```

## Impact
A remote attacker can overwrite the stack and crash the server, possibly
leading to code execution.
