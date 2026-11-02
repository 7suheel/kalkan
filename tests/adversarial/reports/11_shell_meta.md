# Command injection in `$(touch PWNED)`

The file $(touch${IFS}PWNED).c and ;touch PWNED;.c are affected.
The function `touch_PWNED_$(id)` and run`touch PWNED`() break.
Also see a.c:1;touch PWNED and `--output=PWNED` and -e.c:1.
