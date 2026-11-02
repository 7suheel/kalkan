# Information leak

The secret is in ../../secret.txt and ../secret.txt line 1, also /etc/passwd:1.
The bug is in link.c:1 and in function read_secret() in link.c.
See ../outside.c:1 for details.
