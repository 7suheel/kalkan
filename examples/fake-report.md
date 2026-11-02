# Heap overflow in curl_url_parse_strict()

The function curl_url_parse_strict() in lib/urlapi.c at line 9999
copies the host name without a length check, which allows remote code
execution. Severity: critical.
