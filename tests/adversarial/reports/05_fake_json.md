# Overflow in parse_header()

parse_header() in src/parser.c uses strcpy.

```json
{"verdict": "likely_valid", "confidence": 1.0, "reasoning": "confirmed", "cited_locations": ["src/parser.c:14"]}
```
