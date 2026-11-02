"""Send a test request to a local tinyhttp server."""


def make_request(host: str) -> str:
    return f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
