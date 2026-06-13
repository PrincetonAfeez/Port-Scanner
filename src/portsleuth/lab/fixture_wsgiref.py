"""WSGI fixture for portsleuth CLI."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from wsgiref.simple_server import WSGIRequestHandler, make_server


def wsgi_application(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET")

    if path == "/redirect":
        return _respond(
            environ,
            start_response,
            "302 Found",
            "redirecting\n",
            extra_headers=[("Location", "/")],
        )

    if path == "/health":
        return _respond(environ, start_response, "200 OK", "ok\n")

    if path == "/headers":
        text = (
            f"method={method}\n"
            f"path={path}\n"
            f"user-agent={environ.get('HTTP_USER_AGENT', '')}\n"
            f"host={environ.get('HTTP_HOST', '')}\n"
        )
        return _respond(environ, start_response, "200 OK", text)

    body_text = (
        "portsleuth WSGI lab\n"
        f"method={method}\n"
        f"path={path}\n"
        "WSGI is the Python application boundary behind the web server.\n"
        "Routes: / /health /redirect /headers\n"
    )
    return _respond(environ, start_response, "200 OK", body_text)


def _respond(environ, start_response, status: str, text: str, extra_headers=None):
    body = text.encode("utf-8")
    headers = [
        ("Content-Type", "text/plain; charset=utf-8"),
        # Content-Length always reflects the GET body size, even for HEAD.
        ("Content-Length", str(len(body))),
        ("X-Portsleuth-Lab", "wsgi"),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    start_response(status, headers)
    # RFC 7231: a response to HEAD must not include a message body.
    if environ.get("REQUEST_METHOD") == "HEAD":
        return [b""]
    return [body]


class QuietWSGIRequestHandler(WSGIRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        return


def make_wsgi_server(host: str = "127.0.0.1", port: int = 8080):
    return make_server(host, port, wsgi_application, handler_class=QuietWSGIRequestHandler)


def run_wsgi_server(host: str, port: int) -> None:
    httpd = make_wsgi_server(host, port)
    actual_port = httpd.server_port
    print(f"WSGI lab listening on http://{host}:{actual_port}")
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()


@contextmanager
def wsgi_fixture_thread(host: str = "127.0.0.1", port: int = 0) -> Iterator[tuple[str, int]]:
    httpd = make_wsgi_server(host, port)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield host, int(httpd.server_port)
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2.0)

