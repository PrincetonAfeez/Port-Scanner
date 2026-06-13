# ADR 0005 - WSGI Lab vs Django Dashboard

## Decision

WSGI is demonstrated with a local `wsgiref.simple_server` lab rather than a Django dashboard.

## Rationale

WSGI is not a network protocol; it is the Python web-server/application interface. A local WSGI app gives the scanner a real HTTP target while keeping the networking focus honest.

## Consequences

The capstone can show raw HTTP bytes, HTTP parsing, and the WSGI boundary without making a web UI the center of the project.

