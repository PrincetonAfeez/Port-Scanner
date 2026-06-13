# Platform Notes

## Portable core (TCP connect)

The dependable scanner path uses normal connected TCP sockets (`asyncio.open_connection`).
It works without administrator or root privileges on typical Windows, macOS, Linux, and WSL setups.

## Raw packet features

Raw ICMP and raw TCP socket creation require elevated privileges on most platforms.
Windows restricts raw TCP behavior further; treat SYN scanning as Linux-only even when sockets can be created.

Run `portsleuth doctor` to see:

- OS and Python version
- Admin/root status
- Raw ICMP / raw TCP availability
- Whether default lab ports (8080, 9090) are free to bind
- Optional packet capture tools on `PATH`

## Audit log locking

Unix builds use `fcntl` file locking on the audit JSONL file.
Windows uses an in-process lock only — adequate for single-operator local use; concurrent separate processes may interleave lines.

## IPv6

Hostnames may resolve to IPv6 addresses. Use `--family ipv4` (default), `--family ipv6`, or `--family auto`.
IPv6 TCP connect scanning is supported in the portable core; IPv6 packet crafting is out of scope.

## CI matrix

GitHub Actions runs tests on Ubuntu and Windows with Python 3.11 and 3.12.
macOS is supported locally but not in CI.

## Privileged tests

Set `PORTSLEUTH_PRIVILEGED_TESTS=1` to run raw-socket capability tests in `tests/privileged/`.
