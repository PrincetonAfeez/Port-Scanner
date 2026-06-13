"""Exit codes for portsleuth CLI."""

OK = 0
ERROR = 1
USAGE = 2  # argparse also exits with 2 on invalid invocation
AUTHORIZATION_DENIED = 3
TARGET_ERROR = 4
UNSUPPORTED = 5
PRIVILEGE = 6
PARTIAL = 7
FIXTURE = 8
INTERRUPTED = 130
