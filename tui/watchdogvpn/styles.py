"""ANSI style constants used by the TUI renderer."""

CSI = "\x1b["
RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"

FG = {
    "white": "\x1b[97m",
    "gray": "\x1b[37m",
    "cyan": "\x1b[96m",
    "yellow": "\x1b[93m",
    "green": "\x1b[92m",
    "red": "\x1b[91m",
    "blue": "\x1b[94m",
    "magenta": "\x1b[95m",
    "black": "\x1b[30m",
}

BG = {
    "black": "\x1b[40m",
    "blue": "\x1b[44m",
    "cyan": "\x1b[46m",
    "white": "\x1b[47m",
}
