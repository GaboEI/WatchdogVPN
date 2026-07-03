"""Rendering primitives and semantic display helpers for the TUI."""

import re
import shutil
import sys

from watchdogvpn.formatting import strip_ansi
from watchdogvpn.styles import BG, BOLD, CSI, FG, RESET


def get_size():
    cols, rows = shutil.get_terminal_size((120, 30))
    return rows, cols


def clear():
    sys.stdout.write(CSI + "2J" + CSI + "H")


def move(y: int, x: int):
    sys.stdout.write(f"{CSI}{y};{x}H")


def write(y: int, x: int, text: str, style: str = ""):
    move(y, x)
    sys.stdout.write(style + text + RESET)


def hline(y: int, x: int, width: int, ch: str = "─", style: str = ""):
    write(y, x, ch * max(0, width), style)


def box(y: int, x: int, h: int, w: int, title: str = ""):
    if h < 2 or w < 2:
        return
    write(y, x, "┌" + "─" * (w - 2) + "┐", FG["blue"])
    for row in range(y + 1, y + h - 1):
        write(row, x, "│", FG["blue"])
        write(row, x + w - 1, "│", FG["blue"])
    write(y + h - 1, x, "└" + "─" * (w - 2) + "┘", FG["blue"])
    if title:
        write(y, x + 2, f" {title} ", FG["cyan"] + BOLD)


def fit(text: str, width: int) -> str:
    text = strip_ansi(str(text)).replace("\n", " ").strip()
    return text if len(text) <= width else text[: max(0, width - 1)] + "…"


def flag_from_iso(iso: str) -> str:
    iso = (iso or "").upper()
    if not re.match(r"^[A-Z]{2}$", iso):
        return ""
    base = 127397
    return chr(base + ord(iso[0])) + chr(base + ord(iso[1]))


def semantic_style(key: str, value: str) -> str:
    v = value.strip().lower()

    if key in ("VPN", "Tun"):
        if "activo" in v or v in ("active", "up"):
            return FG["green"] + BOLD
        if "degradado" in v or v == "degraded":
            return FG["yellow"] + BOLD
        if "desactivado" in v or v in ("inactive", "down", "failed", "dead"):
            return FG["red"] + BOLD
        return FG["yellow"] + BOLD

    if key == "Auth":
        if v == "ok":
            return FG["green"] + BOLD
        if "expirada" in v:
            return FG["red"] + BOLD
        return FG["yellow"] + BOLD

    if key in ("Rotate", "Watchdog"):
        if "active" in v:
            return FG["green"] + BOLD
        if "inactive" in v or "disabled" in v:
            return FG["red"] + BOLD
        return FG["yellow"] + BOLD

    if key == "Country":
        if v == "ru":
            return FG["red"] + BOLD
        if v in ("unk", "unknown"):
            return FG["yellow"] + BOLD
        return FG["green"] + BOLD

    if key == "IP":
        if "no disponible" in v or "error" in v:
            return FG["yellow"] + BOLD
        return FG["cyan"] + BOLD

    if key == "Route":
        if v == "tun0":
            return FG["green"] + BOLD
        if v in ("default", "enp4s0"):
            return FG["red"] + BOLD
        return FG["yellow"]

    if key == "Location":
        return FG["cyan"] + BOLD

    if key == "Bypass":
        return FG["blue"] + BOLD

    if key == "Event":
        if any(token in v for token in ("critical", "fail", "error")):
            return FG["red"] + BOLD
        if any(token in v for token in ("rotate", "connected", "ok", "aplic")):
            return FG["green"] + BOLD
        if any(token in v for token in ("warn", "unknown")):
            return FG["yellow"] + BOLD
        return FG["cyan"] + BOLD

    if key == "Riesgo":
        if any(token in v for token in ("ninguno", "solo lectura", "bajo", "automatico")):
            return FG["green"] + BOLD
        if any(token in v for token in ("todo el trafico", "fuera del tunel")):
            return FG["red"] + BOLD
        if any(token in v for token in ("microcorte", "corte breve", "no recomendado", "directo")):
            return FG["yellow"] + BOLD
        return FG["yellow"] + BOLD

    if key in ("Tipo", "Perfil", "Comando", "Timer", "Archivo", "Ruta"):
        return FG["cyan"] + BOLD

    if key in ("Impacto", "Efecto", "Accion"):
        return FG["yellow"] + BOLD

    if key in ("Rollback", "Estado"):
        if any(token in v for token in ("automatico", "active", "running")):
            return FG["green"] + BOLD
        if any(token in v for token in ("inactive", "failed", "dead")):
            return FG["red"] + BOLD
        return FG["yellow"] + BOLD

    if key in ("Entradas", "Actual", "Intervalo"):
        return FG["blue"] + BOLD

    return FG["white"]


def display_value(key: str, value: str) -> str:
    if key == "Country":
        code = value.strip().upper()
        if re.match(r"^[A-Z]{2}$", code):
            return f"{flag_from_iso(code)} {code}"
    if key == "Location":
        code = value.strip().upper()
        if re.match(r"^[A-Z]{2}$", code):
            return f"{flag_from_iso(code)} {code}"
    return value


def display_label(key: str) -> str:
    labels = {
        "Auth": "Sesion",
        "Tun": "Tunel",
        "Route": "Ruta",
        "Country": "Pais",
        "Location": "Ubicacion",
        "Rotate": "Rotacion",
        "Watchdog": "Watchdog",
        "Bypass": "Exclusiones",
        "Event": "Evento",
    }
    return labels.get(key, key)
