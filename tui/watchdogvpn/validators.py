"""Pure input validators for the WatchdogVPN TUI."""

import re


def valid_location_hint(value: str) -> bool:
    value = (value or "").strip()
    if not value or value.lower() == "sin valor":
        return False
    return bool(re.match(r"^[A-Za-z0-9 _.-]{2,64}$", value))


def valid_domain(value: str) -> tuple[bool, str]:
    domain = (value or "").strip().lower()
    if domain.startswith("http://") or domain.startswith("https://"):
        return False, "Escribe solo el dominio, sin http:// ni https://. Ejemplo: avito.ru"
    if "/" in domain or ":" in domain:
        return False, "Escribe solo el dominio base, sin rutas, puertos ni parametros."
    if domain.startswith("*."):
        domain = domain[2:]
    if len(domain) > 253:
        return False, "El dominio es demasiado largo."
    pattern = r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
    if not re.match(pattern, domain):
        return False, "Dominio invalido. Usa formato tipo avito.ru, ozon.ru o sub.dominio.ru."
    return True, domain


def valid_timer_interval(value: str):
    value = (value or "").strip()
    if not re.match(r"^[0-9]+(s|min|h|d)$", value):
        return False, "Usa formato systemd simple: 30s, 2min, 3h o 1d."
    amount = int(re.match(r"^([0-9]+)", value).group(1))
    if amount < 1:
        return False, "El intervalo debe ser mayor que cero."
    return True, value
