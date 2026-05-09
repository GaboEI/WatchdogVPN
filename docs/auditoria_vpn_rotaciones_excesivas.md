# Auditoria: rotaciones excesivas del VPN

Fecha de auditoria: 2026-05-09

## Objetivo

Determinar si las rotaciones frecuentes del VPN son un comportamiento correcto
causado por problemas reales de conexion, o si son provocadas por una
configuracion demasiado agresiva de WatchdogVPN.

## Resumen ejecutivo

`myvpn-logrotate.timer` queda descartado como causa. Ese timer solo rota y
comprime archivos de log; no cambia pais, no reinicia AdGuard VPN y no toca el
tunel.

`vpn-watchdog.timer` tampoco aparece como causa directa en el periodo revisado.
El watchdog corre aproximadamente cada 2 minutos, pero la mayor parte de sus
entradas son `OK status='UP'`, con IP y pais detectados. En esos casos observa,
pero no remedia.

El foco real esta en `vpn-rotate.log`: hay ejecuciones de `vpn_rotate start` mas
cercanas de lo esperado para una politica normal de 3 horas. Algunas fueron
justificadas por estado real `DOWN` o `DEGRADED`, pero otras ocurrieron cuando
el snapshot inicial ya estaba sano (`STATUS=UP`, `TUN=UP`, `ROUTE=TUN`,
`IP=OK`).

La conclusion provisional es:

- Hubo un tramo real de inestabilidad donde rotar estaba justificado.
- Despues de estabilizar, varias rotaciones parecen venir de activaciones del
  timer, reinicios del timer durante updates/pruebas, o acciones manuales.
- El dispatcher y el watchdog no son los principales sospechosos durante el
  periodo estable.

## Componentes revisados

### `myvpn-logrotate.timer`

Funcion: housekeeping de logs.

Archivos relacionados:

- `/var/log/myvpn/vpn-events.log`
- `/var/log/myvpn/vpn-watchdog.log`
- `/var/log/myvpn/vpn-rotate.log`
- `/var/log/vpn-dispatcher.log`
- `/var/log/vpn-domain-bypass.log`

Conclusion: descartado. No cambia ubicacion, no reinicia AdGuard VPN, no toca
`tun0` y no llama a `vpn_rotate.sh`.

### `vpn-watchdog.timer`

Funcion: vigilancia cada ~2 minutos.

Hallazgos:

- El watchdog registra entradas frecuentes tipo:
  - `OK status='UP' ip='...' country='FI'`
  - `OK status='UP' ip='...' country='DK'`
  - `OK status='UP' ip='...' country='SE'`
- Cuando el estado es `OK`, el script sale sin ejecutar remediacion.
- Solo llama a rotacion cuando `HEALTH_STATE` es `DOWN`, `RUSSIAN_IP` o
  `UNKNOWN_IP` sostenido hasta umbral.

Conclusion: no parece estar provocando rotaciones mientras el estado esta sano.

### NetworkManager dispatcher

Archivo:

- `networkmanager/dispatcher.d/99-vpn-rotate`

Funcion: revisar eventos `up` y `connectivity-change`.

Hallazgos:

- Al inicio del incidente, el dispatcher encontro estados reales fallidos:
  - `STATUS=DOWN TUN=DOWN ROUTE=DEFAULT IP=FAIL`
  - `STATUS=DEGRADED TUN=UP ROUTE=TUN IP=FAIL`
- En esos casos decidio `ROTATE`, lo cual esta justificado.
- Despues de estabilizar, el dispatcher siguio recibiendo muchos eventos de red,
  pero registraba `state='OK'` y `result='NO ACTION'`.

Conclusion: el dispatcher reacciono correctamente al fallo inicial. En el periodo
estable observado no parece ser el causante de las rotaciones adicionales.

### `vpn-rotate.timer`

Configuracion actual:

```ini
OnBootSec=5min
OnActiveSec=5min
OnUnitInactiveSec=3h
AccuracySec=1min
Persistent=true
```

Hallazgos:

- `OnUnitInactiveSec=3h` representa la politica estable esperada.
- `OnActiveSec=5min` puede provocar una rotacion 5 minutos despues de activar o
  reiniciar el timer.
- Durante sesiones de update, debug o reinicios manuales del timer, ese disparo
  corto puede generar rotaciones extra aunque la VPN este sana.
- El estado actual del timer muestra comportamiento estable: proxima rotacion a
  ~3 horas desde la ultima ejecucion.

Conclusion: es el principal sospechoso para rotaciones sanas cercanas despues de
updates o reinicios de timer.

## Evidencia de rotaciones justificadas

Durante el tramo inicial se observaron rotaciones con estado real fallido:

```text
SNAPSHOT STATUS=DOWN TUN=DOWN ROUTE=DEFAULT IP=FAIL IP_ADDR=none
ERROR: list-locations devolvió 0 ubicaciones válidas
```

Luego:

```text
TRY_FAIL iso='FI' STATUS=DEGRADED TUN=UP ROUTE=TUN IP=FAIL IP_ADDR=none
TRY_FAIL iso='SE' STATUS=DEGRADED TUN=UP ROUTE=TUN IP=FAIL IP_ADDR=none
ROLLBACK_FAIL ... STATUS=DEGRADED TUN=UP ROUTE=TUN IP=FAIL IP_ADDR=none
```

En ese escenario, la rotacion no era ruido: el sistema estaba intentando
recuperarse de falta de IP publica detectable o conectividad degradada.

## Evidencia de rotaciones sospechosas

Despues de recuperar estado estable, aparecen rotaciones cuyo snapshot inicial ya
estaba sano:

```text
SNAPSHOT STATUS=UP TUN=UP ROUTE=TUN IP=OK IP_ADDR=185.174.159.38
TRY_OK iso='SE' STATUS=UP TUN=UP ROUTE=TUN IP=OK ...
```

Tambien:

```text
SNAPSHOT STATUS=UP TUN=UP ROUTE=TUN IP=OK IP_ADDR=149.88.109.83
TRY_OK iso='FI' STATUS=UP TUN=UP ROUTE=TUN IP=OK ...
```

Si esas ejecuciones no corresponden a rotacion manual, reinicio del timer,
firstboot o update reciente, entonces son rotaciones excesivas desde el punto de
vista de producto.

## Criterio de decision

Una rotacion esta justificada si justo antes aparece alguna de estas condiciones:

- `STATUS=DOWN`
- `TUN=DOWN`
- `ROUTE=DEFAULT` o ruta fuera de `tun0`
- `IP=FAIL`
- `IP_ADDR=none`
- pais no permitido o politica `RUSSIAN_IP`
- auth expirada o invalida
- endpoint fallido o imposibilidad de listar ubicaciones
- varias fallas consecutivas de validacion real

Una rotacion es sospechosa si justo antes todo estaba sano:

- `STATUS=UP`
- `TUN=UP`
- `ROUTE=TUN`
- `IP=OK`
- IP publica valida
- pais permitido
- watchdog registrando `OK`
- dispatcher registrando `NO ACTION`

## Diagnostico actual

Estado mas probable:

1. Hubo un problema real de conectividad o validacion de IP publica.
2. Watchdog/dispatcher/rotate intentaron recuperar, y eso estaba justificado.
3. Al estabilizarse, quedaron rotaciones adicionales por timer/restarts/pruebas.
4. El timer estable vuelve a mostrar proxima ejecucion a 3 horas, lo cual indica
   que no hay una rotacion continua permanente en este momento.

## Riesgo de producto

Aunque las rotaciones extras no destruyen el sistema, degradan la experiencia:

- cambian IP sin necesidad;
- reinician partes internas de AdGuard VPN;
- generan notificaciones;
- pueden cortar sesiones activas;
- hacen que el usuario perciba inestabilidad aunque el tunel este sano.

## Acciones recomendadas

### Accion inmediata: trazabilidad de origen

Agregar al log de `vpn_rotate.sh` un campo `trigger` que indique quien llamo la
rotacion:

- `timer`
- `watchdog`
- `dispatcher`
- `manual`
- `tui`
- `unknown`

Esto permitiria dejar de inferir la causa por correlacion de timestamps.

### Accion inmediata: suavizar rotacion por timer

Revisar si `OnActiveSec=5min` debe mantenerse en `vpn-rotate.timer`.

Opcion conservadora:

- mantener `OnUnitInactiveSec=3h`;
- quitar o aumentar `OnActiveSec=5min`;
- conservar firstboot separado para el arranque.

La razon: `OnActiveSec=5min` es util para que el timer no quede sin siguiente
disparo al reiniciarse, pero puede causar rotaciones extra despues de updates o
reinicios manuales.

### Accion de hardening: no rotar si todo esta sano

Antes de ejecutar una rotacion programada, `vpn_rotate.sh` podria distinguir:

- rotacion programada normal: permitida cada intervalo;
- remediacion forzada: permitida si watchdog/dispatcher detectaron fallo;
- rotacion manual: siempre permitida;
- rotacion temprana tras reinicio del timer: evitar si el estado real ya esta
  sano y la ultima rotacion exitosa fue reciente.

### Accion de UX

Reducir notificaciones para rotaciones internas o de prueba. Notificar solo
cuando:

- cambia exitosamente el pais por rotacion real;
- hay fallo sostenido;
- auth expira;
- el usuario ejecuta una accion manual.

## Conclusion

`logrotate` esta descartado.

`watchdog` parece correcto mientras registra `OK`.

`dispatcher` solo disparo rotacion cuando detecto `DOWN` o `DEGRADED`; despues
de estabilizar, registro `NO ACTION`.

`vpn_rotate` si ejecuto rotaciones reales con el sistema sano. La causa mas
probable no es un fallo del tunel, sino activaciones del timer, reinicios del
timer durante updates/pruebas o falta de trazabilidad para distinguir origen.

La siguiente mejora tecnica deberia ser agregar trazabilidad de origen y revisar
la politica `OnActiveSec=5min` para que la automatizacion no parezca mas agresiva
de lo necesario.
