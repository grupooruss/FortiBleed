# FortiBleed Defensive Checker Division81 Gruop Oruss

Script defensivo para inventariar exposición de Fortinet/FortiGate/FortiProxy/FortiWeb frente al contexto **FortiBleed**.

> FortiBleed se está usando principalmente para referirse a una exposición/compromiso masivo de credenciales Fortinet, no a una única vulnerabilidad con PoC universal. Este proyecto **no explota**, **no prueba credenciales**, **no descarga configuraciones** y **no intenta bypass de autenticación**.

## Qué valida

- Servicio HTTPS alcanzable.
- Huellas pasivas de Fortinet/FortiGate/FortiProxy/FortiWeb.
- Posible exposición de interfaz administrativa.
- Posible exposición de SSL-VPN.
- Candidatos de versión cuando están visibles en HTML/headers.
- Clasificación básica de riesgo y recomendaciones operativas.
- Exportación JSON y CSV.

## Instalación

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

Un objetivo:

```bash
python fortibleed_check.py -t https://vpn.tudominio.com
```

Lista de objetivos:

```bash
python fortibleed_check.py -f targets.txt --json results.json --csv results.csv
```

Varios puertos comunes:

```bash
python fortibleed_check.py -f targets.txt --ports 443,8443,10443 --timeout 8 --threads 30
```

Certificados internos/self-signed:

```bash
python fortibleed_check.py -f targets.txt --insecure
```

## Formato de `targets.txt`

```txt
vpn.tudominio.com
https://fw.tudominio.com
203.0.113.10:10443
```

## Interpretación rápida

- `critical`: versión visible potencialmente afectada por reglas incluidas. Confirmar con Fortinet PSIRT.
- `high`: Fortinet expuesto con posible administración o SSL-VPN visible.
- `medium`: Fortinet visible, pero sin evidencia clara de login admin/SSL-VPN.
- `low`: servicio alcanzable sin fingerprint Fortinet.
- `unknown`: no alcanzable, timeout o error.

## Recomendaciones mínimas ante positivo

1. Rotar credenciales locales, LDAP/RADIUS y VPN asociadas al equipo.
2. Invalidar sesiones activas donde sea posible.
3. Exigir MFA en VPN y administración.
4. Revisar logs de login, creación de usuarios/admins, cambios de política y accesos anómalos.
5. Restringir administración a VPN, jumpbox o allowlist.
6. Validar versión exacta contra Fortinet PSIRT y actualizar.
7. Confirmar si el activo aparece en checkers de exposición FortiBleed de fuentes confiables.

## Alcance y ética

Ejecutar únicamente sobre activos propios o con autorización explícita. Este script está diseñado para evaluación defensiva y no realiza explotación.

## División81 Equipo de Ethical Hackers del GRUPO ORUSS.
