Herramienta de escaneo de puertos con múltiples tipos de escaneo.
Tipos de escaneo disponibles:
  - TCP Connect: Intento completo de conexión TCP (3-way handshak>
  - SYN (Half-open): Envía SYN y espera SYN/ACK sin completar la >
  - UDP: Envía paquetes UDP y analiza la respuesta ICMP.
  - TCP ACK: Envía paquetes ACK para filtrar puertos con firewall.
  - TCP NULL: Envía paquete sin flags para evadir filtros básicos.
  - TCP XMAS: Enciende flags FIN, PSH y URG simultáneamente

# Port Scan

Escaneador de puertos automatico en Python con multiples tipos de escaneo.

## Caracteristicas
- TCP Connect: escaneo completo 3-way handshake
- SYN (Half-open): escaneo sigiloso
- UDP: deteccion de puertos UDP
- TCP ACK: filtrado de firewalls
- TCP NULL / XMAS: tecnicas de evasión
- Multihilo: escaneo rapido de multiples puertos

## Uso
1. Descarga el ejecutable desde [Releases](https://github.com/Lesternx/port-scan/releases)
2. Ejecuta `Port-Scan.exe`
3. Ingresa la IP objetivo y selecciona el tipo de escaneo

## Tecnologias
- Python 3.14
- Sockets (conexiones de red)
- Threading (multihilo)
- PyInstaller (ejecutable)

## Instalacion desde codigo
```bash
git clone https://github.com/Lesternx/port-scan.git
cd port-scan
pip install -r requirements.txt
python "port scan automatic.py"
```
