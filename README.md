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
