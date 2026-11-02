Herramienta de escaneo de puertos co                                  │ n múltiples tipos de escaneo.
   2 + │ Tipos de escaneo disponibles:                                     3 + │   - TCP Connect: Intento completo de
       │  conexión TCP (3-way handshak>                                    4 + │   - SYN (Half-open): Envía SYN y esp
       │ era SYN/ACK sin completar la >
   5 + │   - UDP: Envía paquetes UDP y analiz
       │ a la respuesta ICMP.                                              6 + │   - TCP ACK: Envía paquetes ACK para
       │  filtrar puertos con firewall.
   7 + │   - TCP NULL: Envía paquete sin flag                                  │ s para evadir filtros básicos.
   8 + │   - TCP XMAS: Enciende flags FIN, PS
       │ H y URG simultáneamente
   9 + │
  10   │ # Port Scan
  11   │
  12   │ Escaneador de puertos automatico en
       │ Python con multiples tipos de escane
       │ o.
  13   │
  14   │ ## Caracteristicas
  15   │ - TCP Connect: escaneo completo 3-wa
       │ y handshake
  16   │ - SYN (Half-open): escaneo sigiloso
  17   │ - UDP: deteccion de puertos UDP
  18   │ - TCP ACK: filtrado de firewalls
  19   │ - TCP NULL / XMAS: tecnicas de evasi
       │ ón
  20   │ - Multihilo: escaneo rapido de multi
       │ ples puertos
  21   │
  22   │ ## Uso
  23   │ 1. Descarga el ejecutable desde [Rel
       │ eases](https://github.com/Lesternx/p
       │ ort-scan/releases)
  24   │ 2. Ejecuta `Port-Scan.exe`
  25   │ 3. Ingresa la IP objetivo y seleccio
       │ na el tipo de escaneo
  26   │
  27   │ ## Tecnologias
  28   │ - Python 3.14
  29   │ - Sockets (conexiones de red)
  30   │ - Threading (multihilo)
  31   │ - PyInstaller (ejecutable)
  32   │
  33   │ ## Instalacion desde codigo
  34   │ ```bash
  35   │ git clone https://github.com/Lestern
       │ x/port-scan.git
  36   │ cd port-scan
  37   │ pip install -r requirements.txt
  38   │ python "port scan automatic.py"
