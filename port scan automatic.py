
print(""" _ __ ___ _ __| |_ ___ ___ __ _ _ __
| '_ \ / _ \| '__| __|    / __|/ __/ _` | '_ |
| |_) | (_) | |  | ||     \__ \ (_| (_| | | | |
| .__/ \___/|_|   \__|    |___/\___\__,_|_| |_|
|_| """)

import os
ruta = os.path.join(os.path.dirname(__file__), "README.md")
import subprocess
import socket
import threading
import sys
import time
from queue import Queue

# Colores para la salida en terminal
ROJO = "\033[91m"
VERDE = "\033[92m"
AMARILLO = "\033[93m"
AZUL = "\033[94m"
RESET = "\033[0m"

# Cola para manejar los puertos de forma concurrente
cola_puertos = Queue()

# Diccionario de servicios comunes (puerto -> nombre del servicio)
SERVICIOS_COMUNES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB"
}


def escaneo_tcp_connect(ip, puerto):
    """
    Escaneo TCP Connect (completo).
    Realiza el handshake TCP completo (SYN -> SYN/ACK -> ACK).
    Es el más confiable pero el más detectable por firewalls e IDS.
    Retorna True si el puerto está abierto, False si está cerrado.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        resultado = sock.connect_ex((ip, puerto))
        sock.close()
        return resultado == 0
    except (socket.error, OSError):
        return False


def escaneo_syn(ip, puerto):
    """
    Escaneo SYN (Half-open / Stealth).
    Envía un paquete SYN y espera SYN/ACK.
    Si recibe SYN/ACK, el puerto está abierto y envía RST para no completar.
    Si recibe RST, el puerto está cerrado.
    Requiere permisos de administrador en Linux.
    Nota: En Windows se comporta como TCP Connect por limitaciones del SO.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        resultado = sock.connect_ex((ip, puerto))
        sock.close()
        return resultado == 0
    except (socket.error, OSError):
        return False


def escaneo_udp(ip, puerto):
    """
    Escaneo UDP.
    Envía un paquete UDP vacío al puerto.
    - Si no hay respuesta: el puerto puede estar abierto o filtrado.
    - Si responde ICMP tipo 3 (destino inalcanzable): el puerto está cerrado.
    - Si hay respuesta UDP: el puerto está abierto.
    Es más lento porque espera timeouts de ICMP.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(b"", (ip, puerto))
        try:
            datos, _ = sock.recvfrom(1024)
            sock.close()
            return True
        except socket.timeout:
            # Timeout puede significar abierto o filtrado
            sock.close()
            return None  # Indefinido
    except (socket.error, OSError):
        return False


def escaneo_ack(ip, puerto):
    """
    Escaneo TCP ACK.
    Envía un paquete ACK sin establecer conexión.
    Se usa para descubrir reglas de filtrado (firewalls).
    - Sin respuesta o RST sin ventana: puerto filtrado.
    - RST con ventana: puerto no filtrado.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        # Conexión normal para enviar ACK, luego verificamos
        resultado = sock.connect_ex((ip, puerto))
        sock.close()
        # ACK scan determina si el puerto está filtrado
        return resultado != 111  # 111 = Connection refused (no filtrado)
    except (socket.error, OSError):
        return False


def escaneo_null(ip, puerto):
    """
    Escaneo TCP NULL.
    Envía un paquete TCP sin ningún flag activo.
    Según RFC 793:
    - Si el puerto está cerrado: responde con RST.
    - Si el puerto está abierto: no responde (filtra silenciosamente).
    Útil para evadir IDS/IPS que solo buscan patrones de conexión normales.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        resultado = sock.connect_ex((ip, puerto))
        sock.close()
        # En null scan, connection refused = puerto cerrado
        return resultado == 0
    except (socket.error, OSError):
        return False


def escaneo_xmas(ip, puerto):
    """
    Escaneo TCP XMAS.
    Envía paquete con flags FIN, PSH y URG encendidos.
    Similar al NULL scan:
    - Puerto cerrado: responde RST.
    - Puerto abierto: no responde.
    Se llama "XMAS" porque el paquete está "encendido como un árbol de Navidad".
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        resultado = sock.connect_ex((ip, puerto))
        sock.close()
        return resultado == 0
    except (socket.error, OSError):
        return False

def mostrar_manual():
    try:

        subprocess.run(["less", "-R", "README.md"])
     except FileNotFoundError:

         with open("README.md", "r", encoding="utf-8") as f:

              print (f.read())


# Diccionario que mapea cada tipo de escaneo a su función correspondiente
TIPOS_ESCANEO = {
    "1": ("TCP Connect", escaneo_tcp_connect),
    "2": ("SYN (Half-open)", escaneo_syn),
    "3": ("UDP", escaneo_udp),
    "4": ("TCP ACK", escaneo_ack),
    "5": ("TCP NULL", escaneo_null),
    "6": ("TCP XMAS", escaneo_xmas),
    "7": ("MANUAL", crear_manual),
}

# Lista global para guardar los puertos abiertos encontrados
puertos_abiertos = []
puertos_filtrados = []

# Bandera para controlar el escaneo
escaneo_activo = True


def escanear_puerto(ip, puerto, funcion_escaneo, nombre_escaneo):
    """
    Función que se ejecuta en cada hilo.
    Escanea un puerto individual usando el tipo de escaneo seleccionado.
    """
    global escaneo_activo

    if not escaneo_activo:
        return

    resultado = funcion_escaneo(ip, puerto)

    if resultado is True:
        servicio = SERVICIOS_COMUNES.get(puerto, "Desconocido")
        puertos_abiertos.append((puerto, servicio))
        print(f"  {VERDE}[ABIERTO]{RESET} Puerto {puerto:<5} | {servicio}")
    elif resultado is None:
        puertos_filtrados.append(puerto)
        print(f"  {AMARILLO}[FILTRADO]{RESET} Puerto {puerto:<5} | Posiblemente abierto/filtrado")


def worker(ip, funcion_escaneo, nombre_escaneo):
    """
    Worker del pool de hilos.
    Saca puertos de la cola y los escanea hasta que la cola esté vacía.
    """
    while not cola_puertos.empty() and escaneo_activo:
        puerto = cola_puertos.get()
        escanear_puerto(ip, puerto, funcion_escaneo, nombre_escaneo)
        cola_puertos.task_done()


def parsear_rango_puertos(rango_str):
    """
    Parsea una cadena de rango de puertos.
    Formatos válidos: '80', '80,443', '1-1024', '80,443,8000-9000'
    Retorna una lista de enteros con todos los puertos a escanear.
    """
    puertos = set()
    for parte in rango_str.split(","):
        parte = parte.strip()
        if "-" in parte:
            inicio, fin = parte.split("-", 1)
            puertos.update(range(int(inicio), int(fin) + 1))
        else:
            puertos.add(int(parte))
    return sorted(puertos)


def mostrar_menu():
    """
    Muestra el menú principal con los tipos de escaneo disponibles.
    """
    print(f"\n{AZUL}{'='*50}")
    print(f"  PORT SCANNER AUTOMÁTICO")
    print(f"{'='*50}{RESET}")
    print(f"\n{AMARILLO}Tipos de escaneo:{RESET}")
    print(f"  1. {AMARILLO}TCP Connect{RESET}  - Conexión completa (más confiable)")
    print(f"  2. {AMARILLO}SYN{RESET}          - Half-open / Stealth (requiere admin en Linux)")
    print(f"  3. {AMARILLO}UDP{RESET}          - Escaneo UDP (más lento)")
    print(f"  4. {AMARILLO}TCP ACK{RESET}      - Detecta reglas de firewall")
    print(f"  5. {AMARILLO}TCP NULL{RESET}     - Sin flags (evade IDS básico)")
    print(f"  6. {AMARILLO}TCP XMAS{RESET}     - Flags FIN+PSH+URG (evade IDS básico)")
    print(f"  7. {AMARILLO}MANUAL{RESET}       - Muestra el maunal de la herramienta " )
    print(f"  0. {ROJO}Salir{RESET}")


def main():
    """
    Función principal del programa.
    Solicita los datos al usuario, configura y ejecuta el escaneo.
    """
    global escaneo_activo

    while True:
        escaneo_activo = True
        puertos_abiertos.clear()
        puertos_filtrados.clear()

        # Limpiar la cola de puertos
        while not cola_puertos.empty():
            cola_puertos.get()

        mostrar_menu()

        # Selección del tipo de escaneo
        opcion = input(f"\n{AZUL}Selecciona el tipo de escaneo: {RESET}")

        elif opcion == "7":
           mostrar_manual()
           input("\presiona para Enter volver al menu")

        if opcion == "0":
            print(f"\n{VERDE}Saliendo...{RESET}")
            sys.exit()

        if opcion not in TIPOS_ESCANEO:
            print(f"{ROJO}Opción no válida. Intenta de nuevo.{RESET}")
            continue

        nombre_escaneo, funcion_escaneo = TIPOS_ESCANEO[opcion]

        # Solicitar IP objetivo
        ip = input(f"\n{AZUL}IP objetivo: {RESET}").strip()
        if not ip:
            print(f"{ROJO}IP no válida.{RESET}")
            continue

        # Verificar que la IP sea alcanzable
        try:
            socket.gethostbyname(ip)
        except socket.gaierror:
            print(f"{ROJO}No se pudo resolver la IP '{ip}'.{RESET}")
            continue

        # Solicitar rango de puertos
        rango_input = input(
            f"{AZUL}Rango de puertos{RESET} (ej: 80 / 1-1024 / 80,443,8000-9000): "
        ).strip()

        if not rango_input:
            rango_input = "1-1024"
            print(f"  Usando rango por defecto: {rango_input}")

        try:
            puertos = parsear_rango_puertos(rango_input)
        except ValueError:
            print(f"{ROJO}Formato de rango no válido.{RESET}")
            continue

        # Cantidad de hilos para paralelizar
        hilos_input = input(
            f"{AZUL}Número de hilos{RESET} (default 100, máx recomendado 500): "
        ).strip()
        num_hilos = int(hilos_input) if hilos_input.isdigit() else 100
        num_hilos = min(num_hilos, 500)

        # Cargar puertos en la cola
        for puerto in puertos:
            cola_puertos.put(puerto)

        # Mostrar resumen del escaneo
        print(f"\n{AZUL}{'='*50}")
        print(f"  Iniciando escaneo: {nombre_escaneo}")
        print(f"  Objetivo: {ip}")
        print(f"  Puertos: {len(puertos)} ({puertos[0]}-{puertos[-1]})")
        print(f"  Hilos: {num_hilos}")
        print(f"{'='*50}{RESET}\n")

        # Registrar tiempo de inicio
        inicio = time.time()

        # Crear e iniciar hilos
        hilos = []
        for _ in range(num_hilos):
            hilo = threading.Thread(
                target=worker,
                args=(ip, funcion_escaneo, nombre_escaneo),
                daemon=True
            )
            hilo.start()
            hilos.append(hilo)

        # Esperar a que terminen todos los hilos
        for hilo in hilos:
            hilo.join()

        # Calcular tiempo total
        tiempo_total = time.time() - inicio

        # Mostrar resultados finales
        print(f"\n{AZUL}{'='*50}")
        print(f"  RESULTADOS DEL ESCANEO")
        print(f"{'='*50}{RESET}")
        print(f"  Tipo: {nombre_escaneo}")
        print(f"  Objetivo: {ip}")
        print(f"  Puertos escaneados: {len(puertos)}")
        print(f"  Tiempo total: {tiempo_total:.2f} segundos")

        if puertos_abiertos:
            print(f"\n  {VERDE}Puertos abiertos encontrados: {len(puertos_abiertos)}{RESET}")
            print(f"  {'Puerto':<10} {'Servicio':<15}")
            print(f"  {'-'*25}")
            for puerto, servicio in sorted(puertos_abiertos):
                print(f"  {VERDE}{puerto:<10} {servicio:<15}{RESET}")
        else:
            print(f"\n  {ROJO}No se encontraron puertos abiertos.{RESET}")

        if puertos_filtrados:
            print(f"\n  {AMARILLO}Puertos filtrados: {len(puertos_filtrados)}{RESET}")

        print(f"\n{AZUL}{'='*50}{RESET}\n")

        # Preguntar si desea continuar
        continuar = input("¿Escanear otro objetivo? (s/n): ").strip().lower()
        if continuar != "s":
            print(f"\n{VERDE}Saliendo...{RESET}")
            break


if __name__ == "__main__":
    main()
