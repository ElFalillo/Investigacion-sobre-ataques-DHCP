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
