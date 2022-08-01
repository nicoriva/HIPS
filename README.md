<h1 align="center"> HIPS </h1>
HIPS o Host Intrusion Prevention System es un paquete de software instalado que monitorea un solo host en busca de actividad sospechosa mediante el análisis de eventos que ocurren dentro de ese host. En otras palabras, un Sistema de prevención de intrusiones en el host (HIPS) tiene como objetivo detener el malware al monitorear el comportamiento del código. Esto hace posible ayudar a mantener su sistema seguro sin depender de que se agregue una amenaza específica a una actualización de detección.<br>
<br>Instalación:<br>
El software fue diseñado para correr en distribuciones de Linux. Este HIPS fue desarrollado en CentOS 7.<br>
Para la utilización del software, Centos debe tener ciertas aplicaciones instaladas, las siguientes instalaciones deben hacerse desde nuestro usuario propio y ejecutarse como Root solo de ser necesario, ya que algunas instalaciones pueden dañar el sistema operativo si se hacen con un usuario Root.<br>
Primeramente, debemos asegurarnos de que tenemos <b>GCC</b> instalado:<br>
> sudo yum install gcc<br>
Luego, se requiere <b>Python 3</b>. Para instalar Python 3 ejecutamos:<br>
> sudo yum install python3<br>
> sudo yum install python3-devel<br>
<b>PIP3</b> es necesario para instalar librerías de Python.<br>
> sudo yum install epel-release<br>
> sudo yum install python3-pip<br>
<b>Psutil</b> es la librería que se encarga de que Python pueda ejecutar procesos.<br>
> pip3 install psutil<br>
Para almacenar ciertos datos, se requiere una Base de Datos hecha en <b>PostgreSQL</b>. <br>
> sudo yum install postgresql-client<br>
> sudo yum install postgres1l-devel<br>
> sudo systemctl start postgresql<br>
Luego de culminar con las instalaciones procedemos a crear la base de datos, el usuario y las tablas.<br>
> sudo su – postgres<br>
Una vez en el Bash escribimos<br>
> psql<br>
Cuando nos encontremos en el Postgres:<br>
> create database hips_so2;<br>
> create user nombreusuario with password ‘contrasenha’;<br>
> GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO nombreusuario;<br>
> \q<br>
Y con la última instrucción nos encontramos nuevamente en el Bash. <br>
Para seguir debemos configurar nuestro pg_hba.conf. Esto lo hacemos de la siguiente forma:<br>
> cd /var/lib/pgsql/data/<br>
> vi pg_hba.conf<br>
Una vez abierto el archivo, lo debemos dejar como muestra la siguiente imagen:<br>
<img src="https://user-images.githubusercontent.com/70355676/182169189-2975e797-5f3a-4ffb-ae29-0f0969f432e7.png" alt="pg_hba"/><br>
En la imagen el ADDRESS que aparece como 192.168.0.24/32 debe ser reemplazado por el IP de la maquina que la utilizará. <br>
Guardamos el archivo y reiniciamos el servicio.<br>

> exit<br>
> sudo systemctl restart postgresql<br>
> sudo su - postgres<br>
Ahora entramos a nuestro usuario y base de datos con el siguiente comando:<br>
> psql -U nombreusuario -h 127.0.0.1 -d hips_so2<br>
Una vez adentro, creamos las tablas para la base de datos:<br>
> create table alarmas (time TIMESTAMP, alarma varchar);<br>
> create table consumos (nombre varchar(25), cpu real, ram real, maxtime bigint);<br>
> create table general (mi_ip varchar(15), cola_mail int, email varchar, email_clave varchar, m_ssh int, m_fuzz int, m_mail_envios int, m_cpu_defecto float, m_ram_defecto float);<br>
> create table md5sum (ruta varchar, hash varchar);<br>
> create table prevencion (time TIMESTAMP, accion varchar);<br>
> create table sniffers (nombre varchar(25));<br>
Luego procedemos a llenar las tablas con los datos mínimos para poder poner en funcionamiento el sistema. Claramente se pueden llenar todos los campos para un funcionamiento más completo del HIPS.<br>
El siguiente insert es con nuestro IP.<br>
> insert into general (mi_ip) values (‘192.168.0.24’);
> insert into sniffers (nombres) values ('prtg'),(solarwinds'),('tcpdump'),('omnipeek'),('manageengine'),('windump'),('wireshark'),('fiddler'),('netresec'),('ethereal'),('capsa');<br>
> insert into md5sum (ruta) values ('/etc/passwd'),('/etc/shadow');<br>
El siguiente insert es con nuestro IP.<br>
> insert into general (mi_ip, m_mail_envios) values (‘192.168.0.24’, 5);<br>
Una vez terminado el proceso de llenar las tablas salimos de SQL:<br>
> \q<br>
Y salimos del bash:<br>
> exit<br>
Ahora creamos algunos directorios y archivos importantes para el funcionamiento del HIPS:<br>
> sudo cd /etc/postfix<br>
> sudo touch check_sender_access<br>
Luego ejecutamos postman:<br>
> sudo postman hash:sender_access<br>
Luego configuramos el main.cf<br>
> sudo vi main.cf<br>
Simplemente le agregamos al archivo la siguiente línea:<br>
> smtpd_recipient_restrictions = check_sender_access hash:/etc/postfix/sender_access<br>
Guardamos los cambios y reiniciamos el servicio postfix:<br>
> service postfix restart<br>
Luego ejecutamos lo siguiente:<br>
> sudo mkdir /var/log/hips<br>
> sudo touch /var/log/hips/alarmas.log<br>
> sudo touch /var/log/hips/prevencion.log<br>
> sudo mkdir /etc/cuarentena<br>
> sudo chmod 664 /etc/cuarentena<br>
> sudo mkdir /etc/hashes_backup<br>
> sudo chmod 664 /etc/backup_hashes_files<br>
Para realizar los bloqueos con IPTables se debe instalar con:<br>
> sudo yum install iptables-service<br>
Y luego levantamos todos los servicios:<br>
> sudo service iptables start<br>
> service postgresql start<br>
> service sshd start<br>
> service iptables start<br>
<br>En este momento hacemos un git clone de este repositorio y ya estamos listos para ejecutar el HIPS.<br>
