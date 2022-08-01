<h1 align="center"> HIPS </h1>
HIPS o Host Intrusion Prevention System es un paquete de software instalado que monitorea un solo host en busca de actividad sospechosa mediante el análisis de eventos que ocurren dentro de ese host. En otras palabras, un Sistema de prevención de intrusiones en el host (HIPS) tiene como objetivo detener el malware al monitorear el comportamiento del código. Esto hace posible ayudar a mantener su sistema seguro sin depender de que se agregue una amenaza específica a una actualización de detección.<br>
<br>Instalación:<br>
El software fue diseñado para correr en distribuciones de Linux. Este HIPS fue desarrollado en CentOS 7.<br>
Para la utilización del software, Centos debe tener ciertas aplicaciones instaladas, las siguientes instalaciones deben hacerse desde nuestro usuario propio y ejecutarse como Root solo de ser necesario, ya que algunas instalaciones pueden dañar el sistema operativo si se hacen con un usuario Root.<br>
Primeramente, debemos asegurarnos de que tenemos <b>GCC</b> instalado:<br><br>
sudo yum install gcc<br><br>
Luego, se requiere <b>Python 3</b>. Para instalar Python 3 ejecutamos:<br><br>
sudo yum install python3<br><br>
sudo yum install python3-devel<br><br>
<b>PIP3</b> es necesario para instalar librerías de Python.<br><br>
```
sudo yum install epel-release<br><br>
sudo yum install python3-pip<br><br>
```
<b>Psutil</b> es la librería que se encarga de que Python pueda ejecutar procesos.<br><br>
pip3 install psutil<br><br>
Para almacenar ciertos datos, se requiere una Base de Datos hecha en <b>PostgreSQL</b>. <br><br>
sudo yum install postgresql-client<br><br>
sudo yum install postgres1l-devel<br><br>
sudo systemctl start postgresql<br><br>
Luego de culminar con las instalaciones procedemos a crear la base de datos, el usuario y las tablas.<br><br>
sudo su – postgres<br><br>
Una vez en el Bash escribimos<br><br>
psql<br><br>
Cuando nos encontremos en el Postgres:<br><br>
create database hips_so2;<br><br>
create user nombreusuario with password ‘contrasenha’;<br><br>
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO nombreusuario;<br><br>
\q<br><br>
Y con la última instrucción nos encontramos nuevamente en el Bash. <br>
Para seguir debemos configurar nuestro pg_hba.conf. Esto lo hacemos de la siguiente forma:<br><br>
cd /var/lib/pgsql/data/<br><br>
vi pg_hba.conf<br><br>
Una vez abierto el archivo, lo debemos dejar como muestra la siguiente imagen:<br>
<img src="https://user-images.githubusercontent.com/70355676/182169189-2975e797-5f3a-4ffb-ae29-0f0969f432e7.png" alt="pg_hba"/><br>
En la imagen el ADDRESS que aparece como 192.168.0.24/32 debe ser reemplazado por el IP de la maquina que la utilizará. <br>
Guardamos el archivo y reiniciamos el servicio.<br><br>
exit<br><br>
sudo systemctl restart postgresql<br><br>
sudo su - postgres<br><br>
Ahora entramos a nuestro usuario y base de datos con el siguiente comando:<br><br>
psql -U nombreusuario -h 127.0.0.1 -d hips_so2<br><br>
Una vez adentro, creamos las tablas para la base de datos:<br><br>
create table alarmas (time TIMESTAMP, alarma varchar);<br><br>
create table consumos (nombre varchar(25), cpu real, ram real, maxtime bigint);<br><br>
create table general (mi_ip varchar(15), cola_mail int, email varchar, email_clave varchar, m_ssh int, m_fuzz int, m_mail_envios int, m_cpu_defecto float, m_ram_defecto float);<br><br>
create table md5sum (ruta varchar, hash varchar);<br><br>
create table prevencion (time TIMESTAMP, accion varchar);<br><br>
create table sniffers (nombre varchar(25));<br><br>
Luego procedemos a llenar las tablas con los datos mínimos para poder poner en funcionamiento el sistema. Claramente se pueden llenar todos los campos para un funcionamiento más completo del HIPS.<br><br>
El siguiente insert es con nuestro IP.<br><br>
insert into general (mi_ip) values (‘192.168.0.24’);<br>
insert into sniffers (nombres) values ('prtg'),(solarwinds'),('tcpdump'),('omnipeek'),('manageengine'),('windump'),('wireshark'),('fiddler'),('netresec'),('ethereal'),('capsa');<br><br>
insert into md5sum (ruta) values ('/etc/passwd'),('/etc/shadow');<br><br>
El siguiente insert es con nuestro IP.<br><br>
insert into general (mi_ip, m_mail_envios) values (‘192.168.0.24’, 5);<br><br>
Una vez terminado el proceso de llenar las tablas salimos de SQL:<br><br>
\q<br><br>
Y salimos del bash:<br><br>
exit<br><br>
Ahora creamos algunos directorios y archivos importantes para el funcionamiento del HIPS:<br><br>
sudo cd /etc/postfix<br><br>
sudo touch check_sender_access<br><br>
Luego ejecutamos postman:<br><br>
sudo postman hash:sender_access<br><br>
Luego configuramos el main.cf<br><br>
sudo vi main.cf<br><br>
Simplemente le agregamos al archivo la siguiente línea:<br><br>
smtpd_recipient_restrictions = check_sender_access hash:/etc/postfix/sender_access<br><br>
Guardamos los cambios y reiniciamos el servicio postfix:<br><br>
service postfix restart<br><br>
Luego ejecutamos lo siguiente:<br><br>
sudo mkdir /var/log/hips<br><br>
sudo touch /var/log/hips/alarmas.log<br><br>
sudo touch /var/log/hips/prevencion.log<br><br>
sudo mkdir /etc/cuarentena<br><br>
sudo chmod 664 /etc/cuarentena<br><br>
sudo mkdir /etc/hashes_backup<br><br>
sudo chmod 664 /etc/backup_hashes_files<br><br>
Para realizar los bloqueos con IPTables se debe instalar con:<br><br>
sudo yum install iptables-service<br><br>
Y luego levantamos todos los servicios:<br><br>
sudo service iptables start<br><br>
service postgresql start<br><br>
service sshd start<br><br>
service iptables start<br><br>
<br>En este momento hacemos un git clone de este repositorio y ya estamos listos para ejecutar el HIPS.<br>
