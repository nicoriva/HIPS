#Imports
######################################################

import random
import string
import os
import subprocess
import json
import time
from datetime import datetime
import psutil
import socket
import psycopg2
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from getpass import getpass

#Globales
######################################################

#Usuario para conectarse al postgres
USUARIO_BD = 'postgres'

#Contasenha para el usuario de postgres anterior
CLAVE_BD = ''

#Nombre de la base de datos
BASE_DATOS = 'hips_so2'

#Archivos enviados a cuarentena
M_CUARENTENA = ''

#Ruta a la que se mandan los archivos en cuarentena
RUTA_CUARENTENA = '/etc/cuarentena'

#Flotante con el porcentaje maximo de CPU que un proceso puede consumir
M_CPU = 90.000

#Flotante con el porcentaje maximo de memoria RAM que un proceso puede consumir
M_RAM = 90.000

#Ruta donde se guardan copias de archivos con hashes, es como un auxiliar
RUTA_HASHES = '/etc/hashes_backup'

#Contiene la contrasenha del correo que envia las alertas
CLAVE_MAIL = ''

#Direccion email a la que se mandan las alertas
EMAIL = ''

#FUNCIONES RECURRENTES
######################################################

#Envia correos a la direccion que indiquemos, no funciona!
#Parametros: Correo al cual enviar, el asunto del correo, el contenido en el body
#Retorno: No retorna

def send_email(email,asunto,body):
	global CLAVE_MAIL
	global EMAIL
	direccion_mail = EMAIL
	servidor = smtplib.SMTP('smtp.gmail.com', 587)
	servidor.starttls()
	servidor.login(direccion_mail,CLAVE_MAIL)

	mensaje = MIMEMultipart()
	mensaje['From']=direccion_mail
	mensaje['To']=email
	mensaje['Subject']=asunto
	mensaje.attach(MIMEText(body,'plain'))
	servidor.send_message(mensaje)
	del mensaje
	servidor.quit()

#Mueve archivos a la ruta de cuarentena, /etc/cuarentena
#Parametros: Ruta /etc/cuarentena
#Retorno: No retorna

def mv_cuarentena(s_file):
	global RUTA_CUARENTENA
	p =subprocess.Popen("mv "+s_file+" "+RUTA_CUARENTENA, stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()

#Bloquea IPs con el IPTables
#Parametros: IP que se bloqueara
#Retorno: No retorna

def bloquear_ip(ip):
	p =subprocess.Popen("iptables -I INPUT -s "+ip+" -j DROP", stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()

	p =subprocess.Popen("service iptables save", stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()

#Mata un proceso
#Parametros: PID del proceso que se quiere matar
#Retorno: No retorna

def proceso_kill9(pid):
	#p =subprocess.Popen("kill -9 "+str(pid), stdout=subprocess.PIPE, shell=True)
	#(output, err) = p.communicate()
	os.system('kill -9 '+str(pid))

#Bloquea un correo mandandolo a la lista negra del postfix
#Parametros: Email que se desea agregar a la lista negra.
#Retorno: No retorna

def bloquear_email(email):#verificar si es que no esta
	p =subprocess.Popen("echo \""+email+" REJECT\">>/etc/postfix/sender_access", stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	p =subprocess.Popen("postmap /etc/postfix/sender_access", stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()

#Agrega en /var/log/hips/alarmas.log una alarma
#Parametros: Log que se agrega, el tipo de alarma y el IP de quien la genero
#Retorno: No retorna

def agregar_log_alarmas(info, tipo_alarma,ip):
	global USUARIO_BD
	global CLAVE_BD
	global BASE_DATOS

	if ip == '':
		ip = "No hay IP"
	momento = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	informacion_log = ''+momento+" :: "+tipo_alarma+" :: "+ip+" :: "+info
	p =subprocess.Popen("echo \""+informacion_log+"\">>/var/log/hips/alarmas.log", stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	
	try:
		conn = psycopg2.connect(database=BASE_DATOS, user=USUARIO_BD, password=CLAVE_BD)
		cursor = conn.cursor()
		insert_bd = "INSERT INTO alarmas (time,alarma) VALUES (TO_TIMESTAMP('"+momento+"','YYYY-MM-DD HH24:MI:SS'),'"+informacion_log+"');"
		#print (insert_bd)
		cursor.execute(insert_bd)
		conn.commit()
		cursor.close()
		conn.close()	
	except:
		print("\n\n\nOcurrio un error, verifique las credenciales.\n\n\n")
	
#Agrega en /var/log/hips/prevencion.log la medida de prevencion que se tomo
#Parametros: La medida de prevencion y el motivo
#Retorno: No retorna

def agregar_log_prevencion(info, motivo):
	global USUARIO_BD
	global CLAVE_BD
	global BASE_DATOS
	
	momento = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	informacion_log = ''+momento+" :: "+info+" :: Reason --> "+motivo
	p =subprocess.Popen("echo \""+informacion_log+"\">>/var/log/hips/prevencion.log", stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()

	try:
		conn = psycopg2.connect(database=BASE_DATOS, user=USUARIO_BD, password=CLAVE_BD)
		cursor = conn.cursor()
		insert_bd = "INSERT INTO prevencion (time,accion) VALUES (TO_TIMESTAMP('"+momento+"','YYYY-MM-DD HH24:MI:SS'),'"+informacion_log+"');"
		cursor.execute(insert_bd)
		conn.commit()
		cursor.close()
		conn.close()
	except:
		print("\n\n\nOcurrio un error, verifique las credenciales.\n\n\n")

#Realiza la conexion con la base de datos y efectua ciertos querys necesarios para algunas funciones
#Parametros: No recibe parametros
#Retorno: informacion_bd (lista)

def conexion_bd():
	global USUARIO_BD #Usuario para conectarse al postgres
	global CLAVE_BD #Contasenha para el usuario de postgres anterior
	global BASE_DATOS #Nombre de la base de datos
	global EMAIL #Direccion email a la que se mandan las alertas
	global CLAVE_MAIL #Contiene la contrasenha del correo que envia las alertas
	global M_CPU #Flotante con el porcentaje maximo de CPU que un proceso puede consumir
	global M_RAM #Flotante con el porcentaje maximo de memoria RAM que un proceso puede consumir

	#Informacion de la base de datos: sniffers, tamanho de la cola del mail, mi IP, intentos de fuzzing, maximo ssh y maximo de envios de email, no estan las variables globales
	informacion_bd = {'sniffers':'', 'consumos':[], 'mi_ip':'', 'cola_mail' : -1, 'md5sum': [], 'm_ssh' : -1, 'm_fuzz' : -1, 'm_mail_envios' : -1}
	verificado=False #Bandera
	while(verificado is not True): #Intenta hasta lograr conectarse a la base de datos
		print("Ingrese la informacion requerida\n") #Instruccion para el usuario
		USUARIO_BD = input("Nombre de usuario:  ") #Entrada del nombre de usuario para la base de datos, no necesariamente es Postgres
		CLAVE_BD = getpass("Contrasenha:  ") #Entrada de la contrasenha pero con getpass para no mostrar lo que escribe
		try: #Bloque try para realizar el intento de conexion con los datos anteriores
			conn = psycopg2.connect(database=BASE_DATOS, user=USUARIO_BD, password=CLAVE_BD) #Usa psycopg2 para conectarse a la base de datos con la informacion anterior
			verificado = True #Si lo logra cambia la bandera de verificado para salir del While
		except: #Except que lanza un mensaje de error a quien intente conectarse, esto sucede si fracasa el try
			print("\n\n\nDatos incorrectos. Ingreselos nuevamente\n\n\n") #Mensaje para el usuario
	
	cursor = conn.cursor() #Metodo para ejecutar comandos de PostgreSQL desde Python
	sniffers_select = "SELECT * FROM sniffers" #String con query para traer todos los sniffers de la tabla
	consumos_select = "SELECT * FROM consumos" #String con query para traer todos los datos que nos interesan para limitar el consumo
	general_select = "SELECT * FROM general" #String con query para traer toda la informacion sobre nuestra ip, maximos de ciertas cosas, etc.
	md5sum_select = "SELECT hash FROM md5sum" #String con query para traer la columna de Hashes de la tabla md5sum, la informacion trae el hash y la ruta
	md5sum_select_null = "SELECT ruta FROM md5sum WHERE hash IS NULL OR hash=\'\'" #Trae la ruta de la tabla md5sum si es que no hay datos en la columna Hash
	
	cursor.execute(sniffers_select) #Ejecuta query
	data = cursor.fetchall() #Obtiene todas las tuplas restantes de la última declaración ejecutada de una tabla
	data_str = '' #String vacio para usar de acumulador
	for row in data: #For que se repite hasta terminar todas las tuplas del fetchall
		data_str+=row[0]+'|' #Va agregando los sniffers en el string vacio y los separa por un |
	
	if(data_str != ''):	#Si el string con los sniffers no esta vacio, sigue
		informacion_bd['sniffers']=data_str[:-1] #Guarda los sniffers en la lista de informacion y corta la cadena para omitir el último carácter

	cursor.execute(consumos_select) #Ejecuta query
	data = cursor.fetchall() #Obtiene todas las tuplas restantes de la última declaración ejecutada de una tabla
	data_list = [] #array de datos vacio
	for row in data: #For que se repite hasta terminar todas las tuplas del fetchall
		data_list.append({'nombre':row[0], 'maximo_cpu':row[1], 'maximo_ram':row[2], 'maximo_ejecucion':row[3]}) #Agrega al array, por fila, el nombre y los maximos de consumo y duracion
		
	informacion_bd['consumos']=data_list #Agrega a la parte de consumos la informacion anterior
	
	cursor.execute(general_select) #Ejecuta query
	data = cursor.fetchall() #Obtiene todas las tuplas restantes de la última declaración ejecutada de una tabla
	for row in data: #For que se repite hasta terminar todas las tuplas del fetchall
		informacion_bd['mi_ip'] = row[0] #Guarda el IP que esta en la primera fila dentro del array de informacion
		informacion_bd['cola_mail'] = row[1] #Guarda la cola disponible para el mail que esta en la segunda fila de data
		EMAIL = row[2] #Guarda en la variable global la tercera fila de data que contiene el mail
		CLAVE_MAIL = row[3] #Guarda en la cuarta fila la clave del email
		informacion_bd['m_ssh'] = row[4] #Guarda el maximo de intentos de conexion por ssh 
		informacion_bd['m_fuzz'] = row[5] #Guarda el maximo de intentos de fuzzing
		informacion_bd['m_mail_envios'] = row[6] #Guarda el maximo de envios de email
		M_CPU = row[7] #Guarda el maximo de consumo de CPU
		M_RAM = row[8] #Guarda el maximo de consumo de memoria RAM

	cursor.execute(md5sum_select_null) #Ejecuta query
	data = cursor.fetchall() #Obtiene todas las tuplas restantes de la última declaración ejecutada de una tabla
	actualizado = False #Bandera para saber si esta actualizada la tabla
	for row in data: #For que se repite hasta terminar todas las tuplas del fetchall
		hash_update = 'UPDATE md5sum SET hash=\''+creador_hashesmd5(row[0])+'\' WHERE ruta=\''+row[0]+'\';' #Actualiza la tabla con un nuevo hash en la ruta del archivo modificado
		cursor.execute(hash_update) #Ejecuta query anterior
		actualizado = True #Cambia la bandera
	conn.commit() #Realiza el commit para SQL
	
	if(actualizado is not True): #Si la bandera no cambio, sigue
		cursor.execute(md5sum_select) #Ejecuta query
		data = cursor.fetchall() #Obtiene todas las tuplas restantes de la última declaración ejecutada de una tabla
		data_list = [] #Lista vacia
		for row in data: #For que se repite hasta terminar todas las tuplas del fetchall
			data_list.append(row[0]) #Agrega al final la primera fila en data_list
			
		informacion_bd['md5sum']=data_list #Guarda en md5sum de informacion la lista anterior
			
	else: #Si la bandera cambio, sigue
		cursor.close() #Cierra la ejecucion de querys
		conn.close() #Cierra la conexion
		conn = psycopg2.connect(database=BASE_DATOS, user=USUARIO_BD, password=CLAVE_BD) #Nueva conexion a la base de datos
		cursor = conn.cursor() #Metodo para ejecutar comandos de PostgreSQL desde Python
		
		cursor.execute(md5sum_select) #Ejecuta query
		data = cursor.fetchall() ##Obtiene todas las tuplas restantes de la última declaración ejecutada de una tabla
		data_list = [] #Lista vacia
		for row in data: #For que se repite hasta terminar todas las tuplas del fetchall
			data_list.append(row[0]) #Agrega a la lista la primera fila
			
		informacion_bd['md5sum']=data_list #Guarda en md5sum de informacion la lista anterior

	cursor.close() #Cierra la ejecucion de querys
	conn.close()	#Cierra la ejecucion de querys
	return informacion_bd #Retorna la lista con toda la informacion sobre la base de datos
		
#Verifica si se supero el maximo de la cola de mails, no funciona!
#Parametros: Tamanho maximo de mails que puede tener la cola
#Retorno: No retorna

#Funciones propias del HIPS
######################################################

def verificar_cola_mail(M_MAIL):
	global EMAIL #Direccion email a la que se mandan las alertas
	p = subprocess.Popen("mailq", stdout=subprocess.PIPE, shell=True) #Ejecuta el proceso mailq de Linux
	(output, err) = p.communicate() #
	mail_list = output.decode("utf-8").splitlines()
	if M_MAIL >-1 and len(mail_list) > M_MAIL:
		p = subprocess.Popen("se detuvo el servicio postfix ", stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
		mensaje = "Se alcanzo el limite de "+M_MAIL+" mails."
		prevencion = "Se detuvo el servicio Postfix"
		agregar_log_alarmas(mensaje , "Ataque posible de DoS/DDoS",'')
		agregar_log_prevencion(prevencion, "Ataque posible de DoS/DDoS")
		print("La cola del mail esta llena. Ataque posible de DoS/DDoS.\n")
		
#Verifica si se enviaron demasiados correos desde una misma direccion
#Parametros: Cantidad maxima de envios
#Retorno: No retorna

def verificar_smtp_maillog(m_envios):
	cont = dict() #Diccionario que actua de contador
	p = subprocess.Popen("cat  /var/log/maillog.txt | grep -i authid", stdout=subprocess.PIPE, shell=True) #Realiza el proceso cat en linux que muestra linea por linea la informacion de un documento segun su authid
	(output, err) = p.communicate() #Al ejecutar el proceso trae la informacion que genera en el output y un error
	ret_msg = output.decode("utf-8") #Decodifica esa informacion en utf-8 y la guarda en un return
	body = '' #String auxiliar vacio
	for linea in ret_msg.splitlines(): #For que se repite la cantidad de lineas que tenga el return, splitlines separa el output cuando encuentra un /n
		email = linea.split(' ')[-3] #Separa el string linea cuando encuentra un espacio, indexando desde el antepenultimo elemento por el -3
		email = email[7:-1] #Saca el authid= y la coma que esta al final
		if email in cont: #
			cont[email]+=1 #Le suma 1 al contador por cada email
			if cont[email] == m_envios: #Si el contador es igual al maximo permitido
				body = body+email+"\n" #Se agrega el email al string auxiliar
				bloquear_email(email) #Bloquea el email
				#
		else:
			cont[email] = 1 #Pone en 1 el contador
	if body != '' : #Si el string auxiliar no esta vacio
		body = body + " enviaron " + str(m_envios)+" correos. Los emails seran bloqueados " #Utiliza el mismo string para generar un mensaje
	for key in cont: #Ejecuta la cantidad de veces del contador
		aux = cont[key] #Numero de correos en una variable auxiliar
		if aux >= m_envios and m_envios >=0: #Si el numero de correos es igual o mayor al maximo y el maximo es igual o mayor que 0, sigue
			agregar_log_alarmas(str(aux)+" emails enviados por "+key, "ataque SMTP",'') #Agrega al log de alarmas el mensaje de log
			agregar_log_prevencion(key+" bloqueado en postfix", "ataque SMTP") #Agrega al log de prevencion el mensaje de log
			print("Posible ataque SMPT usando: "+key+" . Bloqueado en: /etc/postfix/sender_access\n") #Imprime en pantalla el aviso del problema

#Verifica si ocurrieron muchos errores de autenticacion en un mismo usuario
#Parametros: Cantidad maxima de envios
#Retorno: No retorna

def verificar_smtp_messages(m_envios):
	cont = dict() #Diccionario que actua de contador
	p = subprocess.Popen("cat  /var/log/messages.txt | grep -i \"[service=smtp]\" | grep -i \"auth failure\"", stdout=subprocess.PIPE, shell=True) #Realiza un proceso de linux cat para mostrar messages segun el servicio smtp y si es un auth failure
	(output, err) = p.communicate() #Al ejecutar el proceso trae la informacion que genera en el output y un error
	ret_msg = output.decode("utf-8") #Decodifica esa informacion en utf-8 y la guarda en un return
	body = '' #String auxiliar vacio
	nueva_clave = '' #String para nueva clave vacio
	for linea in ret_msg.splitlines(): #For que se repite la cantidad de lineas que tenga el return, splitlines separa el output cuando encuentra un /n
		usuario = linea.split('=')[1] #Trae un string diviendo la linea del cat segun el =, en el ejemplo por el profesor trae condorito] [service
		usuario = usuario.split(']')[0] #Trae el usuario al encontrar el ] que lo separa en el log, en este caso condorito esta antes de ]
		if usuario in cont:
			cont[usuario]+=1 #Agrega 1 al contador
			if cont[usuario] == m_envios: #Si el contador es igual al maximo de envios
				body = body+usuario+"\n" #Agrega al string auxiliar el usuario
				clave = contrasenha_aleatoria(random.randint(20,30)) #Realiza una contrasenha aleatoria con instrucciones random integer entre 20 y 30
				nueva_clave = nueva_clave + usuario + " :: " + clave #Agrega a un acumulador la nueva clave con el usuario con el formato de log
				p = subprocess.Popen("echo \""+usuario+":"+clave+"\" | chpasswd 2> /dev/null", stdout=subprocess.PIPE, shell=True) #Realiza el proceso echo de linux y le cambia la contrasenha
				(output, err) = p.communicate() #Al ejecutar el proceso trae la informacion que genera en el output y un error
		else:
			cont[usuario] = 1 #Pone el cont en 1
	if body != '' : #Si el auxiliar no esta vacio
		body = body + " obtuvo " + str(m_envios)+" errores de autenticacion. Las contrasenhas de esos usuarios fueron cambiados a: usuario :: nueva_clave\n"+nueva_clave #utiliza el auxiliar para hacer un mensaje
	for key in cont: #Ejecuta tantas veces como el contador
		aux = cont[key] 
		if aux >= m_envios and m_envios >=0: 
			agregar_log_alarmas(str(aux)+" errores de autenticacion para "+key, "ataque SMTP",'') #Agrega el log a alarmas
			print(str(aux)+" errores de autenticacion para: "+key+"\n") #Muestra en pantalla un error
		print(body+"\n-------------------------------------------------\n\n")

#Verifica si ocurrieron muchos errores de autenticacion en un mismo usuario pero en secure
#Parametros: Cantidad maxima de envios
#Retorno: No retorna

def verificar_smtp_secure(m_envios):
	cont = dict()
	p = subprocess.Popen("cat  /var/log/secure.txt | grep -i \"(smtp:auth)\" | grep -i \"authentication failure\"", stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	ret_msg = output.decode("utf-8")
	body = ''
	nueva_clave = ''
	for linea in ret_msg.splitlines():
		usuario = linea.split('=')[-1] #conseguimos el usuarionombre condorito
		if usuario in cont:
			cont[usuario]+=1
			if cont[usuario] == m_envios:
				body = body+usuario+"\n"

				clave = contrasenha_aleatoria(random.randint(20,30))
				nueva_clave = nueva_clave + usuario + " :: " + clave
				p = subprocess.Popen("echo \""+usuario+":"+clave+"\" | chpasswd 2> /dev/null", stdout=subprocess.PIPE, shell=True)
				(output, err) = p.communicate()
		else:
			cont[usuario] = 1
	if body != '' :
		body = body + " obtuvo " + str(m_envios)+" errores de autenticacion. Las contrasenhas de esos usuarios fueron cambiados a: usuario :: nueva_clave\n"+nueva_clave

	for key in cont:
		aux = cont[key]
		if aux >= m_envios and m_envios >=0:
			agregar_log_alarmas(str(aux)+" errores de autenticacion para "+key, "ataque SMTP",'')
			print(str(aux)+" errores de autenticacion para: "+key+"\n")
		print(body+"\n-------------------------------------------------\n\n")

#Verifica si ocurrio un ataque al smtp, lo hace ejecutando las 3 funciones del smtp
#Parametros: Cantidad maxima de envios
#Retorno: No retorna

def verificar_smtp_attack(m_envios):
	verificar_smtp_maillog(m_envios)
	verificar_smtp_messages(m_envios)
	verificar_smtp_secure(m_envios)

#Genera una contrasenha aleatoria
#Parametros: 1
#Retorno: No retorna
def contrasenha_aleatoria(l):
	letters = string.ascii_letters + "1234567890!@#$%^&*()-_=+"
	new_str = ''.join(random.choice(letters) for i in range(l))
	return (new_str)

#Verifica dispositivos en modo promiscuo, dependiendo de si siguen o no en ese modo
#Parametros: La ruta con los dispositivos, /var/log/secure
#Retorno: No retorna

def verificar_promiscuos(RUTA_LOG ):
	prom_left = subprocess.Popen("cat "+RUTA_LOG+" | grep \"left promisc\"", stdout=subprocess.PIPE, shell=True)
	(output_off, err) = prom_left.communicate()
	datos_left = output_off.decode("utf-8")
	array_left = datos_left.splitlines()
	cantidad_left = len(array_left)
	
	prom_adentro = subprocess.Popen("cat "+RUTA_LOG+" | grep \"entered promisc\"", stdout=subprocess.PIPE, shell=True)
	(output_on, err) = prom_adentro.communicate()
	datos_adentro = output_on.decode("utf-8")
	array_adentro = datos_adentro.splitlines()
	cantidad_adentro = len(array_adentro)
	body = ''
	if cantidad_left != cantidad_adentro:
		union_left_adentro = []
		disp_promiscuos = []
		for linea in array_left:
			union_left_adentro.append(linea.split()[-4])
		for linea in array_adentro:
			union_left_adentro.append(linea.split()[-4])
		
		cont = {i:union_left_adentro.count(i) for i in union_left_adentro}
		for dispositivos in cont:
			if cont[dispositivos]%2 != 0:
				disp_promiscuos.append(dispositivos)
		for dispositivos in disp_promiscuos:
			global EMAIL
			body = ''+dispositivos+' :: en modo Promiscuo\n'
			agregar_log_alarmas("Los dispositivos: "+dispositivos+" se encuentran en modo promiscuo", "Dispositivos activos en modo promiscuo",'')
			print(''+dispositivos+' :: en modo promiscuo\n')

#Verifica si existen procesos del tipo sniffer activos para matarlos
#Parametros: Lista de sniffers que conseguimos de la base de datos
#Retorno: No retorna

def verificar_procesos_prom(LISTA_SNIFFERS):
	p = subprocess.Popen("ps axo pid,command | grep -E '"+LISTA_SNIFFERS+"' | grep -v '"+LISTA_SNIFFERS+"'", stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	global EMAIL
	body = output.decode("utf-8")
	for linea in body.splitlines():
		cmd_sniffer = linea.split(' ')[0]
		pid_sniffer = linea.split(' ')[1]
		proceso_kill9(pid_sniffer)
		mv_cuarentena(cmd_sniffer)
		
		agregar_log_alarmas("Sniffer en "+cmd_sniffer, "Sniffer encontrado",'')
		agregar_log_prevencion("Sniffer "+cmd_sniffer+" muerto y en cuarentena", "Sniffer encontrado")
	if len(body)>1:
		body = 'Sniffers:\n'+body+"\n Sniffers en cuarentena"
		print(body+"\n")

#Verifica si hay sniffers o dispositivos promiscuos ejecutando ambas funciones
#Parametros: Ruta /var/log/secure y la lista de sniffers de la base de datos
#Retorno: No retorna

def verificar_sniffers_promiscuos(RUTA_LOG, LISTA_SNIFFERS):
	verificar_promiscuos(RUTA_LOG)
	verificar_procesos_prom(LISTA_SNIFFERS)
	
#Verifica los consumos que tienen los procesos en el sistema segun su uso de cpu, ram y el tiempo de ejecucion
#Parametros: Los limites de consumo en forma de diccionario segun su pid, el nombre, el uso de la cpu, ram y tiempo.
#Retorno: No retorna

def verificar_consumos(limites_consumos):
	global M_CPU
	global M_RAM
	procesos = list()
	for proc in psutil.process_iter():
		aux_procesos = proc.as_dict(attrs=['pid', 'name', 'cpu_percent', 'memory_percent', 'create_time'])
		procesos.append(aux_procesos)
	body = ''
	for proc in procesos:
		max_cpu = 90.000 
		max_ram = 90.000 
		max_tiempo = -1.000 #tiempo en segundos
		for dic in limites_consumos:
			if (proc['name'].lower() == dic['name'].lower()):
				max_cpu = dic['maximo_cpu']
				max_ram = dic['maximo_ram']
				max_tiempo = dic['maximo_ejecucion']
		dif_tiempo = time.time() - proc['create_time']

		fuera_de_rango = ''
		aux_cpu=aux_ram=aux_tiempo=False
		if proc['cpu_percent'] > max_cpu:
			aux_cpu = True
			fuera_de_rango=fuera_de_rango+' CPU'

		if proc['memory_percent'] > max_ram:
			aux_ram = True
			if fuera_de_rango != '':
				fuera_de_rango=fuera_de_rango+' y RAM'
			else:
				fuera_de_rango=fuera_de_rango+' RAM'

		if (dif_tiempo > max_tiempo and max_tiempo >=0.000) :
			aux_tiempo = True
			proc.update({'tiempo_ejec':str(datetime.timedelta(seconds=int(dif_tiempo)))})
			if fuera_de_rango != '':
				fuera_de_rango=fuera_de_rango+' y tiempo de ejecucion'
			else:
				fuera_de_rango=fuera_de_rango+' tiempo de ejecucion'
		if aux_cpu or aux_ram or aux_tiempo:
			proc.update({'Error': 'Fuero de rango: '+fuera_de_rango+' fuera del limite de este proceso'})

			body+=json.dumps(proc)+'\n\n'
			proceso_kill9(proc['pid'])

			agregar_log_alarmas("El proceso supero sus limites de consumo "+json.dumps(proc), "Consumo excesivo",'')
			agregar_log_prevencion("Proceso eliminado por exceder limites de consumo "+json.dumps(proc), "Consumo excesivo")
	if body !='':
		body = 'Consumo excesivo fue encontrado\n\n'+body
		print (body + "\n")
	
#Verifica que usuarios estan conectados al sistema mediante el proceso w
#Parametros: No recibe parametros
#Retorno: No retorna

def verificar_conexiones():
	conexiones_ip = subprocess.Popen("w -i 2>/dev/null", stdout=subprocess.PIPE, shell=True)
	(output, err) = conexiones_ip.communicate()
	print(output.decode("utf-8")+"\n")

#Verifica si hubo intentos de Fuzzing: Si te preguntas que es fuzzing, se trata de una tecnica de testeo automatizado 
#mediante la que se introducen datos invalidos, aleatorios o inesperados a un sistema informatico. 
#Estos datos de entrada podrían dar origen a algún error, y alli es donde los investigadores deben centrar su atencion. 
#Parametros: Nuestro IP para no tenerlo en cuenta en las busquedas y la cantidad maxima de intentos
#Retorno: No retorna
def verificar_fuzzing(IP_SERVIDOR,m_intento):
	cont = dict()
	array_ip = list()
	p = subprocess.Popen("cat /var/log/httpd/access_log | grep -v "+IP_SERVIDOR+" | grep -v ::1 | grep 404", stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	ret_msg = output.decode("utf-8")
	for linea in ret_msg.splitlines():
		direccion_ip = linea.split(" ")[0] 	#La primera palabra de cada linea es la direccion ip
		array_ip.append(direccion_ip)

	body = ''
	for ip in array_ip:
		if ip in cont:
			cont[ip]+=1
			if cont[ip] == m_intento :
				bloquear_ip(ip)
				body = body + '\n'+ip
				agregar_log_alarmas("La direccion "+ip+" realizo "+str(m_intento)+" intentos en direcciones inexistentes", "Ataque de Fuzzing",ip)
				agregar_log_prevencion("La direccion "+ip+" fue bloqueada en IPTables","Ataque de Fuzzing")
				print("La direccion "+ip+" fue bloqueada en IPTables por Fuzzing\n")
				
		else:
			cont[ip]=1
	if body != '':
		body = "Direcciones IP bloqueadas:"+body
	
#Verifica cambios en los hashes de archivos como passwd y shadow
#Parametros: Recibe una lista con el hash producido por md5sum.
#Retorno: No retorna

def verificar_md5sum(HASH_MD5SUM):
	body = ''
	tmp_hashes = '/tmp/hipshashes.md5'
	for aux_hash in HASH_MD5SUM:
		subprocess.Popen("echo "+aux_hash+" >> "+tmp_hashes, stdout=subprocess.PIPE, shell=True)
	p =subprocess.Popen("md5sum -c "+tmp_hashes, stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	
	if output.decode("utf-8")[-3:-1] != 'OK':
		body+=output.decode("utf-8")
		cmd_sniffer = output.decode("utf-8").split(" ")[0]
		agregar_log_alarmas("Ha cambiado el hash para "+cmd_sniffer, "Cambios en MD5SUM","")

	if body != '':
		body = 'Hash fue modificado:\n\n' + body	
		print(body+"\n")

	
	subprocess.Popen("rm "+tmp_hashes, stdout=subprocess.PIPE, shell=True)

#Crea un nuevo hash md5sum
#Parametros: Ruta del archivo al cual queremos crearle el hash
#Retorna: Hash nuevo

def creador_hashesmd5(nueva_ruta_md5):
	global RUTA_HASHES
	p =subprocess.Popen("cp -R "+nueva_ruta_md5+" "+RUTA_HASHES+"/", stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	p =subprocess.Popen("md5sum "+nueva_ruta_md5, stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	print(output.decode("utf-8")[:-1])
	return output.decode("utf-8")[:-1]

#Monitoriza los archivos en el /tmp buscando archivos que empiezan por #!
#Parametros: Ruta donde se busca, /tmp
#Retorno: No retorna

def monitor_shell(RUTA):
	body = ''
	p =subprocess.Popen("find "+RUTA+" -type f", stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	archivos_tmp = output.decode("utf-8")
	for linea in archivos_tmp.splitlines():
		cat =subprocess.Popen("cat "+linea+" | grep '#!'", stdout=subprocess.PIPE, shell=True)
		(output, err) = cat.communicate()
		txt = output.decode("utf-8")
		if(txt !=''):
			body +='Posible script de tipo shell en: '+linea+'\n'
			mv_cuarentena(linea)
			print('Posible script de tipo shell: '+linea+" El archivo se movio a cuarentena.\n")
			agregar_log_alarmas("Posible shell "+linea, "Posible shell en el directorio "+RUTA,"")
			agregar_log_prevencion("Posible script de tipo shell: "+linea+" archivo en cuarentena.","Shell encontrada en el directorio tmp")

	if body!='':
		body = body +"\nArchivos movidos a cuarentena"

#Monitoriza si existen archivos tipo script mediante un pequenho diccionario de terminaciones de archivos
#Recibe: Ruta de /tmp
#Retorno: No retorna

def monitor_scripts(RUTA):
	terminaciones = ['py','c','cpp','ruby','sh','exe','php','java','pl']
	vector_aux = "find "+RUTA+" -type f "
	for i in terminaciones:
		vector_aux+= "-iname '*."+i+"' -o -iname '*."+i+".*' -o "
	if vector_aux!="find "+RUTA+" -type f ":
		vector_aux = vector_aux[:-4]
	p =subprocess.Popen(vector_aux, stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	body = ''
	scripts = output.decode("utf-8")
	body = body + scripts
	if body!='':
		for linea in scripts.splitlines():
			mv_cuarentena(linea)
			print('Archivo script encontrado: '+linea+" El archivo se movio a cuarentena.\n")
			agregar_log_alarmas("Archivo script encontrado: "+linea, "Archivo script encontrado en el directorio " +RUTA,"")
			agregar_log_prevencion("Archivo script "+linea+" movido a cuarentena","Archivo script encontrado en el directorio tmp")
		body = 'Archivos scripts encontrados :\n'+body +"\nArchivos movidos a cuarentena."

#Verifica el directorio /tmp ejecutando las funciones monitores de shell y scripts
#Parametros: No recibe parametros
#Retorno: No retorna

def verificar_ruta_tmp():
	monitor_shell("/tmp")
	monitor_scripts("/tmp")	

#Verifica si hubo errores de autenticacion en el secure
#Parametros: No recibe parametros
#Retorno: No retorna

def verificar_autenticacionf():
	global EMAIL
	p =subprocess.Popen("cat /var/log/secure | grep -i \"authentication failure\"", stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	ret_msg = output.decode("utf-8")
	body = ''
	for linea in ret_msg.splitlines():
		agregar_log_alarmas(linea, "Error de autenticacion","")
		
	body = body + ret_msg

#Verifica si hay scripts ejecutandose cada cierto tiempo en el cron.
#Parametros: Linea con el contenido del crontab, lugar donde se escriben los procesos a ejecutarse y el tiempo en el cual se ejecutan
#Retorno: informacion de que se detecto un script en la linea

def crontab_script(linea):
	separado = linea.split()
	final = separado[-1]
	terminaciones = ['py','c','cpp','ruby','sh','exe','php','java','pl']
	ruta = final.split("/")
	script = ruta[-1]
	tipos_archivos = script.split(".")
	tipos_archivos.reverse()
	for i in tipos_archivos:
		for j in terminaciones:
			if (i==j):
				if (os.path.isfile(final)):
					body = "Posible script hecho por un crontab: "+linea+"\n"
					print(body)
					tipo_alarma = "Posible script en cron"
					agregar_log_alarmas(body, tipo_alarma,'')
					return (body)
	return ('')

#Verifica si hay archivos tipo shell #! en el cron
#Parametros: Linea con el contenido del crontab, lugar donde se escriben los procesos a ejecutarse y el tiempo en el cual se ejecutan
#Retorno: informacion de que se detecto shell en la linea

def crontab_shell(linea):
	separado = linea.split()
	final = separado[-1]
	cat =subprocess.Popen("cat "+final+" 2> /dev/null | grep '#!'", stdout=subprocess.PIPE, shell=True)
	(output, err) = cat.communicate()
	txt = output.decode("utf-8")
	if(txt !=''):
		info = "Posible shell hecho en un crontab: "+linea+"\n"
		print(info)
		tipo_alarma = "Posible shell en cron"
		agregar_log_alarmas(info, tipo_alarma,'')
		return (info)

	return ('')



##Verifica si hay sniffers ejecutandose cada cierto tiempo en el cron.
#Parametros: Linea con el contenido del crontab, lugar donde se escriben los procesos a ejecutarse y el tiempo en el cual se ejecutan
#Retorno: informacion de que se detecto un script en la linea

def crontab_sniffer(linea, LISTA_SNIFFERS):
	separado = linea.split()
	final = separado[-1]
	ruta = final.split("/")
	sniffer = ruta[-1]
	for i in LISTA_SNIFFERS:
		if (i==sniffer):
			info = "Posible sniffer hecho en crontab: "+linea+"\n"
			print(info)
			tipo_alarma = "Posible sniffer en cron"
			agregar_log_alarmas(info, tipo_alarma,'')
			return (info)
	return ('')
	
#Verifica el cron ejecutando las tres funciones anteriores
#Parametros: Los sniffers que agregamos a la base de datos
#Retorno: No retorna

def verificar_cron(LISTA_SNIFFERS):
	global EMAIL
	sniffers = LISTA_SNIFFERS.split("|")
	p =subprocess.Popen("crontab -l", stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	ret_msg = output.decode("utf-8")
	body_scripts = ''
	body_shells = ''
	body_sniffers = ''
	print(ret_msg.splitlines())
	for linea in ret_msg.splitlines():
		aux = crontab_shell(linea)
		print('entra')
		if (aux != ''):
			body_shells = body_shells + aux
		
		aux = crontab_script(linea)
		if (aux != ''):
			body_scripts = body_scripts + aux
		
		aux = crontab_sniffer(linea, sniffers)
		if (aux != ''):
			body_sniffers = body_sniffers + aux
			
	body = body_scripts + body_shells + body_sniffers
	if (body != ''):
		body = ""+body+"\nPlease verify and take action."

#Verifica en el secure si alguien intento ingresar al sistema via ssh y no lo logro al menos 5 veces
#Parametros: Nuestro IP para no tenerlo en cuenta en las busquedas y la cantidad maxima de intentos
#Retorno: No retorna

def verificar_ssh(IP_SERVIDOR,m_intento):
	global EMAIL
	cont = dict()
	array_ip = list()
	p =subprocess.Popen("cat /var/log/secure | grep -i \"ssh\" | grep -i \"Failed password\" | grep -v \""+IP_SERVIDOR+"\"", stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	ret_msg = output.decode("utf-8")
	body = ''
	aux_prev = ''
	for linea in ret_msg.splitlines():
		direccion_ip = linea.split(" ")[-4] #la ip se encuentra en la posicion -4 del string, recordemos que con el - se cuenta desde el final
		array_ip.append(direccion_ip)
		agregar_log_alarmas(linea, "SSH authentication failure",direccion_ip)
		
	for ip in array_ip:
		if ip in cont:
			cont[ip]+=1
			if cont[ip] == m_intento :
				bloquear_ip(ip)
				body = body + '\n'+ip
				agregar_log_prevencion(ip+" fue bloqueado por IPTables","Ocurrio un error en la contrasenha mas de "+str(m_intento)+" veces")
				aux_prev = aux_prev + ip + "\n"
				print(ip+" fue bloqueado por IPTables. Muchos errores de contrasenha en el SSH.\n")
		else:
			cont[ip]=1

	body = body + ret_msg

	if aux_prev != '':
		aux_prev = "IPs bloqueadas por fallos con el SSH :: Error de contrasenha SSH\n" + aux_prev
	

def main():
	global M_CUARENTENA
	global RUTA_CUARENTENA
	global M_RAM
	global M_CPU
	data_list = conexion_bd()
	RUTA_CUARENTENA = '/etc/cuarentena'
	IP_SERVIDOR = data_list['mi_ip']
	M_MAIL = data_list['cola_mail']
	m_mail_envios = data_list['m_mail_envios']
	m_ssh = data_list['m_ssh']
	m_fuzz = data_list['m_fuzz']
	RUTA_LOG = '/var/log/messages'
	LISTA_SNIFFERS = data_list['sniffers']
	limites_consumos = data_list['consumos']
	HASH_MD5SUM= data_list['md5sum']
	
	if os.path.isfile(RUTA_LOG) is not True:
		RUTA_LOG = '/var/log/syslog'

	if os.path.isdir(RUTA_CUARENTENA) is not True:
		p =subprocess.Popen("mkdir "+RUTA_CUARENTENA, stdout=subprocess.PIPE, shell=True)
		(output, err) = p.communicate()
	
	p =subprocess.Popen("chmod 664 "+RUTA_CUARENTENA, stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()

	print("\n-\n\nHIPS en ejecucion\n\n-")
	verificar_smtp_attack(m_mail_envios)
	verificar_sniffers_promiscuos(RUTA_LOG, LISTA_SNIFFERS)
	verificar_consumos(limites_consumos)
	verificar_conexiones()
	verificar_fuzzing(IP_SERVIDOR,m_fuzz)
	verificar_procesos_prom(LISTA_SNIFFERS)
	verificar_md5sum(HASH_MD5SUM)
	verificar_ruta_tmp()
	verificar_autenticacionf()
	verificar_cron(LISTA_SNIFFERS)
	verificar_ssh(IP_SERVIDOR,m_ssh)

	print('\n-\n\nFin de la ejecucion\n\n-')
	return(0)
        
if __name__=='__main__':
        main()
