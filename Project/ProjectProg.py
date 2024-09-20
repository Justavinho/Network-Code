import os  # Importa el módulo os para operaciones del sistema operativo
import platform  # Importa el módulo platform para acceder a información sobre la plataforma
import socket  # Importa el módulo socket para operaciones de red
import requests  # Importa el módulo requests para realizar solicitudes HTTP
import psutil  # Importa el módulo psutil para obtener información del sistema y procesos
import subprocess  # Importa el módulo subprocess para ejecutar comandos externos
import smtplib  # Importa el módulo smtplib para enviar correos electrónicos
from email.mime.multipart import MIMEMultipart  # Importa MIMEMultipart para construir mensajes MIME
from email.mime.text import MIMEText  # Importa MIMEText para manejar texto MIME
from cryptography.fernet import Fernet  # Importa Fernet de cryptography.fernet para cifrado
from scapy.all import sniff, ARP, IP  # Importa scapy para análisis de tráfico de red
import cv2  # Importa OpenCV (cv2) para procesamiento de imágenes y visión por computadora
import numpy as np  # Importa NumPy para operaciones numéricas eficientes
import time  # Importa el módulo time para manejar operaciones relacionadas con el tiempo
from bs4 import BeautifulSoup  # Importa BeautifulSoup para analizar documentos HTML y XML
import threading  # Importa threading para manejar hilos
import datetime  # Importa datetime para manejar fechas y horas


known_faces_folder = "Photos"  # Define la carpeta donde se encuentran las fotos de rostros conocidos

class MainMenu:
    def __init__(self):
        self.log_manager = LogManager()  # Crea una instancia de LogManager para gestionar registros
        self.log_manager.create_initial_log_file()  # Crea un archivo de registro inicial
        self.system_info = SystemInfo(self.log_manager)  # Crea una instancia de SystemInfo
        self.network_devices = NetworkDevices(self.log_manager)  # Crea una instancia de NetworkDevices
        self.network_interfaces = NetworkInterfaces(self.log_manager)  # Crea una instancia de NetworkInterfaces
        self.port_scanner = PortScanner(self.log_manager)  # Crea una instancia de PortScanner
        self.geo_location = GeoLocation(self.log_manager)  # Crea una instancia de GeoLocation
        self.network_analyzer = NetworkAnalyzer(self.log_manager)  # Crea una instancia de NetworkAnalyzer
        self.encryptic_text = EmailManager(self.log_manager)
        self.known_faces_folder = "Photos"  # Define la carpeta de rostros conocidos
        self.facial_recognition = FacialRecognition(self.log_manager, self.known_faces_folder)  # Crea una instancia de FacialRecognition
        self.website_info = WebsiteInfo(self.log_manager)  # Crea una instancia de WebsiteInfo

        self.options = {
            "1": self.facial_recognition_action,  # Opción para reconocimiento facial
            "2": self.network_analyzer.analyze_traffic,  # Opción para analizar tráfico de red
            "3": self.website_info.get_website_info,  # Opción para obtener información de un sitio web
            "4": self.geo_location.detect_geo_location,  # Opción para detectar la ubicación geográfica
            "5": self.port_scanner.scan_ports,  # Opción para escanear puertos
            "6": self.system_info.display_os,  # Opción para mostrar el sistema operativo
            "7": self.network_devices.list_connected_devices,  # Opción para listar dispositivos conectados a la red
            "8": self.network_interfaces.list_network_interfaces,  # Opción para listar interfaces de red
            "9": self.system_info.display_mac_address,  # Opción para mostrar la dirección MAC
            "10": self.encryptic_text.send_encrypted_email,  # Opción para enviar correo electrónico cifrado
            "11": self.configure_router_action,  # Opción para configurar el router
            "12": self.exit_program,  # Opción para salir del programa
        }

    def display_menu(self):
        while True:
            print("\nSeleccione una opción:")
            print("1. Reconocimiento Facial")
            print("2. Analizar el tráfico de red en tiempo real")
            print("3. Obtener información de un sitio web")
            print("4. Detección de la Zona Geográfica")
            print("5. Escaneo de Puertos")
            print("6. Determinar el sistema operativo del equipo")
            print("7. Listar los nombres de todos los equipos conectados a la red")
            print("8. Listar todas las interfaces de red")
            print("9. Obtener la dirección MAC del equipo")
            print("10. Enviar texto cifrado")
            print("11. Configuración de Router")
            print("12. Salir")

            choice = input("Ingrese su elección: ")  # Captura la elección del usuario
            action = self.options.get(choice)  # Obtiene la acción asociada con la elección

            if action:
                self.log_manager.add_log(f"Opción elegida: {choice}")  # Registra la opción elegida en los registros
                self.log_manager.generate_log_file()  # Genera el archivo de registro después de cada elección
                action()  # Ejecuta la acción asociada con la elección
            else:
                self.log_manager.add_log(f"Opción no válida ingresada: {choice}")  # Registra opción no válida en los registros
                print("Opción no válida, por favor intente de nuevo.")  # Muestra un mensaje de error

    # Métodos para acciones específicas del menú
    def configure_router_action(self):  # Método para configurar el router
        router_ip = input("Ingresa la dirección IP del router: ")  # Captura la dirección IP del router
        username = input("Ingresa el nombre de usuario: ")  # Captura el nombre de usuario
        password = input("Ingresa la contraseña: ")  # Captura la contraseña (considerar almacenamiento seguro)
        new_ssid = input("Ingresa el nuevo SSID: ")  # Captura el nuevo SSID
        new_password = input("Ingresa la nueva contraseña del WiFi: ")  # Captura la nueva contraseña del WiFi
        new_ip_address = input("Ingresa la nueva dirección IP del router: ")  # Captura la nueva dirección IP
        new_subnet_mask = input("Ingresa la nueva máscara de subred: ")  # Captura la nueva máscara de subred
        new_gateway = input("Ingresa el nuevo gateway predeterminado: ")  # Captura el nuevo gateway predeterminado

        configurator = DLinkRouterConfigurator(router_ip, username, password)  # Crea una instancia de DLinkRouterConfigurator

        try:
            if configurator.login():  # Intenta iniciar sesión en el router
                print("Inicio de sesión exitoso!")  # Muestra mensaje de inicio de sesión exitoso
                if configurator.configure_network(new_ip_address, new_subnet_mask, new_gateway):  # Intenta configurar la red
                    print("Configuración de red actualizada exitosamente!")  # Muestra mensaje de configuración exitosa
                    self.log_manager.add_log("Configuración de red del router actualizada exitosamente.")  # Registra en los registros
                else:
                    print("Fallo al actualizar la configuración de red.")  # Muestra mensaje de fallo en configuración
                    self.log_manager.add_log("Error: Fallo al actualizar la configuración de red del router.")  # Registra en los registros

                if configurator.configure_wifi(new_ssid, new_password):  # Intenta configurar el WiFi
                    print("Configuración de WiFi actualizada exitosamente!")  # Muestra mensaje de configuración exitosa
                    self.log_manager.add_log("Configuración de WiFi del router actualizada exitosamente.")  # Registra en los registros
                else:
                    print("Fallo al actualizar la configuración de WiFi.")  # Muestra mensaje de fallo en configuración
                    self.log_manager.add_log("Error: Fallo al actualizar la configuración de WiFi del router.")  # Registra en los registros
            else:
                print("Fallo en el inicio de sesión.")  # Muestra mensaje de fallo en inicio de sesión
                self.log_manager.add_log("Error: Fallo en el inicio de sesión del router.")  # Registra en los registros
        except Exception as e:
            self.log_manager.add_log(f"Error al configurar el router: {e}")  # Registra error específico en los registros
            print(f"Error al configurar el router: {e}")  # Muestra mensaje de error específico

    def facial_recognition_action(self):  # Método para iniciar el reconocimiento facial
        self.facial_recognition.recognize_faces_realtime()  # Llama al método de reconocimiento facial en tiempo real


    def exit_program(self):  # Método para salir del programa
        print("Saliendo del programa...")  # Muestra mensaje de salida
        self.log_manager.add_log("Programa cerrado correctamente.")  # Registra en los registros
        self.log_manager.generate_log_file()  # Genera el archivo de registro antes de salir
        exit()  # Sale del programa

class EmailManager:  # Clase para gestionar el envío de correos electrónicos

    def __init__(self, log_manager):
        self.log_manager = log_manager  # Administrador de registros para registrar eventos

    def encrypt_text(self):  # Método para cifrar el texto (puedes adaptarlo según tu método de cifrado)
        plain_text = input("Ingrese el texto que desea cifrar: ")
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        cipher_text = cipher_suite.encrypt(plain_text.encode())
        return cipher_text, key

    def send_encrypted_email(self):  # Método para enviar correo electrónico cifrado
        try:
            encrypted_text, key = self.encrypt_text()

            sender_email = input("Ingrese su dirección de correo electrónico: ")
            receiver_email = input("Ingrese la dirección de correo del destinatario: ")
            password = input("Ingrese su contraseña de correo electrónico: ")
            smtp_server = "smtp.office365.com"  # Servidor SMTP para Outlook

            # Mensaje con el texto cifrado
            message_encrypted = MIMEMultipart()
            message_encrypted["From"] = sender_email
            message_encrypted["To"] = receiver_email
            message_encrypted["Subject"] = "Mensaje cifrado"
            message_encrypted.attach(MIMEText(encrypted_text.decode(), "plain"))

            # Mensaje con la clave y el texto plano (para que el destinatario pueda descifrar)
            message_key = MIMEMultipart()
            message_key["From"] = sender_email
            message_key["To"] = receiver_email
            message_key["Subject"] = "Clave y Texto Plano"
            message_key.attach(MIMEText(f"Clave: {key.decode()}\nTexto Plano: {encrypted_text.decode()}", "plain"))

            with smtplib.SMTP(smtp_server, 587) as server:
                server.starttls()
                server.login(sender_email, password)
                server.sendmail(sender_email, receiver_email, message_encrypted.as_string())
                server.sendmail(sender_email, receiver_email, message_key.as_string())

            print("Mensajes enviados correctamente.")
            self.log_manager.add_log("Mensajes enviados correctamente.")

        except Exception as e:
            print(f"Error al enviar el mensaje: {e}")
            self.log_manager.add_log(f"Error al enviar el mensaje: {e}")

class FacialRecognition:
    def __init__(self, log_manager, known_faces_folder):
        self.log_manager = log_manager  # Gestor de registros para almacenar eventos y errores
        self.face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')  # Clasificador de cascada para detectar rostros en una imagen
        self.recognizer = cv2.face.LBPHFaceRecognizer_create()  # Inicializa el reconocedor LBPH para reconocimiento facial
        self.known_faces_folder = known_faces_folder  # Ruta al directorio que contiene rostros conocidos
        self.known_faces, self.labels = self.load_known_faces(known_faces_folder)  # Carga rostros conocidos y etiquetas

        if self.known_faces:
            self.train_recognizer()  # Entrena el reconocedor si hay rostros conocidos
        else:
            print("No se encontraron rostros conocidos. El reconocimiento facial no funcionará.")

    def load_known_faces(self, folder_path):
        known_faces = []  # Lista para almacenar imágenes de rostros conocidos
        labels = []  # Lista para almacenar etiquetas correspondientes a cada rostro conocido
        label = 0  # Inicializa la etiqueta

        try:
            for person_name in os.listdir(folder_path):  # Itera sobre los nombres de las personas en el directorio
                person_folder = os.path.join(folder_path, person_name)  # Ruta completa a la carpeta de la persona
                if os.path.isdir(person_folder):
                    for filename in os.listdir(person_folder):  # Itera sobre los archivos en la carpeta de la persona
                        if filename.endswith(".jpg") or filename.endswith(".png"):  # Filtra archivos de imagen
                            img_path = os.path.join(person_folder, filename)  # Ruta completa a la imagen
                            image = cv2.imread(img_path, cv2.IMREAD_GRAYSCALE)  # Lee la imagen en escala de grises
                            known_faces.append(image)  # Agrega la imagen a la lista de rostros conocidos
                            labels.append(label)  # Agrega la etiqueta correspondiente
                    label += 1  # Incrementa la etiqueta para la siguiente persona

        except Exception as e:
            self.log_manager.add_log(f"Error al cargar las caras conocidas: {e}")  # Registra errores en el gestor de registros

        return known_faces, np.array(labels)  # Devuelve las listas de rostros conocidos y etiquetas como un arreglo numpy

    def train_recognizer(self):
        try:
            self.recognizer.train(self.known_faces, self.labels)  # Entrena el reconocedor con los rostros conocidos y etiquetas
        except Exception as e:
            self.log_manager.add_log(f"Error al entrenar el reconocedor: {e}")  # Registra errores en el gestor de registros si falla el entrenamiento

    def recognize_faces_realtime(self):
        try:
            video_capture = cv2.VideoCapture(0)  # Inicializa la captura de video desde la cámara

            if not video_capture.isOpened():
                print("Error: No se pudo abrir la cámara.")
                return

            unknown_count = 0  # Contador para rastrear personas desconocidas detectadas
            start_time = None  # Tiempo de inicio para la espera después de detectar desconocidos por tercera vez
            send_email = False  # Bandera para indicar si se debe enviar un correo electrónico

            while True:
                ret, frame = video_capture.read()  # Lee un fotograma del video capturado
                if not ret:
                    print("Error: No se pudo capturar el frame de la cámara.")
                    break

                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)  # Convierte el fotograma a escala de grises
                faces = self.face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))  # Detecta rostros en la imagen

                for (x, y, w, h) in faces:
                    roi_gray = gray[y:y + h, x:x + w]  # Extrae la región de interés (ROI) que contiene el rostro

                    try:
                        label, confidence = self.recognizer.predict(roi_gray)  # Realiza la predicción del rostro

                        if confidence < 100:  # Si la confianza es alta, reconoce al sujeto
                            name = os.listdir(self.known_faces_folder)[label]  # Obtiene el nombre del archivo según la etiqueta
                            cv2.putText(frame, name, (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 255, 0), 2)  # Muestra el nombre sobre el rostro reconocido
                            self.log_manager.add_log(f"Rostro reconocido: {name}")  # Registra el reconocimiento en el gestor de registros
                        else:
                            cv2.putText(frame, "Desconocido", (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 0, 255), 2)  # Etiqueta como desconocido si la confianza es baja
                            unknown_count += 1  # Incrementa el contador de personas desconocidas
                            print("Persona desconocida detectada")  # Imprime un mensaje en la consola
                            if unknown_count == 3:  # Si se detecta a una persona desconocida por tercera vez
                                start_time = time.time()  # Registra el tiempo de inicio
                                send_email = True  # Activa la bandera para enviar un correo electrónico
                                self.send_notification_email()  # Envía el correo electrónico de notificación
                                print("Esperando 10 segundos antes de cerrar la ventana...")
                                time.sleep(10)  # Espera 10 segundos antes de cerrar la ventana
                                break

                    except cv2.error as e:
                        self.log_manager.add_log(f"Error de reconocimiento facial: {e}")  # Registra errores de reconocimiento en el gestor de registros
                        continue

                    cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 0), 2)  # Dibuja un rectángulo alrededor del rostro reconocido

                cv2.imshow('Video', frame)  # Muestra el fotograma con los resultados de reconocimiento

                if cv2.waitKey(1) & 0xFF == ord('q') or send_email:  # Espera la tecla 'q' para salir o envía un correo electrónico
                    break

            video_capture.release()  # Libera los recursos de la cámara
            cv2.destroyAllWindows()  # Cierra todas las ventanas abiertas por OpenCV

        except Exception as e:
            print(f"Error al ejecutar el reconocimiento facial: {e}")  # Manejo de errores generales
            self.log_manager.add_log(f"Error al ejecutar el reconocimiento facial: {e}")  # Registra errores en el gestor de registros

    def send_notification_email(self):
        sender_email = "joshuadiazk@outlook.com"  # Dirección de correo del remitente
        receiver_email = "kingjustavk@outlook.com"  # Dirección de correo del receptor (puedes cambiarla según necesites)

        message = MIMEMultipart()  # Crea un mensaje multipart
        message["From"] = sender_email  # Establece el remitente del mensaje
        message["To"] = receiver_email  # Establece el receptor del mensaje
        message["Subject"] = "Alerta: Persona Desconocida Detectada"  # Asunto del mensaje

        body = "Se detectó a una persona desconocida en el sistema de reconocimiento facial."  # Cuerpo del mensaje
        message.attach(MIMEText(body, "plain"))  # Adjunta el cuerpo del mensaje al mensaje multipart

        try:
            with smtplib.SMTP("smtp-mail.outlook.com", 587) as server:  # Establece conexión SMTP con Outlook
                server.starttls()  # Inicia TLS para seguridad en la comunicación
                server.login(sender_email, "angeline2015")  # Inicia sesión en el servidor SMTP
                server.sendmail(sender_email, receiver_email, message.as_string())  # Envía el mensaje como cadena

            print("Correo electrónico enviado correctamente.")  # Confirma el envío exitoso del correo
            self.log_manager.add_log("Correo electrónico enviado correctamente.")  # Registra el envío exitoso en el gestor de registros

        except Exception as e:
            print(f"Error al enviar el correo electrónico: {e}")  # Manejo de errores al enviar el correo
            self.log_manager.add_log(f"Error al enviar el correo electrónico: {e}")  # Registra errores en el gestor de registros

class DLinkRouterConfigurator:
    def __init__(self, router_ip="192.168.0.1", username=None, password=None):  # Constructor que inicializa el objeto
        self.router_ip = router_ip  # Asigna la dirección IP del router
        self.username = username  # Asigna el nombre de usuario opcional
        self.password = password  # Asigna la contraseña opcional
        self.session = requests.Session()  # Inicializa una sesión de requests para mantener la conexión

    def login(self):
        if not self.username or not self.password:  # Verifica si se proporcionaron las credenciales
            self.username = input("Ingresa el nombre de usuario del router: ")  # Solicita nombre de usuario si no está definido
            self.password = input("Ingresa la contraseña del router: ")  # Solicita contraseña si no está definida

        login_url = f'http://{self.router_ip}/login.cgi'  # URL para el inicio de sesión
        login_data = {
            'username': self.username,
            'password': self.password
        }
        response = self.session.post(login_url, data=login_data)  # Realiza la solicitud POST para iniciar sesión
        return response.status_code == 200 and 'success' in response.text.lower()  # Retorna True si el inicio de sesión fue exitoso

        if response.status_code != 200:  # Manejo de errores si la solicitud no es exitosa
            print(f"Error en la solicitud de inicio de sesión: {response.status_code}")
            print(response.text)  # Imprime la respuesta del router para depuración
            return False

        if 'success' not in response.text.lower():  # Manejo de errores si el inicio de sesión no es exitoso
            print("Inicio de sesión fallido. Verifica las credenciales.")
            print(response.text)  # Imprime la respuesta del router para depuración
            return False

        return True  # Retorna True si el inicio de sesión fue exitoso

    def configure_network(self, new_ip_address, new_subnet_mask, new_gateway):
        if not self.login():  # Verifica el inicio de sesión antes de configurar la red
            return False

        network_config_url = f'http://{self.router_ip}/lan_setup.shtml'  # URL para la configuración de red
        response = self.session.get(network_config_url)  # Obtiene la página de configuración de red
        soup = BeautifulSoup(response.text, 'html.parser')  # Parsea el HTML para obtener datos

        token_input = soup.find('input', {'name': 'token_key'})  # Encuentra el token de seguridad necesario para enviar datos
        if token_input:
            token_value = token_input['value']  # Obtiene el valor del token si está presente
        else:
            return False  # Retorna False si no se encuentra el token

        network_config_data = {
            'token_key': token_value,
            'ipaddr': new_ip_address,
            'netmask': new_subnet_mask,
            'gateway': new_gateway,
            'submit': 'Save Settings'
        }

        response = self.session.post(network_config_url, data=network_config_data)  # Envía los datos de configuración de red

        # Verificación adicional
        time.sleep(2)  # Espera 2 segundos para asegurar que la configuración se aplique
        check_url = f'http://{self.router_ip}/lan_setup.shtml'  # URL para verificar la configuración
        check_response = self.session.get(check_url)  # Obtiene la página de configuración actualizada
        check_soup = BeautifulSoup(check_response.text, 'html.parser')  # Parsea el HTML de la página actualizada
        ipaddr_input = check_soup.find('input', {'name': 'ipaddr'})  # Encuentra el campo de dirección IP configurada

        return ipaddr_input and ipaddr_input['value'] == new_ip_address  # Retorna True si la dirección IP se configuró correctamente

    def configure_wifi(self, new_ssid, new_password):
        if not self.login():  # Verifica el inicio de sesión antes de configurar el WiFi
            return False

        wifi_config_url = f'http://{self.router_ip}/wl_basic.shtml'  # URL para la configuración WiFi
        response = self.session.get(wifi_config_url)  # Obtiene la página de configuración WiFi
        soup = BeautifulSoup(response.text, 'html.parser')  # Parsea el HTML para obtener datos

        token_input = soup.find('input', {'name': 'token_key'})  # Encuentra el token de seguridad necesario para enviar datos
        if token_input:
            token_value = token_input['value']  # Obtiene el valor del token si está presente
        else:
            return False  # Retorna False si no se encuentra el token

        wifi_config_data = {
            'token_key': token_value,
            'ssid': new_ssid,
            'pskValue': new_password,
            'pskCipher': 'AES',
            'submit': 'Save Settings'
        }

        response = self.session.post(wifi_config_url, data=wifi_config_data)  # Envía los datos de configuración WiFi

        return response.status_code == 200  # Retorna True si la configuración WiFi fue exitosa

class WebsiteInfo:
    def __init__(self, log_manager):
        self.log_manager = log_manager

    def get_website_info(self):
        website = input("Ingrese la dirección del sitio web (ejemplo: www.google.com): ")
        try:
            ip_address_v4 = socket.gethostbyname(website)

            # Obtener dirección IPv6 (con manejo de errores)
            try:
                ip_address_v6 = socket.getaddrinfo(website, None, socket.AF_INET6)[0][4][0]
            except socket.gaierror:
                ip_address_v6 = "No se pudo obtener la dirección IPv6"

            # Obtener zona del servidor (con manejo de errores)
            try:
                ipapi_response = requests.get(f"https://ipapi.co/{ip_address_v4}/json/")
                ipapi_response.raise_for_status()
                server_zone = ipapi_response.json().get("timezone", "No disponible")
            except requests.exceptions.RequestException:
                server_zone = "No se pudo obtener la zona del servidor"

            # Registro e impresión de información (sin nombre de servidor)
            for info in [
                f"Información para {website}:",
                f"  Dirección IPV4: {ip_address_v4}",
                f"  Dirección IPV6: {ip_address_v6}",
                f"  Zona del servidor: {server_zone}",
            ]:
                self.log_manager.add_log(info)
                print(info)

        except Exception as e:
            error_msg = f"Error al obtener información del sitio web: {e}"
            print(error_msg)
            self.log_manager.add_log(error_msg)

class SystemInfo:
    def __init__(self, log_manager):  # Constructor que inicializa el objeto con un gestor de registros
        self.log_manager = log_manager  # Asigna el gestor de registros proporcionado

    def display_os(self):
        os_name = platform.system()  # Obtiene el nombre del sistema operativo
        self.log_manager.add_log(f"Sistema operativo detectado: {os_name}")  # Registra un mensaje de registro con el nombre del sistema operativo
        print(f"Sistema operativo: {os_name}")  # Imprime el nombre del sistema operativo

    def display_mac_address(self):
        mac_address = self.get_mac_address()  # Obtiene la dirección MAC del sistema
        self.log_manager.add_log(f"Dirección MAC: {mac_address}")  # Registra un mensaje de registro con la dirección MAC
        print(f"Dirección MAC: {mac_address}")  # Imprime la dirección MAC

    def get_mac_address(self):
        interfaces = psutil.net_if_addrs()  # Obtiene todas las interfaces de red y sus direcciones
        for interface, addrs in interfaces.items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK:  # Verifica si la dirección es de tipo AF_LINK (dirección MAC)
                    return addr.address  # Retorna la dirección MAC encontrada
        return "Dirección MAC no encontrada"  # Retorna un mensaje si no se encuentra la dirección MAC

class NetworkDevices:
    def __init__(self, log_manager):  # Constructor que inicializa el objeto con un gestor de registros
        self.log_manager = log_manager  # Asigna el gestor de registros proporcionado

    def list_connected_devices(self):
        arp_output = subprocess.check_output(['arp', '-a']).decode()  # Ejecuta el comando 'arp -a' para obtener la lista de dispositivos conectados
        devices = arp_output.split('\n')  # Divide la salida en líneas individuales
        self.log_manager.add_log("Dispositivos conectados a la red:")  # Registra un mensaje de registro indicando el inicio de la lista de dispositivos
        for device in devices:
            if device:
                self.log_manager.add_log(device)  # Registra cada dispositivo en el gestor de registros
                print(device)  # Imprime cada dispositivo en la consola

class NetworkInterfaces:
    def __init__(self, log_manager):  # Constructor que inicializa el objeto con un gestor de registros
        self.log_manager = log_manager  # Asigna el gestor de registros proporcionado

    def list_network_interfaces(self):
        interfaces = psutil.net_if_addrs()  # Obtiene todas las interfaces de red y sus direcciones
        self.log_manager.add_log("Interfaces de red disponibles:")  # Registra un mensaje de registro indicando el inicio de la lista de interfaces de red
        for interface, addrs in interfaces.items():
            self.log_manager.add_log(f"Interface: {interface}")  # Registra el nombre de la interfaz en el gestor de registros
            print(f"Interface: {interface}")  # Imprime el nombre de la interfaz en la consola
            for addr in addrs:
                self.log_manager.add_log(f"  {addr.family.name}: {addr.address}")  # Registra cada dirección de la interfaz en el gestor de registros
                print(f"  {addr.family.name}: {addr.address}")  # Imprime cada dirección de la interfaz en la consola

class PortScanner:
    def __init__(self, log_manager):
        self.log_manager = log_manager  # Almacena el gestor de registros proporcionado

    def scan_ports(self):
        # Solicita al usuario que elija entre escanear un rango de puertos o un puerto específico
        choice = input("Seleccione una opción:\n1. Escanear un rango de puertos\n2. Escanear un puerto específico\nIngrese su elección: ")
        if choice == "1":  # Si elige la opción 1
            ip_address = input("Ingrese la dirección IP: ")  # Solicita la dirección IP
            start_port = int(input("Ingrese el puerto de inicio: "))  # Solicita el puerto de inicio
            end_port = int(input("Ingrese el puerto de fin: "))  # Solicita el puerto de fin
            self.scan_port_range(ip_address, start_port, end_port)  # Llama a la función para escanear el rango de puertos
        elif choice == "2":  # Si elige la opción 2
            ip_address = input("Ingrese la dirección IP: ")  # Solicita la dirección IP
            port = int(input("Ingrese el puerto: "))  # Solicita el puerto específico
            self.scan_specific_port(ip_address, port)  # Llama a la función para escanear el puerto específico
        else:
            print("Opción no válida.")  # Informa al usuario que la opción no es válida

    def scan_port_range(self, ip_address, start_port, end_port):
        open_ports = []  # Inicializa una lista para almacenar los puertos abiertos
        for port in range(start_port, end_port + 1):  # Itera sobre el rango de puertos
            result = self.scan_port(ip_address, port)  # Escanea el puerto actual
            if result:  # Si el puerto está abierto
                open_ports.append(port)  # Agrega el puerto a la lista de puertos abiertos
        # Registra los puertos abiertos y los imprime
        self.log_manager.add_log(f"Puertos abiertos en {ip_address} del {start_port} al {end_port}: {open_ports}")
        print(f"Puertos abiertos en {ip_address} del {start_port} al {end_port}: {open_ports}")

    def scan_specific_port(self, ip_address, port):
        result = self.scan_port(ip_address, port)  # Escanea el puerto específico
        if result:  # Si el puerto está abierto
            # Registra y imprime que el puerto está abierto
            self.log_manager.add_log(f"El puerto {port} está abierto en {ip_address}.")
            print(f"El puerto {port} está abierto en {ip_address}.")
        else:
            # Registra y imprime que el puerto está cerrado
            self.log_manager.add_log(f"El puerto {port} está cerrado en {ip_address}.")
            print(f"El puerto {port} está cerrado en {ip_address}.")

    def scan_port(self, ip_address, port):
        # Crea un socket TCP/IP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # Establece un tiempo de espera de 1 segundo
            result = s.connect_ex((ip_address, port))  # Intenta conectarse al puerto
            return result == 0  # Retorna True si la conexión fue exitosa (puerto abierto)

    def perform_scan(self, target_ip):
        open_ports = []  # Inicializa una lista para almacenar los puertos abiertos
        for port in range(1, 1025):  # Itera sobre los primeros 1024 puertos
            # Ejecuta el comando 'nc -zv' para escanear el puerto
            result = subprocess.run(['nc', '-zv', target_ip, str(port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:  # Si el puerto está abierto
                open_ports.append(port)  # Agrega el puerto a la lista de puertos abiertos
        return open_ports  # Retorna la lista de puertos abiertos

class GeoLocation:
    def __init__(self, log_manager):
        self.log_manager = log_manager  # Asigna el gestor de registros proporcionado

    def detect_geo_location(self):
        choice = input(
            "Seleccione una opción:\n1. Detectar ubicación de la IP de la maquina\n2. Detectar ubicación de una IP específica\nIngrese su elección: ")
        if choice == "1":
            ip = self.get_public_ip()  # Obtiene la dirección IP pública del dispositivo
        elif choice == "2":
            ip = input("Ingrese la dirección IP: ")  # Solicita al usuario una dirección IP específica
        else:
            print("Opción no válida.")
            return

        if ip:
            location = self.get_geo_location(ip)  # Obtiene la ubicación geográfica asociada a la dirección IP
            if location:
                self.log_manager.add_log(f"Ubicación geográfica detectada para IP {ip}: {location}")  # Registra un mensaje de registro con la ubicación geográfica
                print(f"Ubicación geográfica para IP {ip}: {location}")  # Imprime la ubicación geográfica en la consola
            else:
                self.log_manager.add_log(f"No se pudo obtener la ubicación geográfica para IP {ip}.")  # Registra un mensaje de registro si no se pudo obtener la ubicación
                print(f"No se pudo obtener la ubicación geográfica para IP {ip}.")  # Imprime un mensaje en la consola si no se pudo obtener la ubicación
        else:
            self.log_manager.add_log("No se pudo obtener la IP pública.")  # Registra un mensaje de registro indicando que no se pudo obtener la IP pública
            print("No se pudo obtener la IP pública.")  # Imprime un mensaje en la consola indicando que no se pudo obtener la IP pública

    def get_public_ip(self):
        try:
            response = requests.get(
                "https://api.ipify.org?format=json")  # Realiza una solicitud GET para obtener la IP pública desde ipify
            ip = response.json().get("ip")  # Obtiene la dirección IP del JSON de respuesta
            return ip
        except Exception as e:
            self.log_manager.add_log(
                f"Error al obtener IP pública: {e}")  # Registra un mensaje de registro si ocurre un error al obtener la IP pública
            return None  # Retorna None si ocurre un error al obtener la IP pública

    def get_geo_location(self, ip):
        try:
            response = requests.get(
                f"https://ipapi.co/{ip}/json/")  # Realiza una solicitud GET para obtener la ubicación geográfica basada en la dirección IP
            location_data = response.json()  # Convierte la respuesta JSON en un diccionario Python
            location = {
                "ciudad": location_data.get("city"),  # Obtiene el nombre de la ciudad desde los datos de ubicación
                "region": location_data.get("region"),  # Obtiene el nombre de la región desde los datos de ubicación
                "pais": location_data.get("country_name"),  # Obtiene el nombre del país desde los datos de ubicación
                "latitud": location_data.get("latitude"),  # Obtiene la latitud desde los datos de ubicación
                "longitud": location_data.get("longitude"),  # Obtiene la longitud desde los datos de ubicación
            }
            return location  # Retorna un diccionario con la ubicación geográfica
        except Exception as e:
            self.log_manager.add_log(
                f"Error al obtener ubicación geográfica: {e}")  # Registra un mensaje de registro si ocurre un error al obtener la ubicación geográfica
            return None  # Retorna None si ocurre un error al obtener la ubicación geográfica

class NetworkAnalyzer:
    def __init__(self, log_manager):  # Constructor que inicializa el objeto con un gestor de registros
        self.log_manager = log_manager  # Asigna el gestor de registros proporcionado
        self.running = False  # Inicializa el estado de ejecución del análisis como falso

    def analyze_traffic(self):
        self.running = True  # Establece el estado de ejecución del análisis como verdadero
        iface = input("Ingrese la interfaz de red a analizar (ejemplo: eth0): ")  # Solicita al usuario la interfaz de red a analizar
        self.log_manager.add_log(f"Análisis de tráfico iniciado en la interfaz {iface}")  # Registra un mensaje de registro indicando que se ha iniciado el análisis de tráfico en la interfaz especificada

        def packet_capture():
            try:
                while self.running:
                    sniff(iface=iface, prn=self.process_packet, store=False, timeout=10)  # Captura paquetes en la interfaz especificada y los procesa usando self.process_packet
                    time.sleep(1)  # Pequeña pausa para evitar sobrecarga

            except Exception as e:
                self.log_manager.add_log(f"Error al analizar el tráfico de la red: {e}")  # Registra un mensaje de registro si ocurre un error durante el análisis de tráfico
                print(f"Error al analizar el tráfico de la red: {e}")  # Imprime un mensaje en la consola si ocurre un error durante el análisis de tráfico

        capture_thread = threading.Thread(target=packet_capture)  # Crea un hilo para la captura de paquetes
        capture_thread.start()  # Inicia el hilo de captura de paquetes

        while self.running:
            print("\nPresione Enter para continuar, o escriba 'salir' para detener:")  # Solicita al usuario que presione Enter para continuar o escriba 'salir' para detener el análisis
            command = input().lower()  # Lee la entrada del usuario y la convierte a minúsculas
            if command == 'salir':
                self.running = False  # Cambia el estado de ejecución del análisis a falso para detener el bucle while
                break

        capture_thread.join()  # Espera a que el hilo de captura de paquetes termine su ejecución
        self.log_manager.add_log("Análisis de tráfico detenido")  # Registra un mensaje de registro indicando que se ha detenido el análisis de tráfico

    def process_packet(self, packet):
        if packet.haslayer(ARP):  # Verifica si el paquete tiene una capa ARP
            self.log_manager.add_log(f"ARP Packet: {packet.summary()}")  # Registra un mensaje de registro con la información resumida del paquete ARP
            print(f"ARP Packet: {packet.summary()}")  # Imprime la información resumida del paquete ARP en la consola
        elif packet.haslayer(IP):  # Verifica si el paquete tiene una capa IP
            self.log_manager.add_log(f"IP Packet: {packet.summary()}")  # Registra un mensaje de registro con la información resumida del paquete IP
            print(f"IP Packet: {packet.summary()}")  # Imprime la información resumida del paquete IP en la consola

class LogManager:
    def __init__(self):  # Constructor que inicializa el objeto
        self.logs = []  # Inicializa una lista vacía para almacenar registros

    def add_log(self, message):
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Obtiene la marca de tiempo actual en formato 'YYYY-MM-DD HH:MM:SS'
        self.logs.append(f"{timestamp} - {message}")  # Agrega un nuevo registro con la marca de tiempo al mensaje especificado a la lista de registros

    def generate_log_file(self):
        with open("log.txt", "w") as log_file:  # Abre el archivo 'log.txt' en modo de escritura
            log_file.write("=== Log del Programa ===\n")  # Escribe un encabezado en el archivo de registro
            for log in self.logs:
                log_file.write(log + "\n")  # Escribe cada registro en una línea nueva en el archivo de registro

    def create_initial_log_file(self):
        with open("log.txt", "w") as log_file:  # Abre el archivo 'log.txt' en modo de escritura (crea un archivo nuevo o sobrescribe el existente)
            log_file.write("=== Log del Programa ===\n")  # Escribe un encabezado inicial en el archivo de registro

# Ejecutar el menú principal si el script se ejecuta como programa principal
if __name__ == "__main__":
    main_menu = MainMenu()  # Crea una instancia de la clase MainMenu para mostrar el menú principal
    main_menu.display_menu()  # Llama al método display_menu() para mostrar el menú principal y comenzar la interacción
