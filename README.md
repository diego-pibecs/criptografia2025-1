# secure-comm-protocol
Este repositorio corresponde al proyecto de la materia de Criptografía que consiste en la creación de un protocolo seguro de comunicación que implementará cifrado asimétrico, cifrado simétrico y una aplicación web para realizar la comunicación. 

## Institución 
**Universidad Nacional Autónoma de México**
Facultad de Ingeniería

**Proyecto 1**  Implementación de un protocolo de comunicación segura

## Autores ✒️

- **Arroyo Moreno Diego Alejandro** 
- **Ceron Maciel Eduardo Alfredo** 
- **Miranda Bueno Fatima Yolanda** 
- **Ortega Gaytán Alan Eduardo** 


## Comenzando 🚀

Para comenzar, se debe de clonar el repositorio de la siguiente manera:

```bash
git clone https://github.com/diego-pibecs/criptografia2025-1.git
```
Y debemos asegurarnos que estemos en la rama main:

```bash
git branch -a
```

### Pre-requisitos 📋

- Es necesario tener Python instalado, al menos la versión 3.10.
- Tener instalado el manejador de paquetes _pip_.

Los siquientes módulos de Python son necesarios: 

- bidict==0.23.1
- blinker==1.8.2
- cffi==1.17.1
- click==8.1.7
- colorama==0.4.6
- cryptography==43.0.3
- Flask==3.0.3
- Flask-SocketIO==5.4.1
- h11==0.14.0
- itsdangerous==2.2.0
- Jinja2==3.1.4
- MarkupSafe==3.0.2
- pycparser==2.22
- pycryptodome==3.21.0
- python-engineio==4.10.1
- python-socketio==5.11.4
- simple-websocket==1.1.0
- Werkzeug==3.0.6
- wsproto==1.2.0

_Es recomendable tener Git instalado para poder clonar el repositorio, aunque no es la única forma de hacerlo._

### Instalación 🔧

Para poder generar un entorno virtual con python se debe de ejecutar el comando:

```bash
python -m venv <nombre_del_entorno_virtual>
```
 
Si lo ejecutas en otro sistema operativo como MacOs o Linux puedes probar con el comando:

```bash
python3 -m venv <nombre_del_entorno_virtual>
```

Para activar el entorno virtual en Windows:

```bash
.<nombre_del_entorno_virtual>\Scripts\activate
```

Para activar el entorno virtual en MacOS o Linux:

```bash
source <nombre_del_entorno_virtual>/bin/activate
```

Para instalar los módulos rápidamente con el archivo requirements.txt 

```bash
pip install -r requirements.txt
```

Para verificar que los módulos se han instalado correctamente, puedes ejecutar el comando:

```bash
pip freeze
```

## Despliegue 📦

Para poder desplegar la aplicación web, ejecuta el comando:

```bash
python app.py
```

Si el comando anterior no funciona, intenta con:

```bash
python3 app.py
```
## Construido con 🛠️

Las herramientas utilizadas para el desarrollo del proyeto:_

* [Flask](https://flask.palletsprojects.com/en/stable/) - Micro-framework web para Python que facilita el desarrollo de aplicaciones y APIs.
* [pycryptodome](https://pypi.org/project/pycryptodome/) - Biblioteca para realizar operaciones criptográficas y gestionar claves en Python.
* [Flask-SocketIO](https://flask-socketio.readthedocs.io/en/latest/intro.html) - Extensión de Flask que permite la comunicación en tiempo real con WebSockets.
* [cryptography](https://pypi.org/project/cryptography/) - Biblioteca que proporciona herramientas para implementar criptografía de forma segura en Python.
