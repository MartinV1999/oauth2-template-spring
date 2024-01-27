# Spring OAuth2 Authentication Server

Template que proporciona la autenticación del usuario, se crea el usuario de prueba automaticamente junto a su rol (se puede cambiar en la BD), en este proyecto se usó el gestor de base de datos PostgreSQL para obtener al usuario. En ocasiones no se relaciona el rol del usuario , basta con insertarlo manualmente en la base de datos. (INSERT INTO users_roles (user_id, role_id) VALUES (1 , 1))

### Las credenciales del resource-server: 
- username: client-app
- password: 12345 <-- en la configuración de spring security se encripta con BCrypt, en caso que no se utilice se debe borrar el autowired de PasswordEncoder.

### Credenciales del Usuario:
- username: admin@correo.cl
- password: admin

# Flujo de inicio de sesión:

- Paso 1: Correr proyectos en el siguiente orden , primero authentication server y luego resource-server.
- Paso 2: ir a la siguiente ruta -> http://127.0.0.1:9000/login , luego ingresar credenciales del usuario.
- Paso 3: Copiar codigo , abrir postman seleccionar como metodo de Authorización  "Basic Auth", ingresar credenciales del resource-server , enviar petición tipo POST. Luego ingresar los datos como en la imagen (en code va el codigo obtenido)

![image](https://github.com/MartinV1999/oauth2-template-spring/assets/96119356/f7042330-6910-45b0-a1ce-41258dbbc616)

Paso 4: Obtener el token (JWT) con la información del usuario, probar con las rutas protegidas.

# Link hacia el resource server template

https://github.com/MartinV1999/oauth2-template-spring-resource-server
