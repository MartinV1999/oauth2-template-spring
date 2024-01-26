package com.martin.springboot.security.authserver.auth.server;

import com.martin.springboot.security.authserver.auth.server.models.Role;
import com.martin.springboot.security.authserver.auth.server.models.User;
import com.martin.springboot.security.authserver.auth.server.services.RoleService;
import com.martin.springboot.security.authserver.auth.server.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;

import java.util.Optional;

@SpringBootApplication
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@Component
	public class Inicializador implements ApplicationListener<ContextRefreshedEvent> {
		@Autowired
		private UserService userService;

		@Autowired
		private RoleService roleService;

		public void InicializadorUser(UserService userService, RoleService roleService) {
			this.userService = userService;
			this.roleService = roleService;
		}

		// Método que se ejecuta al iniciar la aplicación
		@Override
		public void onApplicationEvent(ContextRefreshedEvent event) {
			// Verifica si es la primera vez que se inicia la aplicación
			Long id = 1L;
			Optional<User> op = userService.findById(id);
			Optional<Role> or = roleService.findByName("ROLE_ADMIN");

			if (event.getApplicationContext().getParent() == null && !op.isPresent() && !or.isPresent()) {
				// Lógica de inicialización (por ejemplo, insertar el usuario maestro)
				insertarRoles();
				insertarUsuarioMaestro();
			}
		}
		// Método para insertar un usuario maestro
		private void insertarUsuarioMaestro() {
			User user = new User();

			user.setUsername("admin");
			user.setEmail("admin@correo.cl");
			user.setPassword("admin");

			userService.save(user);
			System.out.println("Usuario maestro insertado correctamente.");
		}
		private void insertarRoles(){
			roleService.save("ROLE_ADMIN");
			roleService.save("ROLE_USER");
			System.out.println("Roles insertados");
		}
	}


}
