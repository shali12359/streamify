package com.streamify.authentication;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = {"com.streamify.authentication"})
public class AuthenticationApplication {

	public static void main(String[] args) {

		SpringApplication.run(AuthenticationApplication.class, args);
	}

}
