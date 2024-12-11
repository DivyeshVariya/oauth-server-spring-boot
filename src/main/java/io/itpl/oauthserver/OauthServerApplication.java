package io.itpl.oauthserver;

import io.itpl.oauthserver.config.RSAKeyRecord;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(RSAKeyRecord.class)
@SpringBootApplication
public class OauthServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(OauthServerApplication.class, args);
	}

}
