package iam.casclient;

import org.apereo.cas.client.session.SingleSignOutHttpSessionListener;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;

import jakarta.servlet.http.HttpSessionListener;

@SpringBootApplication
public class CasclientApplication {

	public static void main(String[] args) {
		SpringApplication.run(CasclientApplication.class, args);
	}

	// Register the listener bean here to make it active in the Servlet Container
    @Bean
    public ServletListenerRegistrationBean<HttpSessionListener> singleSignOutListener() {
        ServletListenerRegistrationBean<HttpSessionListener> listener = 
            new ServletListenerRegistrationBean<>();
        listener.setListener(new SingleSignOutHttpSessionListener());
        return listener;
    }
}
