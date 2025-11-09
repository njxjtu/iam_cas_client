package iam.casclient.config;

import org.apereo.cas.client.session.SingleSignOutFilter;
import org.apereo.cas.client.validation.Cas20ServiceTicketValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import jakarta.servlet.http.HttpSessionListener;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // Properties injected from application.properties
    @Value("${cas.server.loginUrl}")
    private String casServerLoginUrl;

    @Value("${cas.client.serviceUrl}")
    private String casClientServiceUrl;

    @Value("${cas.server.validationUrl}")
    private String casValidationUrl;

    // --- Core Spring Security Beans (New Pattern) ---

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        
        // 1. Configure the request authorization rules
    	http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/login/cas", "/logout").permitAll() 
                .anyRequest().authenticated()
            )
            // 2. Configure the unauthenticated entry point (redirects to CAS login)
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint(casAuthenticationEntryPoint())
            )
            // 3. Add CAS filters to the chain
            .addFilter(casAuthenticationFilter(authenticationManager))
            .addFilterBefore(casSingleSignOutFilter(), CasAuthenticationFilter.class)
            .addFilterBefore(casLogoutFilter(), LogoutFilter.class) // Custom logout filter
            .csrf(csrf -> csrf.disable());// Disable CSRF for simplicity in this CAS example
            
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        // Register the CasAuthenticationProvider with the AuthenticationManager
        return new ProviderManager(Arrays.asList(casAuthenticationProvider()));
    }

    // --- CAS-Specific Provider and Filter Beans ---

    @Bean
    public CasAuthenticationProvider casAuthenticationProvider() {
        CasAuthenticationProvider provider = new CasAuthenticationProvider();
        provider.setServiceProperties(serviceProperties());
        provider.setTicketValidator(new Cas20ServiceTicketValidator(casValidationUrl));
        
        // Custom logic to load user roles after CAS authentication
        provider.setAuthenticationUserDetailsService(new CustomUserDetailsService());
        
        provider.setKey("cas_client_key_for_hashing");
        return provider;
    }

    @Bean
    public CasAuthenticationFilter casAuthenticationFilter(AuthenticationManager authenticationManager) {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManager);
        filter.setServiceProperties(serviceProperties());
        // Set the URL that triggers the filter after CAS redirect
        filter.setFilterProcessesUrl("/login/cas"); 
        return filter;
    }

    // --- CAS-Specific Utility Beans ---

    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService(casClientServiceUrl);
        serviceProperties.setSendRenew(false);
        return serviceProperties;
    }

    @Bean
    public CasAuthenticationEntryPoint casAuthenticationEntryPoint() {
        CasAuthenticationEntryPoint entryPoint = new CasAuthenticationEntryPoint();
        entryPoint.setLoginUrl(casServerLoginUrl);
        entryPoint.setServiceProperties(serviceProperties());
        return entryPoint;
    }

    @Bean
    public SingleSignOutFilter casSingleSignOutFilter() {
    	return new SingleSignOutFilter();
    }
    
    @Bean
    public LogoutFilter casLogoutFilter() {
        // Redirects to CAS server logout URL after logging out of the client app
        String casLogoutUrl = casServerLoginUrl.substring(0, casServerLoginUrl.lastIndexOf('/')) + "/logout";
        
        // Local logout handler clears the Spring Security context
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.setInvalidateHttpSession(true);
        
        // This filter is triggered by /logout in the client app
        return new LogoutFilter(casLogoutUrl, logoutHandler);
    }
    
    // New bean required for Single Logout (SLO) configuration
    @Bean
    public HttpSessionListener httpSessionListener() {
        // This listener is registered to clean up sessions during CAS-initiated logouts
        return new org.apereo.cas.client.session.SingleSignOutHttpSessionListener();
    }
}