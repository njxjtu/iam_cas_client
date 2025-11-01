package iam.casclient.config;

import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class CustomUserDetailsService implements AuthenticationUserDetailsService<CasAssertionAuthenticationToken> {

    @Override
    public UserDetails loadUserDetails(CasAssertionAuthenticationToken token) throws UsernameNotFoundException {
        
        String username = token.getName(); // The username provided by CAS

        // --- REPLACE THIS WITH YOUR REAL AUTHORIZATION LOGIC ---
        // In a production app, you would fetch user roles from a database 
        // or directory (LDAP/AD) based on this username.
        List<GrantedAuthority> authorities = new ArrayList<>();
        
        if (username.equals("casuser")) { 
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
            authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        } else {
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        }
        
        // The password field is irrelevant as CAS handles authentication
        return new User(username, "NOT_USED", authorities);
    }
}