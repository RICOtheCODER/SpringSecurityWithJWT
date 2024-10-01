package com.Security.SecurityDemo.config;

import com.Security.SecurityDemo.jwt.AuthEntryPointJwt;
import com.Security.SecurityDemo.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
//custom security configuration class
public class SecurityConfig {
    @Autowired
    DataSource dataSource;
    @Autowired
    private AuthEntryPointJwt authEntryPointJwt;
    @Bean
    public AuthTokenFilter authenticationJwtfilter(){
        return new AuthTokenFilter();
    }
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
//        httpSecurity.authorizeHttpRequests((requests)->requests.requestMatchers(toH2Console()).permitAll()
//                .requestMatchers("/h2-console/login.do").permitAll().anyRequest().authenticated());
//        httpSecurity.sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//       // http.headers().frameOptions().disable();
//        httpSecurity.headers(headers->headers.frameOptions(frameoptions->frameoptions.disable()));
//        httpSecurity.headers(headers->headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));
//        httpSecurity.csrf(csf->csf.disable());//important to allow all
//        //removes cookie tracking and enables stateless
//        httpSecurity.httpBasic(Customizer.withDefaults());
//        return httpSecurity.build();
        httpSecurity.authorizeHttpRequests(authorizeRequests->authorizeRequests.requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/sign-in").permitAll().anyRequest().authenticated());
        httpSecurity.sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        httpSecurity.exceptionHandling(exception->exception.authenticationEntryPoint(authEntryPointJwt));
        httpSecurity.headers(headers->headers.frameOptions(frameoptions->frameoptions.sameOrigin()));
        httpSecurity.csrf(csrf->csrf.disable());
        httpSecurity.addFilterBefore(authenticationJwtfilter(), UsernamePasswordAuthenticationFilter.class);
        return httpSecurity.build();
    }
    //in memory password username
    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource){
//        UserDetails user1= User.withUsername("user1").password(encoder().encode("password1"))
//                .roles("USER").build();
//        UserDetails admin=User.withUsername("admin").password(encoder().encode("admin")).roles("ADMIN").build();
//        JdbcUserDetailsManager userDetailsManager=new JdbcUserDetailsManager(dataSource);
//        //return new InMemoryUserDetailsManager(user1,admin);
//        userDetailsManager.createUser(user1);
//        userDetailsManager.createUser(admin);
//        return userDetailsManager;
        return new JdbcUserDetailsManager(dataSource);
    }
    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService){
        return args -> {
            JdbcUserDetailsManager manager=(JdbcUserDetailsManager) userDetailsService;
                UserDetails user1= User.withUsername("user1").password(encoder().encode("password1"))
                        .roles("USER").build();
                UserDetails admin=User.withUsername("admin").password(encoder().encode("admin")).roles("ADMIN").build();
                JdbcUserDetailsManager userDetailsManager=new JdbcUserDetailsManager(dataSource);
                //return new InMemoryUserDetailsManager(user1,admin);
                userDetailsManager.createUser(user1);
                userDetailsManager.createUser(admin);

        };
    }

    @Bean
    public PasswordEncoder encoder(){
            return new BCryptPasswordEncoder();
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception{
        return builder.getAuthenticationManager();
    }
}
