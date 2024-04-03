package com.inn.cafe.JWT;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    CustomerUsersDetailsService customerUsersDetailsService;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customerUsersDetailsService);
//                .passwordEncoder(passwordEncoder());
    }

    @Autowired
    JwtFilter jwtFilter;

    //    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return NoOpPasswordEncoder.getInstance();
//    }
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean(name = BeanIds.AUTHENTICATION_MANAGER)
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues())
                .and()
                .csrf().disable()
                .authorizeHttpRequests()
//                .antMatchers("/user/login", "/user/signup", "/user/forgotPassword")
                .requestMatchers("/user/login", "/user/signup", "/user/forgotPassword")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and().exceptionHandling()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
//                .and()
//                .csrf().disable()
//                .authorizeRequests(authorize -> authorize
//                        .antMatchers(HttpMethod.POST, "/user/login", "/user/signup", "/user/forgotPassword").permitAll()
//                        .anyRequest().authenticated())
//                .exceptionHandling()
//                .and()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                // Configure authorization rules as needed
//                .anyRequest().authenticated()
//                .and()
//                .formLogin()
//                // Configure form login details as needed
//                .and()
//                .httpBasic();
//
//        return http.build();
//    }


//    @Bean
//    public WebSecurityCustomizer webSecurityCustomizer() {
//
//    }

//    @Bean
//    public SecurityFilterChain filterChain(AuthenticationManagerBuilder auth) throws Exception {
//        return auth.userDetailsService(customerUsersDetailsService);
//    }

//@Bean
//public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManagerBuilder auth) throws Exception {
//    http
//            .authorizeRequests()
//            // Configure authorization rules as needed
//            .anyRequest().authenticated()
//            .and()
//            .formLogin()
//            // Configure form login details as needed
//            .and()
//            .httpBasic();
//    auth.userDetailsService(customerUsersDetailsService);
//
//    return http.build();
//}

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(customerUsersDetailsService);
//    }
}
