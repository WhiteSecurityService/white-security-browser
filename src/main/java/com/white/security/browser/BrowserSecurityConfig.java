package com.white.security.browser;

import com.white.security.browser.session.WhiteExpiredSessionStrategy;
import com.white.security.core.authentication.FormAuthenticationConfig;
import com.white.security.core.authentication.mobile.SmsCodeAuthenticationSecurityConfig;
import com.white.security.core.properties.SecurityConstants;
import com.white.security.core.properties.SecurityProperties;
import com.white.security.core.validate.ValidateCodeSecurityConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.social.security.SpringSocialConfigurer;

import javax.annotation.Resource;
import javax.sql.DataSource;

/**
 * All rights Reserved, Designed by xxxx
 *
 * @Author: White
 * @Date: 2018/9/7
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private SecurityProperties securityProperties;

    @Autowired
    private AuthenticationSuccessHandler whiteAuthenticationSuccessHandler;

    @Autowired
    private AuthenticationFailureHandler whiteAuthenticationFailureHandler;

    @Resource
    private DataSource dataSource;

    @Resource
    private UserDetailsService userDetailsService;

    @Autowired
    private ValidateCodeSecurityConfig validateCodeSecurityConfig;

    @Autowired
    private SmsCodeAuthenticationSecurityConfig smsCodeAuthenticationSecurityConfig;

    @Autowired
    private FormAuthenticationConfig formAuthenticationConfig;

    @Autowired
    private SpringSocialConfigurer whiteSocialSecurityConfig;

    @Autowired
    private InvalidSessionStrategy invalidSessionStrategy;

    @Autowired
    private SessionInformationExpiredStrategy sessionInformationExpiredStrategy;

    @Autowired
    private LogoutSuccessHandler logoutSuccessHandler;

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl tokenRepository = new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
//        tokenRepository.setCreateTableOnStartup(true);
        return tokenRepository;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // 表单配置
        formAuthenticationConfig.configure(http);

        http.apply(validateCodeSecurityConfig)
                    .and()
                .apply(smsCodeAuthenticationSecurityConfig)
                    .and()
                .apply(whiteSocialSecurityConfig)
                    .and()
                // 记住我配置
                .rememberMe()
                    .tokenRepository(persistentTokenRepository())
                    .tokenValiditySeconds(securityProperties.getBrowser().getRememberMeSeconds())
                    .userDetailsService(userDetailsService)
                    .and()
                .sessionManagement()
                    .invalidSessionStrategy(invalidSessionStrategy)
                    .maximumSessions(securityProperties.getBrowser().getSession().getMaximumSessions())
                    .maxSessionsPreventsLogin(securityProperties.getBrowser().getSession().isMaxSessionsPreventsLogin())
                    .expiredSessionStrategy(sessionInformationExpiredStrategy)
                    .and()
                    .and()
                .logout()
                    .logoutUrl("/signOut")
//                    .logoutSuccessUrl("white-logout.html")
                    .logoutSuccessHandler(logoutSuccessHandler)
                    .deleteCookies("JSESSIONID")
                    .and()
                .authorizeRequests() // 定义哪些URL需要被保护、哪些不需要被保护
                    .antMatchers(SecurityConstants.DEFAULT_UNAUTHENTICATION_URL,
                            SecurityConstants.DEFAULT_LOGIN_PROCESSING_URL_MOBILE,
                            securityProperties.getBrowser().getSignInPage(),
                            SecurityConstants.DEFAULT_VALIDATE_CODE_URL_PREFIX + "/*",
                            securityProperties.getBrowser().getSignUpUrl(),
                            securityProperties.getBrowser().getSession().getSessionInvalidUrl(),
                            securityProperties.getBrowser().getSignOutUrl(),
                            "/user/register").permitAll()
                    .anyRequest()
                    .authenticated() // 任何请求,登录后可以访问
                    .and()
                .csrf().disable();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**", "/css/**");
    }
}
