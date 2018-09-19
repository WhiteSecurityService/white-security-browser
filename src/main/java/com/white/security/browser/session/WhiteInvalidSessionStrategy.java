package com.white.security.browser.session;

import com.white.security.core.properties.SecurityProperties;
import org.springframework.security.web.session.InvalidSessionStrategy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 默认Session失效策略
 *
 * @Author: White
 * @Date: 2018/9/19
 */
public class WhiteInvalidSessionStrategy extends AbstractSessionStrategy implements InvalidSessionStrategy {

    public WhiteInvalidSessionStrategy(SecurityProperties securityProperties) {
        super(securityProperties);
    }

    public void onInvalidSessionDetected(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        onSessionInvalid(request, response);
    }
}
