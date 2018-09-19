package com.white.security.browser.session;

import com.white.security.core.properties.SecurityProperties;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import javax.servlet.ServletException;
import java.io.IOException;

/**
 * All rights Reserved, Designed by xxxx
 *
 * @Author: White
 * @Date: 2018/9/19
 */
public class WhiteExpiredSessionStrategy extends AbstractSessionStrategy implements SessionInformationExpiredStrategy {

    public WhiteExpiredSessionStrategy(SecurityProperties securityProperties) {
        super(securityProperties);
    }

    public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException, ServletException {
        onSessionInvalid(event.getRequest(), event.getResponse());
    }

//    public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException, ServletException {
//        event.getResponse().setContentType("application/json;charset=UTF-8");
//        event.getResponse().getWriter().write("并发登录!");
//    }


    @Override
    protected boolean isConcurrency() {
        return true;
    }
}
