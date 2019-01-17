package com.redgate.jira.auth.httpheader;

import com.atlassian.seraph.auth.AuthenticatorException;
import org.apache.log4j.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;

public class HttpHeaderAuthenticator extends com.atlassian.jira.security.login.JiraSeraphAuthenticator
{
    private static final Logger log = Logger.getLogger(HttpHeaderAuthenticator.class);

    @Override
    public Principal getUser(HttpServletRequest request, HttpServletResponse response) {
        Principal user = super.getUser(request, response);

        if(user != null) {
            // JIRA already knows this authenticated user. (either via session, cookie or basic auth.)
            return user;
        }

        // attempt to login this user via HTTP Headers.
        return getUserViaHttpHeaders(request, response);
    }

    private Principal getUserViaHttpHeaders(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getHeader("X-Forwarded-Login");

        if(username == null){
            log.warn("X-Forwarded-Login header is missing. Unknown user. ¯\\\\_(ツ)_/¯");
            return null;
        }

        log.info(String.format("X-Forwarded-Login header found for %s. Logging user in.", username));

        // get user from JIRA matching the username.
        Principal user = getUser(username);

        if(user == null) {
            log.warn(String.format("X-Forwarded-Login header was set to %s which is not a known user.", username));
            return null;
        }

        this.authoriseUserAndEstablishSession(request, response, user);
        // Set the remember me cookie to work around suspected "Bot Killer plugin" bug which ends up
        // destroying sessions after 1h of inactivity rather than 5
        this.getRememberMeService().addRememberMeCookie(request, response, username);
        this.getElevatedSecurityGuard().onSuccessfulLoginAttempt(request, username);
        return user;
    }

    @Override
    protected boolean authenticate(Principal user, String password) throws AuthenticatorException {
        // do NOT override the default authenticate as we still want JIRA to perform the right thing
        // to authenticate a user with password. (Required to be able to use Basic Auth)
        return super.authenticate(user, password);
    }
}
