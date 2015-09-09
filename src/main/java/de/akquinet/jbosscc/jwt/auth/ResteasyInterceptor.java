package de.akquinet.jbosscc.jwt.auth;

import org.jboss.resteasy.annotations.interception.Precedence;
import org.jboss.resteasy.annotations.interception.ServerInterceptor;
import org.jboss.resteasy.core.ResourceMethod;
import org.jboss.resteasy.core.ServerResponse;
import org.jboss.resteasy.spi.Failure;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.interception.PreProcessInterceptor;
import org.jboss.security.auth.callback.UsernamePasswordHandler;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.ext.Provider;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

@Provider
@ServerInterceptor
@Precedence("JWT_SECURITY")
public class ResteasyInterceptor implements PreProcessInterceptor {

    private static final Logger LOG = Logger.getLogger( ResteasyInterceptor.class.getName() );

    private static final String AUTH_HEADER_KEY = "Authorization";
    private static final String AUTH_HEADER_VALUE_PREFIX = "Bearer "; // with trailing space to separate token

    @Override
    public ServerResponse preProcess( HttpRequest request, ResourceMethod method )
            throws Failure, WebApplicationException {

        String jwt = getBearerToken( request );

        if ( jwt != null ) {
            LOG.info( "JWT provided, try to log in..." );
            UsernamePasswordHandler callbackHandler = new UsernamePasswordHandler( jwt, "".toCharArray() );
            try {
                LoginContext loginContext = new LoginContext( "jwt-security", callbackHandler );
                loginContext.login();
            } catch ( LoginException e ) {
                LOG.log( Level.WARNING, "Failed logging in with JWT", e );
            }
        }

        // go on without authentication
        return null;
    }

    /**
     * Get the bearer token from the HTTP request.
     * The token is in the HTTP request "Authorization" header in the form of: "Bearer [token]"
     */
    private String getBearerToken( HttpRequest request ) {
        List<String> authHeaders = request.getHttpHeaders().getRequestHeader( AUTH_HEADER_KEY );
        if ( authHeaders != null && !authHeaders.isEmpty() ) {
            String authHeader = authHeaders.get( 0 ).trim();
            if ( authHeader.startsWith( AUTH_HEADER_VALUE_PREFIX ) ) {
                return authHeader.substring( AUTH_HEADER_VALUE_PREFIX.length() );
            }
        }
        return null;
    }
}
