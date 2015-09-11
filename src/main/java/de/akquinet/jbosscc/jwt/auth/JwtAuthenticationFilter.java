package de.akquinet.jbosscc.jwt.auth;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

@WebFilter( "/*" )
public class JwtAuthenticationFilter implements Filter {

    private static final java.util.logging.Logger LOG = Logger.getLogger( JwtAuthenticationFilter.class.getName() );

    private static final String AUTH_HEADER_KEY = "Authorization";
    private static final String AUTH_HEADER_VALUE_PREFIX = "Bearer "; // with trailing space to separate token

    @Override
    public void init( FilterConfig filterConfig ) throws ServletException {
        LOG.info( "JwtAuthenticationFilter initialized" );
    }

    @Override
    public void doFilter( ServletRequest request,
                          ServletResponse response,
                          FilterChain chain ) throws IOException, ServletException {
        try {
            String jwt = getBearerToken( (HttpServletRequest) request );
            if ( jwt != null && !jwt.isEmpty() ) {
                ( (HttpServletRequest) request ).login( jwt, "" );
                LOG.info( "Logged in using JWT" );
            } else {
                LOG.info( "No JWT provided, go on unauthenticated" );
            }
        } catch ( final Exception e ) {
            LOG.log( Level.WARNING, "Failed getting security token and logging in", e );
        } finally {
            chain.doFilter( request, response );
        }
    }

    @Override
    public void destroy() {

    }

    /**
     * Get the bearer token from the HTTP request.
     * The token is in the HTTP request "Authorization" header in the form of: "Bearer [token]"
     */
    private String getBearerToken( HttpServletRequest request ) {
        String authHeader = request.getHeader( AUTH_HEADER_KEY );
        if ( authHeader != null && authHeader.startsWith( AUTH_HEADER_VALUE_PREFIX ) ) {
            return authHeader.substring( AUTH_HEADER_VALUE_PREFIX.length() );
        }
        return null;
    }
}
