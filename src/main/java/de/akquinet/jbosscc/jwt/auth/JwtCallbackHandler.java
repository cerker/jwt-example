package de.akquinet.jbosscc.jwt.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

public class JwtCallbackHandler implements CallbackHandler {

    private static final Logger LOG = LoggerFactory.getLogger( JwtCallbackHandler.class );

    private transient String jwt;

    public JwtCallbackHandler( final String jwt ) {
        this.jwt = jwt;
    }

    @Override
    public void handle( final Callback[] callbacks ) throws IOException, UnsupportedCallbackException {
        for ( Callback callback : callbacks ) {
            if ( callback instanceof TextInputCallback ) {
                ( (TextInputCallback) callback ).setText( jwt );
            } else if ( callback instanceof NameCallback ) {
                String name = ( (NameCallback) callback ).getName();
                LOG.info( "Logging in with name: " + name );
            } else if ( callback instanceof PasswordCallback ) {
                char[] password = ( (PasswordCallback) callback ).getPassword();
                LOG.info( "Logging in with password: " + password );
            }
        }
    }
}
