package de.akquinet.jbosscc.jwt.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;

import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.CredentialExpiredException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.security.Principal;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

@SuppressWarnings( "UnusedDeclaration" ) // used by the container
public class JwtLoginModule implements LoginModule {

    private static final Logger LOG = Logger.getLogger( JwtLoginModule.class.getName() );

    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map<String, ?> sharedState;
    private Map<String, ?> options;

    private Principal identity;
    private Principal group;

    @Override
    public void initialize( Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options ) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;
    }

    @Override
    public boolean login() throws LoginException {
        String jwt = getJwt();

        if ( jwt != null ) {
            try {
                LOG.info( "JWT provided" );

                JwtManager jwtManager = lookupJwtManager();

                // verify the received token
                Jws<Claims> jws = jwtManager.parseToken( jwt );

                // now we can trust its information...
                String user = jws.getBody().getSubject();
                identity = new SimplePrincipal( user );

                String role = (String) jws.getBody().get( "role" );
                group = new SimplePrincipal( role );

                LOG.info( "JWT is valid, logging in user " + user + " with role " + role );

                return true;
            } catch ( SignatureException | MalformedJwtException
                    | UnsupportedJwtException | IllegalArgumentException e ) {
                throw new FailedLoginException( "Invalid security token provided" );
            } catch ( ExpiredJwtException e ) {
                throw new CredentialExpiredException( "The security token is expired" );
            }
        }
        return false;
    }

    @Override
    public boolean commit() throws LoginException {
        Set<Principal> principals = subject.getPrincipals();
        principals.add( identity );

        SimpleGroup roles = new SimpleGroup( "Roles" );
        roles.addMember( group );
        principals.add( roles );

        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        identity = null;
        group = null;
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        identity = null;
        group = null;
        return true;
    }


//    @Override
//    public boolean login() throws LoginException {
//        loginOk = false;
//
//        String jwt = getJwt();
//
//        if ( jwt != null ) {
//            try {
//                LOG.info( "JWT provided" );
//
//                JwtManager jwtManager = lookupJwtManager();
//
//                // verify the received token
//                Jws<Claims> jws = jwtManager.parseToken( jwt );
//
//                // now we can trust its information...
//                String subject = jws.getBody().getSubject();
//                identity = new SimplePrincipal( subject );
//
//                String role = (String) jws.getBody().get( "role" );
//                group = new SimplePrincipal( role );
//
//                LOG.info( "JWT is valid, logging in user " + subject + " with role " + role );
//
//                loginOk = true;
//
//                return true;
//            } catch ( SignatureException | MalformedJwtException
//                    | UnsupportedJwtException | IllegalArgumentException e ) {
//                throw new FailedLoginException( "Invalid security token provided" );
//            } catch ( ExpiredJwtException e ) {
//                throw new CredentialExpiredException( "The security token is expired" );
//            }
//        }
//        return false;
//    }

//    @Override
//    protected Principal getIdentity() {
//        return identity;
//    }

//    @Override
//    protected Group[] getRoleSets() throws LoginException {
//        SimpleGroup roles = new SimpleGroup( "Roles" );
//        roles.addMember( group );
//        return new Group[]{roles};
//    }

    private String getJwt() throws LoginException {
        NameCallback callback = new NameCallback( "prompt" );
        try {
            callbackHandler.handle( new Callback[]{callback} );
            return callback.getName();
        } catch ( IOException | UnsupportedCallbackException e ) {
            String msg = "Failed getting the security token";
            LOG.log( Level.SEVERE, msg, e );
            throw new LoginException( msg );
        }
//        } else if ( callbackHandler instanceof JBossCallbackHandler ) {
//            try {
//                SecurityAssociationCallback callback = new SecurityAssociationCallback();
//                callbackHandler.handle( new Callback[]{callback} );
//                Object credential = callback.getCredential();
//                Principal principal = callback.getPrincipal();
//                LOG.info( "credential=" + credential + ", principal=" + principal );
//            } catch ( IOException | UnsupportedCallbackException e ) {
//                e.printStackTrace();
//            }
    }

    private JwtManager lookupJwtManager() {
        try {
            BeanManager beanManager = InitialContext.doLookup( "java:comp/BeanManager" );
            Set<Bean<?>> beans = beanManager.getBeans( JwtManager.class );
            if ( beans.isEmpty() ) {
                throw new RuntimeException( "Failed looking up CDI Bean " + JwtManager.class.getName()
                                                    + ": Found " + beans.size() + " " );
            }
            Bean<?> bean = beans.iterator().next();
            CreationalContext<?> context = beanManager.createCreationalContext( bean );
            return (JwtManager) beanManager.getReference( bean, JwtManager.class, context );
        } catch ( NamingException e ) {
            throw new RuntimeException( e );
        }
    }
}
