package de.akquinet.jbosscc.jwt.rs;

import de.akquinet.jbosscc.jwt.user.AuthenticationException;
import de.akquinet.jbosscc.jwt.auth.JwtManager;
import de.akquinet.jbosscc.jwt.dto.LoginRequest;
import de.akquinet.jbosscc.jwt.dto.LoginResponse;
import de.akquinet.jbosscc.jwt.user.User;
import de.akquinet.jbosscc.jwt.user.UserService;

import javax.annotation.Resource;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ejb.EJB;
import javax.ejb.EJBContext;
import javax.ejb.Stateless;
import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import java.util.logging.Logger;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static javax.ws.rs.core.Response.Status.UNAUTHORIZED;

@Path( "test" )
@Produces( APPLICATION_JSON )
@Consumes( APPLICATION_JSON )
@Stateless
public class TestResourceEjb {

    private static final Logger LOG = Logger.getLogger( TestResourceEjb.class.getName() );

    @EJB
    private UserService userService;

    @Inject
    private JwtManager jwtManager;

    @Resource
    private EJBContext ejbContext;

    @POST
    @Path( "login" )
    @PermitAll
    public Response login( final LoginRequest loginRequest ) {
        try {
            User user = userService.authenticate( loginRequest.getUsername(), loginRequest.getPassword() );
            String jwt = jwtManager.createToken( user.getName(), user.getRole() );
            LoginResponse response = new LoginResponse( user.getName(), user.getRole(), jwt );
            return Response.ok().entity( response ).build();
        } catch ( AuthenticationException e ) {
            LOG.warning( e.getMessage() );
            return Response.noContent().status( UNAUTHORIZED ).build();
        }
    }

    @GET
    @Path("helloGuest")
    @PermitAll
    public String helloGuest() {
        return sayHello();
    }

    @GET
    @Path("helloAdmin")
    @RolesAllowed( "admin" )
    public String helloAdmin() {
        return sayHello();
    }

    @GET
    @Path("helloCustomer")
    @RolesAllowed( "customer" )
    public String helloCustomer() {
        return sayHello();
    }

    private String sayHello() {
        String callerName = ejbContext.getCallerPrincipal().getName();
        return "Hello " + callerName + "!";
    }
}
