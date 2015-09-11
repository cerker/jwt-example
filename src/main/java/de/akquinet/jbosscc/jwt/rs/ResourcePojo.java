package de.akquinet.jbosscc.jwt.rs;


import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;
import java.security.Principal;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;

@Path( "pojo" )
@Produces( APPLICATION_JSON )
@Consumes( APPLICATION_JSON )
public class ResourcePojo {

    @Context
    private SecurityContext securityContext;

    @GET
    @Path( "helloGuest" )
    @PermitAll
    public String helloGuest() {
        return sayHello();
    }

    @GET
    @Path( "helloAdmin" )
    @RolesAllowed( "admin" )
    public String helloAdmin() {
        return sayHello();
    }

    @GET
    @Path( "helloCustomer" )
    @RolesAllowed( "customer" )
    public String helloCustomer() {
        return sayHello();
    }

    private String sayHello() {
        Principal userPrincipal = securityContext.getUserPrincipal();
        String callerName = userPrincipal == null ? "anonymous" : userPrincipal.getName();
        return "Hello " + callerName + "!";
    }
}
