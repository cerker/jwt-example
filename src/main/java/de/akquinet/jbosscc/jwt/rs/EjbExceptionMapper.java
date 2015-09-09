package de.akquinet.jbosscc.jwt.rs;

import javax.ejb.EJBAccessException;
import javax.ejb.EJBException;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

@Provider
public class EjbExceptionMapper implements ExceptionMapper<EJBException> {

    @Override
    public Response toResponse( EJBException exception ) {
        if ( exception instanceof EJBAccessException ) {
            Response.Status status = Response.Status.UNAUTHORIZED;
            return response( status );
        }
        return response( Response.Status.INTERNAL_SERVER_ERROR );
    }

    private Response response( Response.Status status ) {return Response.noContent().status( status ).build();}
}
