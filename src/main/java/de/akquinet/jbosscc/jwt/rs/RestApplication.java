package de.akquinet.jbosscc.jwt.rs;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

/**
 * Configures the JAX-RS subsystem for the application.
 */
@ApplicationPath( "/" )
public class RestApplication extends Application {
}
