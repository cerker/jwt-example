package de.akquinet.jbosscc.jwt.user;

import javax.annotation.security.PermitAll;
import javax.ejb.Stateless;
import java.util.HashMap;
import java.util.Map;

@Stateless
@PermitAll
public class UserService {

    private static final Map<String, User> USER_DB = new HashMap<String, User>() {{
        put( "customer", new User( "customer", "customerpw", UserRoles.CUSTOMER ) );
        put( "admin", new User( "admin", "adminpw", UserRoles.ADMIN ) );
    }};

    public User authenticate( final String username, final String password ) {
        User user = USER_DB.get( username );
        if ( user != null && user.getPassword().equals( password ) ) {
            return user;
        }
        throw new SecurityException( "Failed logging in user with name '" + username
                                             + "': unknown username or wrong password" );
    }
}
