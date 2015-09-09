package de.akquinet.jbosscc.jwt.dto;

public class LoginResponse {

    private String username;
    private String role;
    private String jwt;

    public LoginResponse( String username, String role, String jwt ) {
        this.username = username;
        this.role = role;
        this.jwt = jwt;
    }

    public String getUsername() {
        return username;
    }

    public String getRole() {
        return role;
    }

    public String getJwt() {
        return jwt;
    }
}
