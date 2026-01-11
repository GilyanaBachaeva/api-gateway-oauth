package fileconverter.apigateway.security;

import lombok.Data;

@Data
public class RouteRole {
    private String path;
    private String role;
}
