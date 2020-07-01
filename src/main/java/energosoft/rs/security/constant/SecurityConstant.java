package energosoft.rs.security.constant;

public class SecurityConstant {
    public static final long EXPIRATION_TIME = 432_000_000; // 5 days expressed in milliseconds
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String JWT_TOKEN_HEADER = "Jwt-Token";
    public static final String TOKEN_CANNOT_BE_VERIFIED = "Token cannot be verified";
    public static final String GET_ARRAYS_LLC = "Energosoft ITSS";
    public static final String GET_ARRAYS_ADMINISTRATION = "User Management Portal";
    public static final String AUTHORITIES = "authorities";
    public static final String FORBIDDEN_MESSAGE = "You need to log in to access this page";
    public static final String ACCESS_DENIED_MESSAGE = "You do not have permission to access this page";
    public static final String OPTIONS_HTTP_METHOD = "OPTIONS";
    public static final String USERNAME_ALREADY_EXISTS = "Username already exist";
    public static final String EMAIL_ALREADY_EXISTS = "Email already exist";
    public static final String USER_NOT_FOUND_BY_USERNAME = "No user found by username ";
    public static final String NO_USER_FOUND_BY_EMAIL = "No user found for email: ";
//    public static final String[] PUBLIC_URLS = { "/user/login", "/user/register", "/user/image/**" };
    public static final String[] PUBLIC_URLS = { "**" };
}
