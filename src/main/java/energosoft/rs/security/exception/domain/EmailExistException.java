package energosoft.rs.security.exception.domain;

/**
 *  @Author: Veljko Siracki
 **/

public class EmailExistException extends Exception {

    public EmailExistException(String message) {
        super(message);
    }
}
