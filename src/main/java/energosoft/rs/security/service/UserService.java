package energosoft.rs.security.service;

import energosoft.rs.security.domain.UserEntity;
import energosoft.rs.security.exception.domain.EmailExistException;
import energosoft.rs.security.exception.domain.EmailNotFoundException;
import energosoft.rs.security.exception.domain.UserNotFoundException;
import energosoft.rs.security.exception.domain.UsernameExistException;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.List;

public interface UserService {

    UserEntity register(String firstName, String lastName, String username, String email) throws UserNotFoundException, UsernameExistException, EmailExistException, MessagingException;
    List<UserEntity> getUsers();
    UserEntity findUserByUsername(String username);
    UserEntity findUserByEmail(String email);

    UserEntity addNewUser(String firstName, String lastName,
                          String username, String email,
                          String role, boolean isNonLocked,
                          boolean isActive, MultipartFile profileImage) throws UserNotFoundException, UsernameExistException, EmailExistException, IOException;

    UserEntity updateUser(String currentUsername, String newFirstName , String newLastName,
                          String newUsername, String newEmail,
                          String role, boolean isNonLocked,
                          boolean isActive, MultipartFile profileImage) throws UserNotFoundException, UsernameExistException, EmailExistException, IOException;

    void deleteUser(long id);
    void resetPassword(String email) throws EmailNotFoundException, MessagingException;
    UserEntity updateProfileImage(String username, MultipartFile profileImage) throws UserNotFoundException, UsernameExistException, EmailExistException, IOException;

}
