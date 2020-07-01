package energosoft.rs.security.service;


import energosoft.rs.security.domain.UserEntity;
import energosoft.rs.security.exception.domain.EmailExistException;
import energosoft.rs.security.exception.domain.UserNotFoundException;
import energosoft.rs.security.exception.domain.UsernameExistException;

import java.util.List;

public interface UserService {

    UserEntity register(String firstName, String lastName, String username, String email) throws UserNotFoundException, UsernameExistException, EmailExistException;

    List<UserEntity> getUsers();

    UserEntity findUserByUsername(String username);

    UserEntity findUserByEmail(String email);
}
