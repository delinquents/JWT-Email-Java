package energosoft.rs.security.service;


import energosoft.rs.security.domain.UserEntity;

public interface UserService {
    UserEntity findUserEntityByUsername(String username);
}
