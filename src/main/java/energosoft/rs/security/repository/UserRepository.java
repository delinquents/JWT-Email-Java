package energosoft.rs.security.repository;

import energosoft.rs.security.domain.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {


    UserEntity findUserEntityByUsername(String username);
    UserEntity findUserEntityByEmail(String email);


}

