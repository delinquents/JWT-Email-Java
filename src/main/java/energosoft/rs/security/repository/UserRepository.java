package energosoft.rs.security.repository;

import energosoft.rs.security.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;

/**
 *  @Author: Veljko Siracki
 **/

@Repository
public interface UserRepository extends JpaRepository<User, Long> {


    User findUserByUsername(String username);
    User findUserByEmail(String email);

    @Modifying
    @Query("delete from User u where u.username = ?1 ")
    void deleteByUsername( String username);

}

