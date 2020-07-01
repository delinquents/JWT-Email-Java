package energosoft.rs.security.service.impl;


import energosoft.rs.security.domain.UserEntity;
import energosoft.rs.security.domain.UserPrincipal;
import energosoft.rs.security.enumeration.Role;
import energosoft.rs.security.exception.domain.EmailExistException;
import energosoft.rs.security.exception.domain.UserNotFoundException;
import energosoft.rs.security.exception.domain.UsernameExistException;
import energosoft.rs.security.repository.UserRepository;
import energosoft.rs.security.service.UserService;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.transaction.Transactional;
import java.util.Date;
import java.util.List;

import static energosoft.rs.security.constant.SecurityConstant.*;

@Service
@Transactional
@Qualifier("userDetailsService")
public class UserServiceImpl implements UserService, UserDetailsService {

    private Logger LOGGER = LoggerFactory.getLogger(getClass());
    private UserRepository userRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    public UserServiceImpl(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = userRepository.findUserEntityByUsername(username);
                if (user == null) {
                    LOGGER.error(USER_NOT_FOUND_BY_USERNAME + username);
                   throw new UsernameNotFoundException("User not found by username:" + username);
                } else {
                    user.setLastLoginDateDisplay(user.getLastLoginDate());
                    user.setLastLoginDate(new Date());
                    userRepository.save(user);
                    UserPrincipal userPrincipal = new UserPrincipal(user);
                    LOGGER.info("Returning found user by username: " + username);
                    return userPrincipal;
                }
    }


    @Override
    public UserEntity register(String firstName, String lastName, String username, String email) throws UserNotFoundException, UsernameExistException, EmailExistException {
        validateNewUsernameAndEmail(StringUtils.EMPTY, username, email);
        UserEntity user = new UserEntity();
        user.setUserId(generateUserId());
        String password = generatePassword();
        String encodedPassword = encodePassword(password);
        user.setFirstName(firstName);;
        user.setLastName(lastName);
        user.setUsername(username);
        user.setEmail(email);
        user.setJoinDate(new Date());
        user.setPassword(encodedPassword);
        user.setActive(true);
        user.setNotLocked(true);
        user.setRole(Role.ROLE_USER.name());
        user.setAuthorities(Role.ROLE_USER.getAuthorities());
        user.setProfileImageUrl(getTemporaryProfileImageUrl());
        userRepository.save(user);
        LOGGER.info("New user password: " + password);
        return user;
    }

    private String getTemporaryProfileImageUrl() {
        return ServletUriComponentsBuilder.fromCurrentContextPath().path("/user/image/profile/temp").toUriString();
    }

    private String encodePassword(String password) {
        return  this.bCryptPasswordEncoder.encode(password);
    }

    private String generatePassword() {
        return RandomStringUtils.randomAlphanumeric(10);
    }

    private String generateUserId() {
        return RandomStringUtils.randomNumeric(10);
    }

    private UserEntity validateNewUsernameAndEmail(String currentUsername, String newUsername, String newEmail ) throws UserNotFoundException, EmailExistException, UsernameExistException {
        UserEntity userByNewUsername = findUserByUsername(newUsername);
        UserEntity userByNewEmail = findUserByEmail(newEmail);

        if (StringUtils.isNotBlank(currentUsername)) {
           UserEntity currentUser = findUserByUsername(currentUsername);
           if( currentUser == null) {
               throw new UserNotFoundException(USER_NOT_FOUND_BY_USERNAME + currentUsername);
           }
           if(userByNewUsername != null && !currentUser.getId().equals(userByNewUsername.getId())) {
               throw new UsernameExistException(USERNAME_ALREADY_EXISTS);
           }
            if(userByNewEmail != null && !currentUser.getId().equals(userByNewEmail.getId())) {
                throw new EmailExistException(EMAIL_ALREADY_EXISTS);
            }
            return  currentUser;
        } else {
            if (userByNewUsername != null) {
                throw new UsernameExistException(USERNAME_ALREADY_EXISTS);
            }
            if(userByNewEmail != null) {
                throw new EmailExistException(EMAIL_ALREADY_EXISTS);
            }
            return null;
        }
    }

    @Override
    public List<UserEntity> getUsers() {
        return userRepository.findAll();
    }

    @Override
    public UserEntity findUserByUsername(String username) {
        return userRepository.findUserEntityByUsername(username);
    }

    @Override
    public UserEntity findUserByEmail(String email) {
        return userRepository.findUserEntityByEmail(email);
    }
}
