package energosoft.rs.security.controllers;



import energosoft.rs.security.domain.UserEntity;
import energosoft.rs.security.domain.UserPrincipal;
import energosoft.rs.security.exception.ExceptionHandling;
import energosoft.rs.security.exception.domain.EmailExistException;
import energosoft.rs.security.exception.domain.UserNotFoundException;
import energosoft.rs.security.exception.domain.UsernameExistException;
import energosoft.rs.security.service.UserService;
import energosoft.rs.security.utilty.JWTTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import static energosoft.rs.security.constant.SecurityConstant.JWT_TOKEN_HEADER;
import static org.springframework.http.HttpStatus.*;

@RestController
@RequestMapping(path = { "/", "/user"})
public class UserController   extends ExceptionHandling {

    private Logger LOGGER = LoggerFactory.getLogger(getClass());

    private UserService userService;
    private AuthenticationManager authenticationManager;
    private JWTTokenProvider jwtTokenProvider;

    @Autowired
    public UserController(UserService userService, AuthenticationManager authenticationManager, JWTTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping ("/register")
    public ResponseEntity<UserEntity> register(@RequestBody UserEntity user) throws UserNotFoundException, UsernameExistException, EmailExistException {
        UserEntity newUser = userService.register(user.getFirstName(), user.getLastName(), user.getUsername(), user.getEmail());
    return  new ResponseEntity<>(newUser, OK);
    }

    @PostMapping ("/login")
    public ResponseEntity<UserEntity> showUser(@RequestBody UserEntity user) throws UserNotFoundException, UsernameExistException, EmailExistException {
        authenticate(user.getUsername(), user.getPassword());
        UserEntity loginUser = userService.findUserByUsername(user.getUsername());
        UserPrincipal userPrincipal = new UserPrincipal(loginUser);
        HttpHeaders jwtHeader = getJwtHeader(userPrincipal);
        LOGGER.info("Generated JWTToken: " + jwtTokenProvider.generateJwtToken(userPrincipal));
        return  new ResponseEntity<>(loginUser, jwtHeader, OK );
    }

    private HttpHeaders getJwtHeader(UserPrincipal userPrincipal) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJwtToken(userPrincipal));
        return headers;
    }

    private void authenticate(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }


}
