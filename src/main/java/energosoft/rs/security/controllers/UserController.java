package energosoft.rs.security.controllers;


import energosoft.rs.security.domain.UserEntity;
import energosoft.rs.security.domain.UserPrincipal;
import energosoft.rs.security.exception.ExceptionHandling;
import energosoft.rs.security.exception.domain.EmailExistException;
import energosoft.rs.security.exception.domain.EmailNotFoundException;
import energosoft.rs.security.exception.domain.UserNotFoundException;
import energosoft.rs.security.exception.domain.UsernameExistException;
import energosoft.rs.security.service.UserService;
import energosoft.rs.security.ui.response.HttpResponse;
import energosoft.rs.security.utilty.JWTTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static energosoft.rs.security.constant.FileConstant.*;
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
    public ResponseEntity<UserEntity> register(@RequestBody UserEntity user) throws UserNotFoundException, UsernameExistException, EmailExistException, MessagingException {
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

    @PostMapping("/add")
    public ResponseEntity<UserEntity> addNewUser(@RequestParam("firstName") String firstName,
                                                 @RequestParam("lastName") String lastName,
                                                 @RequestParam("username") String username,
                                                 @RequestParam("email") String email,
                                                 @RequestParam("role") String role,
                                                 @RequestParam("isActive") String isActive,
                                                 @RequestParam("isNonLocked") String isNonLocked,
                                                 @RequestParam(value = "profileImage" , required = false) MultipartFile profileImage) throws UserNotFoundException, UsernameExistException, EmailExistException, IOException {
        UserEntity newUser = userService.addNewUser(firstName, lastName, username, email, role,
                Boolean.parseBoolean(isNonLocked),Boolean.parseBoolean(isActive), profileImage);

        return new ResponseEntity<>(newUser, OK);
    }

    @PostMapping("/update")
    public ResponseEntity<UserEntity> update(    @RequestParam("currentUsername") String currentUsername,
                                                 @RequestParam("firstName") String firstName,
                                                 @RequestParam("lastName") String lastName,
                                                 @RequestParam("username") String username,
                                                 @RequestParam("email") String email,
                                                 @RequestParam("role") String role,
                                                 @RequestParam("isActive") String isActive,
                                                 @RequestParam("isNonLocked") String isNonLocked,
                                                 @RequestParam(value = "profileImage" , required = false) MultipartFile profileImage) throws UserNotFoundException, UsernameExistException, EmailExistException, IOException {
        UserEntity updatedUser = userService.updateUser(currentUsername ,firstName, lastName, username, email, role,
                Boolean.parseBoolean(isNonLocked),Boolean.parseBoolean(isActive), profileImage);

        return new ResponseEntity<>(updatedUser, OK);
    }

    @PostMapping("/updateProfileImage")
    public ResponseEntity<UserEntity> updatePorfileImage(
                                                 @RequestParam("username") String username,
                                                 @RequestParam(value = "profileImage") MultipartFile profileImage) throws UserNotFoundException, UsernameExistException, EmailExistException, IOException {
        UserEntity updatedUser = userService.updateProfileImage(username, profileImage);

        return new ResponseEntity<>(updatedUser, OK);
    }

    @GetMapping("/find/{username}")
    public ResponseEntity<UserEntity> getUser(@PathVariable String username) {
        UserEntity foundUser = userService.findUserByUsername(username);
        return new ResponseEntity<>(foundUser, OK);
    }

    @GetMapping("/list")
    public ResponseEntity<List<UserEntity>> getAllUsers() {
        List<UserEntity> users = userService.getUsers();
        return new ResponseEntity<>(users, OK);
    }

    @GetMapping("/resetPassword/{email}")
    public ResponseEntity<HttpResponse> resetPassword(@PathVariable String email) throws EmailNotFoundException, MessagingException {
        userService.resetPassword(email);
        return response(OK, "An email whit a new password was send to: " + email);
    }

    @DeleteMapping("/delete/{id}")
    @PreAuthorize("hasAnyAuthority('user:delete')")
    public ResponseEntity<HttpResponse> deleteUser(@PathVariable long id) {
        userService.deleteUser(id);
        return response(NO_CONTENT, "User deleted successfully");
    }

    @GetMapping(path = "/image/{username}/{fileName}", produces = MediaType.IMAGE_JPEG_VALUE)
    public byte[] getProfileImage(@PathVariable("username") String username, @PathVariable("fileName") String fileName) throws IOException {
        return Files.readAllBytes(Paths.get(USER_FOLDER + username + FORWARD_SLASH + fileName));
    }

    @GetMapping(path = "/image/{profile}/{username}", produces = MediaType.IMAGE_JPEG_VALUE)
    public byte[] getTempProfileImage(@PathVariable("username") String username) throws IOException {
        URL url = new URL(TEMP_PROFILE_IMAGE_BASE_URL + username);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (InputStream inputStream = url.openStream()) {
            int bytesRead;
            byte[] chunk = new byte[1024];
            while ((bytesRead = inputStream.read(chunk)) > 0) {
                byteArrayOutputStream.write(chunk, 0 , bytesRead);
            }
        }
        return byteArrayOutputStream.toByteArray();
    }

    private HttpHeaders getJwtHeader(UserPrincipal userPrincipal) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJwtToken(userPrincipal));
        return headers;
    }

    private ResponseEntity<HttpResponse> response(HttpStatus status, String message) {
        return new ResponseEntity<>(new HttpResponse(status.value(), status, status.getReasonPhrase().toUpperCase(),
                message), status);
    }

    private void authenticate(String username, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }


}
