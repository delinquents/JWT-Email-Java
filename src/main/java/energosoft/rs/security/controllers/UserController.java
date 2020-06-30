package energosoft.rs.security.controllers;


import energosoft.rs.security.exception.ExceptionHandling;
import energosoft.rs.security.exception.domain.UserNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = { "/", "/user"})
public class UserController   extends ExceptionHandling {


    @GetMapping("/home")
    public String showUser() throws UserNotFoundException {
        return  "new UserEntity()";
//        throw new UserNotFoundException("The user was not found");
    }


}
