package com.loginservice.login.controller;

import com.loginservice.login.dto.AuthenticationMessage;
import com.loginservice.login.dto.NewUserInput;
import com.loginservice.login.dto.NewUserOuput;
import com.loginservice.login.dto.UpdateInfo;
import com.loginservice.login.dto.UserIdOutput;
import com.loginservice.login.entity.Users;
import com.loginservice.login.helper.*;
import com.loginservice.login.service.UsersService;
import com.sun.deploy.net.HttpResponse;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletResponse;

import java.util.UUID;

/*
    User Controller Class - APIs definition
 */

@RestController
@RequestMapping
@CrossOrigin(origins = "*")
public class UsersController {

    private static final Logger logger = LogManager.getLogger(UsersController.class);

    @Autowired
    UsersService usersService;

    @Autowired
    Environment environment;

    private String fromEmail;
    private String fromPassword;
    private String sentFromHost;
    private String confirmEndPoint;
    private String redisHost;
    private String redisPort;
    private String uiUrl;

    @PostConstruct
    public void init() {
        fromEmail = environment.getProperty("from-email");
        fromPassword = environment.getProperty("from-password");
        sentFromHost = environment.getProperty("confirm-api-host");
        confirmEndPoint = environment.getProperty("confirm-endpoint");
        redisHost = environment.getProperty("redis-host");
        redisPort = environment.getProperty("redis-port");
        uiUrl = environment.getProperty("ui-endpoint");
    }

    /*
        API to register an user
     */
    @RequestMapping(value = "/register", method = RequestMethod.POST, headers = "Content-Type=application/json")
    @ResponseBody
    public ResponseEntity addUser(@RequestBody NewUserInput newUserInput) {

        Validator validator = new Validator();

        Users existingUser = usersService.findUserByEmail(newUserInput.getEmail());
        if (existingUser!=null) {
            ErrorHandler errorHandler = new ErrorHandler();
            errorHandler.setMessage(Errors.EXISTING_USER.getError());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorHandler);
        }

        logger.info("Validating User input for Registration");
        ErrorHandler errorHandler = validator.validate(newUserInput);

        String errorMessage = errorHandler.getMessage();

        if(!errorMessage.equals(Errors.VALID.getError())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorHandler);
        }

        String email = newUserInput.getEmail().toLowerCase();
        logger.info("Creating new user -> " + email);
        Users user = new Users();
        user.setEmail(email);
        user.setPassword(newUserInput.getPassword());
        user.setInstitution(newUserInput.getInstitution());
        user.setFirstname(newUserInput.getFirstname());
        user.setLastname(newUserInput.getLastname());
        user.setUserType(newUserInput.getUserType());
        user.setDescription(newUserInput.getDescription());
        usersService.addOrUpdate(user);

        RedisUtils redisUtils = new RedisUtils(redisHost,redisPort);
        String confirmToken = generateAuthToken();
        redisUtils.addUserToken(confirmToken, email, 86400);
        logger.info("Generated Auth Token");
        buildBodyAndSendEmail (confirmToken, email);
        logger.info(email + " -> User Created. Sent the verification email");
        return ResponseEntity.status(HttpStatus.CREATED).body(Errors.CREATED.getError());
    }

    /*
        API to register an user
     */
    @RequestMapping(value = "/update", method = RequestMethod.POST, headers = "Content-Type=application/json")
    @ResponseBody
    public ResponseEntity update(@RequestBody UpdateInfo updateInfo, @RequestHeader("token") String token) {

        RedisUtils redisUtils = new RedisUtils(redisHost,redisPort);
        if(!redisUtils.keyExists(token)) {
            ErrorHandler errorHandler = new ErrorHandler();
            errorHandler.setMessage(Errors.AUTH_TOKEN_INVALID.getError());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorHandler);
        }
        String email = redisUtils.getValue(token);
        Users user = usersService.findUserByEmail(email);
        if (user==null) {
            ErrorHandler errorHandler = new ErrorHandler();
            errorHandler.setMessage(Errors.NO_EXISTING_USER.getError());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorHandler);
        }
        String description = updateInfo.getDescription();
        if(description!=null && !description.equals(""))
            user.setDescription(description);

        String institution = updateInfo.getInstitution();
        if(institution!=null && !institution.equals(""))
            user.setInstitution(institution);

        String firstName = updateInfo.getFirstname();
        if(firstName!=null && !firstName.equals(""))
            user.setFirstname(firstName);

        String lastName = updateInfo.getLastname();
        if(lastName!=null && !lastName.equals(""))
            user.setLastname(lastName);

        usersService.addOrUpdate(user);

        return ResponseEntity.status(HttpStatus.OK).body(Errors.CREATED.getError());
    }

    /*
        API to login and authenticate with email and password
     */
    @RequestMapping(value = "/login", method = RequestMethod.GET)
    @ResponseBody
    public ResponseEntity login(@RequestHeader("auth-user") String email, @RequestHeader("auth-password") String password) {
        logger.info("Trying to login with ->" + email);
        return auth(email.toLowerCase(), password);

    }

    /*
        API to authorize with auth token
     */
    @RequestMapping(value = "/auth", method = RequestMethod.GET)
    @ResponseBody
    public ResponseEntity authenticateToken(@RequestHeader("auth-token") String authToken) {
        logger.info("Verifying Auth token");
        return verifyToken (authToken);
    }

    /*
        API to confirm user creation and activate
     */
    @RequestMapping(value = "/confirm", method = RequestMethod.GET)
    @ResponseBody
    public ResponseEntity confirmEmail(@RequestParam("token") String confirmToken, @RequestParam("email") String email, HttpServletResponse httpServletResponse) throws Exception{
        logger.info("Activating and confirming email");
        RedisUtils redisUtils = new RedisUtils(redisHost,redisPort);
        ResponseEntity responseEntity =  verifyToken (confirmToken);
        if(responseEntity.getStatusCode()==HttpStatus.OK) {
            Users user = usersService.findUserByEmail(email);
            if(user!=null) {
                user.setEnabled(true);
                usersService.addOrUpdate(user);
            }
            httpServletResponse.sendRedirect(uiUrl+"Yes");
            return ResponseEntity.status(responseEntity.getStatusCode()).body("EMAIL CONFIRMED. PLEASE LOGIN");
        }
        httpServletResponse.sendRedirect(uiUrl+"No");
        String newToken = generateAuthToken();
        redisUtils.addUserToken(newToken, email, 86400);
        buildBodyAndSendEmail (newToken, email);
        return ResponseEntity.status(responseEntity.getStatusCode()).body("EMAIL NOT CONFIRMED, SENT THE REQUEST AGAIN");
    }

    /*
        API to disable user
     */
    @RequestMapping(value = "/disable", method = RequestMethod.PUT)
    @ResponseBody
    public ResponseEntity disableUser(@RequestHeader("auth-token") String authToken) {
        ResponseEntity responseEntity = verifyToken(authToken);
        if (responseEntity.getStatusCode()==HttpStatus.OK) {
            RedisUtils redisUtils = new RedisUtils(redisHost,redisPort);
            String email = redisUtils.getValue(authToken);
            Users user = usersService.findUserByEmail(email);
            user.setEnabled(false);
            usersService.addOrUpdate(user);
            redisUtils.delete(authToken);
            redisUtils.delete(email);
            logger.info("User Disabled -> "+ email);
            return ResponseEntity.status(HttpStatus.OK).body(null);
        }
        return ResponseEntity.status(responseEntity.getStatusCode()).body(null);
    }

    /*
        API to logout
     */
    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    @ResponseBody
    public ResponseEntity logout(@RequestHeader("auth-token") String authToken) {
            RedisUtils redisUtils = new RedisUtils(redisHost,redisPort);
            String email = "";
            if(redisUtils.keyExists(authToken)) {
                email = redisUtils.getValue(authToken);
                redisUtils.delete(authToken);
                redisUtils.delete(email);
            }
            return ResponseEntity.status(HttpStatus.OK).body(null);
    }

    /*
        API to enable user
     */
    @RequestMapping(value = "/enable", method = RequestMethod.PUT)
    @ResponseBody
    public ResponseEntity enableUser(@RequestHeader("auth-user") String email) {
        Users user = usersService.findUserByEmail(email);
        if(user!=null) {
            RedisUtils redisUtils = new RedisUtils(redisHost, redisPort);
            String confirmToken = generateAuthToken();
            redisUtils.addUserToken(confirmToken, email, 86400);
            buildBodyAndSendEmail(confirmToken, email);
            logger.info(email + " -> User Enabled. Sent the verification email");
            return ResponseEntity.status(HttpStatus.OK).body(Errors.ENABLED.getError());
        }
        ErrorHandler errorHandler = new ErrorHandler();
        errorHandler.setMessage(Errors.NO_EXISTING_USER.getError());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorHandler);
    }

    /*
        API to change password
     */
    @RequestMapping(value = "/change_password", method = RequestMethod.PUT)
    @ResponseBody
    public ResponseEntity changePassword(@RequestHeader ("auth-token") String authToken, @RequestHeader ("password") String newPassword) {
        Validator validator = new Validator();
        ResponseEntity responseEntity = verifyToken(authToken);
        if (responseEntity.getStatusCode()==HttpStatus.OK) {
            RedisUtils redisUtils = new RedisUtils(redisHost,redisPort);
            String email = redisUtils.getValue(authToken);
            Users user = usersService.findUserByEmail(email);
            String passwordValidation = validator.validatePassword (newPassword);
            if(passwordValidation.equals(Errors.VALID.getError())) {
                redisUtils.delete(authToken);
                redisUtils.delete(email);
                user.setPassword(newPassword);
                usersService.addOrUpdate(user);
                logger.info(email + " ->'s password changed");
                return ResponseEntity.status(HttpStatus.OK).body(null);
            } else {
                ErrorHandler errorHandler = new ErrorHandler();
                errorHandler.setMessage(passwordValidation);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(passwordValidation);
            }
        }
        return ResponseEntity.status(responseEntity.getStatusCode()).body(null);
    }

    /*
        API to get user Id from auth-token
     */
    @RequestMapping(value = "", method = RequestMethod.GET)
    @ResponseBody
    public ResponseEntity getUserIDByAuthToken(@RequestHeader("auth-token") String authToken) {
        RedisUtils redisUtils = new RedisUtils(redisHost,redisPort);
        String email = redisUtils.getValue(authToken);
        Users user = usersService.findUserByEmail(email);
        if(user!=null) {
            UserIdOutput userIdOutput = new UserIdOutput();
            userIdOutput.setUserId(user.getId().toString());
            userIdOutput.setEmail(email);
            return ResponseEntity.status(HttpStatus.OK).body(userIdOutput);
        }
        ErrorHandler errorHandler = new ErrorHandler();
        errorHandler.setMessage(Errors.NO_EXISTING_USER.getError());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorHandler);
    }

    /*
        API to get user details by user id
     */
    @RequestMapping(value = "/{id}", method = RequestMethod.GET)
    @ResponseBody
    public ResponseEntity getUserById(@PathVariable("id") String id) {

        Users user = usersService.getUserById(UUID.fromString(id));

        if(user!=null) {
            NewUserOuput newUserOuput = new NewUserOuput();
            newUserOuput.setEmail(user.getEmail());
            newUserOuput.setFirstname(user.getFirstname());
            newUserOuput.setLastname(user.getLastname());
            newUserOuput.setDescription(user.getDescription());
            newUserOuput.setUserType(user.getUserType());
            newUserOuput.setInstitution(user.getInstitution());
            return ResponseEntity.status(HttpStatus.OK).body(newUserOuput);
        }

        ErrorHandler errorHandler = new ErrorHandler();
        errorHandler.setMessage(Errors.NO_EXISTING_USER.getError());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorHandler);
    }

    private ResponseEntity verifyToken (String token) {

        RedisUtils redisUtils = new RedisUtils(redisHost,redisPort);

        if(token==null || token.equals("")) {
            ErrorHandler errorHandler = new ErrorHandler();
            errorHandler.setMessage(Errors.AUTH_TOKEN_EMPTY.getError());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorHandler);
        }

        if(!redisUtils.keyExists(token)){
            ErrorHandler errorHandler = new ErrorHandler();
            errorHandler.setMessage(Errors.AUTH_TOKEN_INVALID.getError());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorHandler);
        }

        return authMessageBuilder (token, redisUtils);

    }

    private String generateAuthToken () {
        return UUID.randomUUID().toString();
    }

    private ResponseEntity auth (String email, String password) {

        RedisUtils redisUtils = new RedisUtils(redisHost,redisPort);
        Users user = null;
        ErrorHandler errorHandler = new ErrorHandler();

        if(email==null || email.equals("")) {
            errorHandler.setMessage(Errors.EMAIL_EMPTY.getError());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorHandler);
        }

        if(password==null || password.equals("")) {
            errorHandler.setMessage(Errors.EMPTY.getError());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorHandler);
        }

        user = usersService.findUserByEmail(email);

        if(user==null) {
            errorHandler.setMessage(Errors.NO_EXISTING_USER.getError());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorHandler);
        }

        if(!user.getEnabled()) {
            errorHandler.setMessage(Errors.NOT_ENABLED.getError());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorHandler);
        }

        if(!usersService.isPassword(user,password)) {
            errorHandler.setMessage(Errors.INCORRECT_PASSWORD.getError());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorHandler);
        }

        if(!redisUtils.keyExists(email)) {
            redisUtils.addUserToken(email,generateAuthToken(), 3600);
        }

        return authMessageBuilder (email, redisUtils);
    }

    private ResponseEntity authMessageBuilder (String redisKey, RedisUtils redisUtils) {
        AuthenticationMessage authenticationMessage = new AuthenticationMessage();
        authenticationMessage.setMessage(Errors.AUTHENTICATED.getError());
        authenticationMessage.setAuthToken(redisUtils.getValue(redisKey));
        authenticationMessage.setValidFor(Long.toString(redisUtils.authTtl(redisKey)));
        return ResponseEntity.status(HttpStatus.OK).body(authenticationMessage);
    }

    private void buildBodyAndSendEmail (String token, String email) {
        EmailConfirmation emailConfirmation = new EmailConfirmation();
        String subject = "PLEASE CONFIRM EMAIL -> " + email;
        String body = "http://" + sentFromHost + confirmEndPoint + "?token=" + token + "&email=" + email;

        emailConfirmation.sendConfirmation(email, fromEmail, fromPassword, body, subject);
    }

}
