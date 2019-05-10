package com.loginservice.login.helper;

import com.loginservice.login.dto.NewUserInput;
import com.loginservice.login.entity.Users;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Validator {

    private static final Logger logger = LogManager.getLogger(Validator.class);

    public ErrorHandler validate(NewUserInput newUserInput) {

        ErrorHandler errorHandler = new ErrorHandler();

        String passwordValidationResult = "";
        String email = newUserInput.getEmail();
        String firstName = newUserInput.getFirstname();
        String lastName = newUserInput.getLastname();
        String password = newUserInput.getPassword();
        String userType = newUserInput.getUserType();
        String description = newUserInput.getDescription();

        if(email==null || email.equals("")) {
            errorHandler = new ErrorHandler();
            errorHandler.setMessage(Errors.EMAIL_EMPTY.getError());
            return errorHandler;
        }

        if(firstName==null || firstName.equals("")) {
            errorHandler = new ErrorHandler();
            errorHandler.setMessage(Errors.FIRST_NAME_EMPTY.getError());
            return errorHandler;
        }

        if(lastName==null || lastName.equals("")) {
            errorHandler = new ErrorHandler();
            errorHandler.setMessage(Errors.LAST_NAME_EMPTY.getError());
            return errorHandler;
        }

        if(userType==null || userType.equals("")) {
            errorHandler = new ErrorHandler();
            errorHandler.setMessage(Errors.USER_TYPE_NOT_DEFINED.getError());
            return errorHandler;
        }

        if(description==null || description.equals("")) {
            errorHandler = new ErrorHandler();
            errorHandler.setMessage(Errors.DESCRIPTION.getError());
            return errorHandler;
        }

        passwordValidationResult = validatePassword(password);

        if(!passwordValidationResult.equals(Errors.VALID.getError())) {
            errorHandler = new ErrorHandler();
            errorHandler.setMessage(passwordValidationResult);
            return errorHandler;
        }

        errorHandler.setMessage(Errors.VALID.getError());
        return errorHandler;
    }


    public String validatePassword (String password) {

        if(password==null || password.equals("")) {
            return Errors.EMPTY.getError();
        }
        else if (password.length()<7) {
            return Errors.PASSWORD_LENGTH.getError();
        }
        else if (!matchPasswordChars("[a-zA-Z]", password)) {
            return Errors.PASSWORD_VALID_CHARACTERS.getError();
        }
        else if (!matchPasswordChars("[0-9]", password)) {
            return Errors.PASSWORD_VALID_CHARACTERS.getError();
        }
        else if (!matchPasswordChars("[^A-Za-z0-9]", password)) {
            return Errors.PASSWORD_VALID_CHARACTERS.getError();
        } else {
            return Errors.VALID.getError();
        }
    }

    private boolean matchPasswordChars (String patternString, String password) {
        Pattern pattern = Pattern.compile(patternString);
        Matcher matcher = pattern.matcher(password);
        if(matcher.find())
            return true;
        else
            return false;
    }

}
