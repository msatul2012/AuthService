LOGIN SERVICE - 
  1. REGISTER USER.
  2. LOGIN USER.
  3. CHANGE PASSWORD.
  4. EMAIL CONFIRMATION.
  5. DISABLE USER. 
  6. AUTH.
  7. ENABLE USER.
  8. GET USER DETAILS BY ID
  9. GET USERID BY AUTH TOKEN
  10. RESET PASSWORD - FORGOT PASSWORD - //TODO
  
  GET
/auth
authenticateToken

PUT
/change_password
changePassword

GET
/confirm
confirmEmail

PUT
/disable
disableUser

PUT
/enable
enableUser

GET
/login
login

POST
/register
addUser

GET
/id
getUserIDByAuthToken

GET
/id/{id}
getUserById


SWAGGER URL - http://localhost:8087/user/swagger-ui.html#/

Running on - PORT 8087
  
