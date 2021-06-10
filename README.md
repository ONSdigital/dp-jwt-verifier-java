# dp-jwt-verifier-java
A Java JSON Web Token (JWT) verification library

## Example

Create an instance of the library (uses interface):
```
    private JWTHandler jwtHandler;
```

Get verification of JWT Access Token (caller gets SIGNING_KEY from config):
```
    UserDataPayload jwtObj = this.jwtHandler.verifyJWT(<JWT_ACCESS_TOKEN>, <SIGNING_KEY>);
```

Will return an object containing user's email and groups they belong to, or error so that the caller can take action.

### Populate an object example

```java
import com.github.onsdigital.JWTHandlerImpl;
import com.github.onsdigital.impl.UserDataPayload;
import com.github.onsdigital.interfaces.JWTHandler;
...
...
...
    // can be passed is as part of class constructor too
    private JWTHandler jwtHandler = new JWTHandlerImpl();
    try {
        UserDataPayload jwtData = jwtHandler.verifyJWT(<JWT_ACCESS_TOKEN>, <SIGNING_KEY>);
        System.out.Println("Users email is: "+jwtData.getEmail());
        System.out.Println("A group user belongs to is: "+jwtData.getGroups()[0]);
        ...
        ...
    } catch (JWTTokenExpiredException e) {
        throw new ...("Error: ", e);
    } catch (JWTVerificationException e) {
        throw new ...("Error: ", e);
    } catch (JWTDecodeException e) {
        throw new ...("Error: ", e);
    }

```

### Useful tooling

See [JWT.io](https://jwt.io/) for a JWT debugger and playground.

### Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for details.

### License

Copyright © 2021, Office for National Statistics (https://www.ons.gov.uk)

Released under MIT license, see [LICENSE](LICENSE.md) for details.
