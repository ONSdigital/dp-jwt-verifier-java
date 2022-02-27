# dp-jwt-verifier-java

A Java JSON Web Token (JWT) verification library, designed to decode and verify a JWT Access Token using an RSA public signing key (asymmetric encryption).

## Example

Create an instance of the library:

```java
import com.github.onsdigital.JWTVerifier;
import com.github.onsdigital.JWTVerifierImpl;

public class Example {
    private String signingKeyId = "<PUBLIC_SIGNING_KEY_ID>";
    private String signingKey = "<PUBLIC_SIGNING_KEY>";
    private JWTVerifier jwtVerifier;
    
    public Example() {
        Map<String, String> signingKeys = new HashMap<>();
        signingKeys.put(signingKeyId, signingKey);
        this.jwtVerifier = new JWTVerifierImpl(signingKeys);
    }
}
```

The caller should likely provide the public signing and key ID rather than using constants.
The `<PUBLIC_SIGNING_KEY` must be a base64 encoded DER formatted public key.

Parse and verify the JWT Token:

```java
import com.github.onsdigital.JWTVerifier;
import com.github.onsdigital.UserDataPayload;
import com.github.onsdigital.exceptions.JWTDecodeException;
import com.github.onsdigital.exceptions.JWTTokenExpiredException;
import com.github.onsdigital.exceptions.JWTVerificationException;

public class Example {
    private JWTVerifier jwtVerifier;

    public void example() {
        String token = "<JWT_ACCESS_TOKEN>";
        try {
            UserDataPayload userData = jwtVerifier.verify(token);
            System.out.printf("id: '%s'\nemail: '%s'\ngroups: '%s'\n", userData.getId(), userData.getEmail(), userData.getGroups());
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        } catch (JWTDecodeException e) {
            e.printStackTrace();
        } catch (JWTTokenExpiredException e) {
            e.printStackTrace();
        } catch (JWTVerificationException e) {
            e.printStackTrace();
        }
    }
}
```

If the signature is valid, an object containing the user's email and a list of groups they belong to is returned.
Otherwise, an exception is thrown so that the caller can take action.

### Useful tooling

See [JWT.io](https://jwt.io/) for a JWT debugger and playground.

### Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for details.

### License

Copyright © 2021, Office for National Statistics (https://www.ons.gov.uk)

Released under MIT license, see [LICENSE](LICENSE.md) for details.
