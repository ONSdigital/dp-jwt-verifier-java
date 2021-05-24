package com.github.onsdigital;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;

import com.github.onsdigital.exceptions.*;
import com.github.onsdigital.impl.UserDataPayload;

public class JWTVerifierTests 
{
    // state constants
    private final static String SIGNED_TOKEN         = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCIsInVzZXJuYW1lIjoiamFuZWRvZUBleGFtcGxlLmNvbSJ9.fn_ojA25syD6ajJ6we_grfBpaPSUSQeVSqnQGAozkHA";
    private final static String INVALID_SIGNED_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhLS1iYmJiLWNjY2MtZGPvv71kLWVlZWVlZWVlZWVlZSIsImRldmljZV9rZXkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjb2duaXRvOmdyb3VwcyI6WyJhZG1pbiIsInB1Ymxpc2hpbmciLCJkYXRhIiwidGVzdCJdLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6ImF3cy5jb2duaXRvLnNpZ25pbi51c2VyLmFkbWluIiwiYXV0aF90aW1lIjoxNTYyMTkwNTI0LCJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLnVzLXdlc3QtMi5hbWF6b25hd3MuY29tL3VzLXdlc3QtMl9leGFtcGxlIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjE1NjIxOTA1MjQsImp0aSI6ImFhYWFhYWFhLWJiYmItY2NjYy1kZGRkLWVlZWVlZWVlZWVlZSIsImNsaWVudF9pZCI6IjU3Y2Jpc2hrNGoyNHBhYmMxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJqYW5lZG9lQGV4YW1wbGUuY29tIn0.G-hL9kNQ8kVDmPpJDMeQzF8tDdR8yLOudaxqc1Ij0RQ";
    private final static String TOKEN_NO_USER        = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCJ9.u0K17k2kNo8_UUYNvWrIYDambCL7cRwUESPmeUmA9JE";
    private final static String TOKEN_NO_GROUPS      = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCIsInVzZXJuYW1lIjoiamFuZWRvZUBleGFtcGxlLmNvbSJ9.WKbbFixuFuP5jqMwt6yIV6NvqyqGHUXv2t-cy3mx2wQ";
    private final static String TOKEN_EXPIRED_TIME   = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5LCJpYXQiOjE1NjIxOTA1MjQsImp0aSI6ImFhYWFhYWFhLWJiYmItY2NjYy1kZGRkLWVlZWVlZWVlZWVlZSIsImNsaWVudF9pZCI6IjU3Y2Jpc2hrNGoyNHBhYmMxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJqYW5lZG9lQGV4YW1wbGUuY29tIn0.isHbp66W4VL_uS3Zms_uH0nEvoe3yBEzDUuMvxYZwK8";
    private final static String SECRET_KEY           = "my-HS256-bit-secret";
    private final static String USERNAME             = "me.myself@me.myself.io";
    // error messages
    private final static String CANNOT_VERIFY_ERROR   = "Verification of JWT token integrity failed.";
    private final static String SECRET_KEY_ERROR      = "Secret key check failed - null or empty key supplied.";
    private final static String INVALID_PAYLOAD_ERROR = "Required JWT payload claim not found [username or cognito:groups].";
    private final static String EXPIRED_TOKEN_ERROR   = "Access token has expired.";
    private final static String TOKEN_NOT_VALID_ERROR = "Token format not valid.";
    private final static String TOKEN_NULL_ERROR      = "Token cannot be null.";

    // create JWTVerifier test object
    JWTVerifier verify = new JWTVerifier();

    @Test
    public void decodeAndVerifyValidJWTPayload() {
        UserDataPayload jwtData = verify.verifyJWTToken(SIGNED_TOKEN, SECRET_KEY);

        String[] grps = jwtData.getGroups();

        Arrays.sort(grps);
        // assert json data
        assertThat(jwtData.getEmail().equals(USERNAME));
        assertThat(grps[0].equals("admin"));
        assertThat(grps[1].equals("data"));
        assertThat(grps[2].equals("publishing"));
        assertThat(grps[3].equals("test"));
    }

    public @Test
    void emptySecretKeySupplied() {
        assertThatThrownBy(() -> verify.verifyJWTToken(INVALID_SIGNED_TOKEN, ""))
            .isInstanceOf(JWTDecodeException.class)
                .hasMessageContaining(SECRET_KEY_ERROR);
    }

    public @Test
    void noUserNameInPayloadSupplied() {
        assertThatThrownBy(() -> verify.verifyJWTToken(TOKEN_NO_USER, SECRET_KEY))
            .isInstanceOf(JWTDecodeException.class)
                .hasMessageContaining(INVALID_PAYLOAD_ERROR);
    }

    public @Test
    void noGroupsInPayloadSupplied() {
        assertThatThrownBy(() -> verify.verifyJWTToken(TOKEN_NO_GROUPS, SECRET_KEY))
            .isInstanceOf(JWTDecodeException.class)
                .hasMessageContaining(INVALID_PAYLOAD_ERROR);
    }

    public @Test
    void throwErrorVerifyingToken() {
        assertThatThrownBy(() -> verify.verifyJWTToken(INVALID_SIGNED_TOKEN, SECRET_KEY))
            .isInstanceOf(JWTVerificationException.class)
                .hasMessageContaining(CANNOT_VERIFY_ERROR);
    }

    public @Test
    void throwErrorExpiredToken() {
        assertThatThrownBy(() -> verify.verifyJWTToken(TOKEN_EXPIRED_TIME, SECRET_KEY))
            .isInstanceOf(JWTTokenExpiredException.class)
                .hasMessageContaining(EXPIRED_TOKEN_ERROR);
    }

    public @Test
    void throwErrorTokenNull() {
        assertThatThrownBy(() -> verify.verifyJWTToken(null, SECRET_KEY))
            .isInstanceOf(JWTDecodeException.class)
                .hasMessageContaining(TOKEN_NULL_ERROR);
    }

    public @Test
    void throwErrorTokenFormatNotValid() {
        assertThatThrownBy(() -> verify.verifyJWTToken("", SECRET_KEY))
            .isInstanceOf(JWTDecodeException.class)
                .hasMessageContaining(TOKEN_NOT_VALID_ERROR);
    }
}
