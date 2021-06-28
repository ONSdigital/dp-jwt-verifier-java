package com.github.onsdigital;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import com.github.onsdigital.exceptions.*;
import com.github.onsdigital.impl.UserDataPayload;

public class JWTVerifierTests 
{
    // state constants
    private final static String SIGNED_TOKEN         = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCIsInVzZXJuYW1lIjoiamFuZWRvZUBleGFtcGxlLmNvbSJ9.HT4-3zGRYwYZXKa_VJVdvRfX0sP1D6iUC4VYrCOvC44naJX7KrGtfenfXPLA6JcRi7dBH7gF_uuHFT2neNWADCrpFIftbOYR_JT5sVe6GFV5kdMANUlWUMni4Cak66LSeFlaVPkD2oB4yGjITpKFBJO3lTmxNByX-JVg3mkVipISd8PmUDFoWV1RiQj05AheR-JoQTHnsT2VPpyC5jYfWsPEntrhSGfCAuxWSqfUwL5SNoKEAuEGZvxDG-Xy6c3CLQzh_mZBHAfTbMmGXYXfomc9UMud-1z2cxtiYRa9S28EY-oyMBKm74mdarcCZDACVnq6nLeTYqsKoA2EdrjZmw";
    private final static String INVALID_SIGNED_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC2lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCIsInVzZXJuYW1lIjoiamFuZWRvZUBleGFtcGxlLmNvbSJ9.HT4-3zGRYwYZXKa_VJVdvRfX0sP1D6iUC4VYrCOvC44naJX7KrGtfenfXPLA6JcRi7dBH7gF_uuHFT2neNWADCrpFIftbOYR_JT5sVe6GFV5kdMANUlWUMni4Cak66LSeFlaVPkD2oB4yGjITpKFBJO3lTmxNByX-JVg3mkVipISd8PmUDFoWV1RiQj05AheR-JoQTHnsT2VPpyC5jYfWsPEntrhSGfCAuxWSqfUwL5SNoKEAuEGZvxDG-Xy6c3CLQzh_mZBHAfTbMmGXYXfomc9UMud-1z2cxtiYRa9S28EY-oyMBKm74mdarcCZDACVnq6nLeTYqsKoA2EdrjZmw";
    private final static String TOKEN_NO_USER        = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCJ9.u0K17k2kNo8_UUYNvWrIYDambCL7cRwUESPmeUmA9JE";
    private final static String TOKEN_NO_GROUPS      = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCIsInVzZXJuYW1lIjoiamFuZWRvZUBleGFtcGxlLmNvbSJ9.WKbbFixuFuP5jqMwt6yIV6NvqyqGHUXv2t-cy3mx2wQ";
    private final static String TOKEN_EXPIRED_TIME   = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5LCJpYXQiOjE1NjIxOTA1MjQsImp0aSI6ImFhYWFhYWFhLWJiYmItY2NjYy1kZGRkLWVlZWVlZWVlZWVlZSIsImNsaWVudF9pZCI6IjU3Y2Jpc2hrNGoyNHBhYmMxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJqYW5lZG9lQGV4YW1wbGUuY29tIn0.isHbp66W4VL_uS3Zms_uH0nEvoe3yBEzDUuMvxYZwK8";
   
    private final static String PUBLIC_KEY = 
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv"
    +"vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc"
    +"aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy"
    +"tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0"
    +"e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb"
    +"V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9"
    +"MwIDAQAB";
    
    private final static String USERNAME             = "me.myself@me.myself.io";

    // create JWTVerifier test object
    JWTVerifier verify = new JWTVerifier();

    @Test
    public void decodeAndVerifyValidJWTPayload() {

        UserDataPayload jwtData = verify.verifyJWTToken(SIGNED_TOKEN, PUBLIC_KEY);

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
        assertThatThrownBy(() -> verify.verifyJWTToken(SIGNED_TOKEN, ""))
            .isInstanceOf(JWTDecodeException.class)
                .hasMessageContaining(verify.PUBLIC_KEY_ERROR);
    }

    public @Test
    void noUserNameInPayloadSupplied() {
        assertThatThrownBy(() -> verify.verifyJWTToken(TOKEN_NO_USER, PUBLIC_KEY))
            .isInstanceOf(JWTDecodeException.class)
                .hasMessageContaining(verify.INVALID_PAYLOAD_ERROR);
    }

    public @Test
    void noGroupsInPayloadSupplied() {
        assertThatThrownBy(() -> verify.verifyJWTToken(TOKEN_NO_GROUPS, PUBLIC_KEY))
            .isInstanceOf(JWTDecodeException.class)
                .hasMessageContaining(verify.INVALID_PAYLOAD_ERROR);
    }

    public @Test
    void throwErrorVerifyingToken() {
        assertThatThrownBy(() -> verify.verifyJWTToken(INVALID_SIGNED_TOKEN, PUBLIC_KEY))
            .isInstanceOf(JWTVerificationException.class)
                .hasMessageContaining(verify.CANNOT_VERIFY_ERROR);
    }

    public @Test
    void throwErrorExpiredToken() {
        assertThatThrownBy(() -> verify.verifyJWTToken(TOKEN_EXPIRED_TIME, PUBLIC_KEY))
            .isInstanceOf(JWTTokenExpiredException.class)
                .hasMessageContaining(verify.EXPIRED_TOKEN_ERROR);
    }

    public @Test
    void throwErrorTokenNull() {
        assertThatThrownBy(() -> verify.verifyJWTToken(null, PUBLIC_KEY))
            .isInstanceOf(JWTDecodeException.class)
                .hasMessageContaining(verify.TOKEN_NULL_ERROR);
    }

    public @Test
    void throwErrorTokenFormatNotValid() {
        assertThatThrownBy(() -> verify.verifyJWTToken("", PUBLIC_KEY))
            .isInstanceOf(JWTDecodeException.class)
                .hasMessageContaining(verify.TOKEN_NOT_VALID_ERROR);
    }
}
