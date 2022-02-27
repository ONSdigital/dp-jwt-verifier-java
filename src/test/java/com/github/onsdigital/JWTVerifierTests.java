package com.github.onsdigital;

import com.github.onsdigital.exceptions.JWTDecodeException;
import com.github.onsdigital.exceptions.JWTTokenExpiredException;
import com.github.onsdigital.exceptions.JWTVerificationException;
import com.github.onsdigital.impl.UserDataPayload;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JWTVerifierTests {
    // state constants
    private final static String SIGNED_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCIsInVzZXJuYW1lIjoiamFuZWRvZUBleGFtcGxlLmNvbSJ9.p1_RhFQiprKmUUWiloNqTcThfS3fHZBSjiwv32FEc_ShVYJJfkf-s4zEDe1wWItZqbINTOJC8exRjDnUQHIhcCqmaT4FYKhkENgw8bzPrOa7Qjp7Ep4Pfj5Xu3lUgbzoHS_hCxWbt_Z1wSSALqAl--bdkkDuO9VyNcm85Dv9BpIOLsIvfSofutJ6GDOUxZp6q9bM9WdPrx2o4dP5ppemRB1EXXF3we3WqtDfb0SdX8Pjlj-qu4rxTIlA00BlTsVFOn9HHK8XFAOGs8umfJeAEt4EkZF_IL5-3BCUEIjkJqOh_POYSPWkEnsMw00UV90adHx9gZdKWyag_8kQXLliRQ";
    private final static String INVALID_SIGNED_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC2lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCIsInVzZXJuYW1lIjoiamFuZWRvZUBleGFtcGxlLmNvbSJ9.HT4-3zGRYwYZXKa_VJVdvRfX0sP1D6iUC4VYrCOvC44naJX7KrGtfenfXPLA6JcRi7dBH7gF_uuHFT2neNWADCrpFIftbOYR_JT5sVe6GFV5kdMANUlWUMni4Cak66LSeFlaVPkD2oB4yGjITpKFBJO3lTmxNByX-JVg3mkVipISd8PmUDFoWV1RiQj05AheR-JoQTHnsT2VPpyC5jYfWsPEntrhSGfCAuxWSqfUwL5SNoKEAuEGZvxDG-Xy6c3CLQzh_mZBHAfTbMmGXYXfomc9UMud-1z2cxtiYRa9S28EY-oyMBKm74mdarcCZDACVnq6nLeTYqsKoA2EdrjZmw";
    private final static String TOKEN_NO_USER = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCJ9.AgKGQQBHlH0hFMXl3LkYneg36_6EhOgDf2ZQiwRma4UVLzd_NHin68oUy9SbiiXTpszVGFvod-uPqAXIA5kTX-Q88z0D93XSin8nAAhAjzsHvVqkzawII4rZmXbxYhdzKWG67YOrlaR9p8cWBh_rK6gY-LARCJz7lbM3LRAxZzOt102Rk86l-Fpw1gEKzz5sZLsAsHp6QoLkr9m5fABpkhziOIIH7dFQ-8Mvdo4kbBEWrc_Ihq59IqLvOoGP0dXijUuHhdGx41imcs6SSAfSfYYgSRxoODFr9N7mkfQgpDU0iDuvdfWPpqKthy2sPKaqBCnwfeAgESNd-VbvlXn5AA";
    private final static String TOKEN_NO_GROUPS = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNTYyMTkwNTI0LCJqdGkiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJjbGllbnRfaWQiOiI1N2NiaXNoazRqMjRwYWJjMTIzNDU2Nzg5MCIsInVzZXJuYW1lIjoiamFuZWRvZUBleGFtcGxlLmNvbSJ9.FmMmUITX-vOylUJYHhaqpx-bpcuR267jqg-3oltVHXdYBuiCWZB31WEI5pPe6zyn-z6beLy54GYwUEKXfZTS9_lFkN_0D50uWtKp6-POMV9KmoKlFTyzmKGW9n7GRAGwlG-S6cpnUxtx_7Zq4DFCs7L6351H97B3rFNPiqLWImYA4OUUZonSI8fhHQvk_eVuZcxN-U2f9_5G56vCdnIydy4sFS8wOO56nFX4Mylta3G6bYL0l5tAQPXcqmhvrWIppb_K1R7sDXDi0cgAa9lUYIcboV1vNEbHChZmKY7Zn0Qfvq4tKkHUmL5cVUZQDOc_6k7rUwkHEXwbufCgS4H2Mg";
    private final static String TOKEN_EXPIRED_TIME = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJwdWJsaXNoaW5nIiwiZGF0YSIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6OTk5OTk5OTk5LCJpYXQiOjE1NjIxOTA1MjQsImp0aSI6ImFhYWFhYWFhLWJiYmItY2NjYy1kZGRkLWVlZWVlZWVlZWVlZSIsImNsaWVudF9pZCI6IjU3Y2Jpc2hrNGoyNHBhYmMxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJqYW5lZG9lQGV4YW1wbGUuY29tIn0.HH71yDzQHXfq339zTH__6HL6iycGrz3fmV6jNOoCMXqroHJTMZ2sNkE0zCj1JBX3aByGdvs-XqZRUqAzHY-UD0sG4pxWZNa7uA-r8ultgurdGKIba8pKkUQDlaNWLm7sj8pEe0aurtzjDIZ2Vd5aA3HJ2_LxX-x0dbkJIsArPNpVaeuD9mRpbXZ4stxw8EFT3j38H9O2C8Qu9X4Yw4Pg_3qfeZX87lxSvVk3HbxDYSaL0ttKfPOEtOOM7b6f9_nNJaSZ7tFBb3bQZxVUP1xyUzOB21UGfXhiwNfAxx1CDvP7xfkRSGLOHiHitg0lygr1Q4sBDgACBUCEtVDDf7ZnDQ";
    private final static String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwdowpUQS8YPrzFamOi7bEM74+yeqoAH0Tm+PLZdWjaIxL13XfxX63jO3iHAJe/Uh74d2vtTuHV7Vkl0wRjjJOuWrj5espG5VxU6xHJG/R2tVDElv05fFZhZn/YCwUJV2Zrz9Z0PIdPHB4eZODo64Qfab+ihgeLlny5l6+srVacWqsQ47i3DdJQOd6MgacvrKt+B0Ior1HKlHR0NneFPNu9zvCg11O1W0yl2+ou0UOPVqF8EfoavvgwbAUWwxeHXcN+TmgKx6Oa4X9ylk+Q0FUewYF020f5j7AW9EZrdu4rBTO2fliV02+DblOh/NTuHEzeCBHp3h4Mg5Bv3NYxY9sQIDAQAB";
    private final static String USERNAME = "janedoe@example.com";

    // create JWTVerifier test object
    JWTVerifier verify = new JWTVerifier();

    @Test
    void decodeAndVerifyValidJWTPayload() {
        UserDataPayload jwtData = verify.verifyJWTToken(SIGNED_TOKEN, PUBLIC_KEY);

        List<String> grps = jwtData.getGroups();

        // assert json data
        assertEquals(USERNAME, jwtData.getEmail());
        assertEquals("admin", grps.get(0));
        assertEquals("publishing", grps.get(1));
        assertEquals("data", grps.get(2));
        assertEquals("test", grps.get(3));
    }

    @Test
    void emptySecretKeySupplied() {
        assertThatThrownBy(() -> verify.verifyJWTToken(SIGNED_TOKEN, ""))
                .isInstanceOf(JWTDecodeException.class)
                .hasMessageContaining(JWTVerifier.PUBLIC_KEY_ERROR);
    }

    @Test
    void noUserNameInPayloadSupplied() {
        assertThatThrownBy(() -> verify.verifyJWTToken(TOKEN_NO_USER, PUBLIC_KEY))
                .isInstanceOf(JWTDecodeException.class)
                .hasMessageContaining(JWTVerifier.MISSING_USERNAME_ERROR);
    }

    @Test
    void noGroupsInPayloadSupplied() {
        UserDataPayload jwtData = verify.verifyJWTToken(TOKEN_NO_GROUPS, PUBLIC_KEY);

        List<String> grps = jwtData.getGroups();

        // assert json data
        assertEquals(USERNAME, jwtData.getEmail());
        assertTrue(grps.isEmpty());
    }

    @Test
    void throwErrorVerifyingToken() {
        assertThatThrownBy(() -> verify.verifyJWTToken(INVALID_SIGNED_TOKEN, PUBLIC_KEY))
                .isInstanceOf(JWTVerificationException.class)
                .hasMessageContaining(JWTVerifier.CANNOT_VERIFY_ERROR);
    }

    @Test
    void throwErrorExpiredToken() {
        assertThatThrownBy(() -> verify.verifyJWTToken(TOKEN_EXPIRED_TIME, PUBLIC_KEY))
                .isInstanceOf(JWTTokenExpiredException.class)
                .hasMessageContaining(JWTVerifier.EXPIRED_TOKEN_ERROR);
    }

    @Test
    void throwErrorTokenNull() {
        assertThatThrownBy(() -> verify.verifyJWTToken(null, PUBLIC_KEY))
                .isInstanceOf(JWTDecodeException.class)
                .hasMessageContaining(JWTVerifier.TOKEN_NULL_ERROR);
    }

    @Test
    void throwErrorTokenFormatNotValid() {
        assertThatThrownBy(() -> verify.verifyJWTToken("", PUBLIC_KEY))
                .isInstanceOf(JWTDecodeException.class)
                .hasMessageContaining(JWTVerifier.TOKEN_NOT_VALID_ERROR);
    }
}
