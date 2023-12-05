package com.github.onsdigital;

import com.github.onsdigital.exceptions.JWTDecodeException;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Locator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.security.Key;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;

class SigningKeyLocatorImplTests {

    private final static String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwdowpUQS8YPrzFamOi7bEM74+yeqoAH0Tm+PLZdWjaIxL13XfxX63jO3iHAJe/Uh74d2vtTuHV7Vkl0wRjjJOuWrj5espG5VxU6xHJG/R2tVDElv05fFZhZn/YCwUJV2Zrz9Z0PIdPHB4eZODo64Qfab+ihgeLlny5l6+srVacWqsQ47i3DdJQOd6MgacvrKt+B0Ior1HKlHR0NneFPNu9zvCg11O1W0yl2+ou0UOPVqF8EfoavvgwbAUWwxeHXcN+TmgKx6Oa4X9ylk+Q0FUewYF020f5j7AW9EZrdu4rBTO2fliV02+DblOh/NTuHEzeCBHp3h4Mg5Bv3NYxY9sQIDAQAB";

    private final static String PUBLIC_KEY_ID = "1234example=";

    @Mock
    private JwsHeader jwsHeader;

    @BeforeEach
    void beforeEach() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void constructor_ShouldThrowException_WhenNullSigningKeys() {
        assertThatThrownBy(() -> new SigningKeyLocatorImpl(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(SigningKeyLocatorImpl.KEYS_REQUIRED_ERROR);
    }

    @Test
    void constructor_ShouldThrowException_WhenNotValidKeyFormat() {
        Map<String, String> signingKeys = new HashMap<>();
        signingKeys.put("1234", "SU5WQUxJRF9LRVk=");
        assertThatThrownBy(() -> new SigningKeyLocatorImpl(signingKeys))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(SigningKeyLocatorImpl.PUBLIC_KEY_CHECK_ERROR);
    }

    @Test
    void constructor_ShouldThrowException_WhenKeyNotBase64() {
        Map<String, String> signingKeys = new HashMap<>();
        signingKeys.put("1234", "INVALID_KEY");
        assertThatThrownBy(() -> new SigningKeyLocatorImpl(signingKeys))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Illegal base64 character");
    }

    @Test
    void resolveSigningKey_ShouldReturnKey_WhenKeyIDKnown() {
        Map<String, String> signingKeys = new HashMap<>();
        signingKeys.put(PUBLIC_KEY_ID, PUBLIC_KEY);
        Locator<Key> keyLocator = new SigningKeyLocatorImpl(signingKeys);

        when(jwsHeader.getKeyId()).thenReturn(PUBLIC_KEY_ID);

        Key result = keyLocator.locate(jwsHeader);

        assertNotNull(result);
        assertEquals("RSA", result.getAlgorithm());
    }

    @Test
    void resolveSigningKey_ShouldThrowException_WhenKeyIDNotKnown() {
        Map<String, String> signingKeys = new HashMap<>();
        signingKeys.put(PUBLIC_KEY_ID, PUBLIC_KEY);
        Locator<Key> keyLocator = new SigningKeyLocatorImpl(signingKeys);

        when(jwsHeader.getKeyId()).thenReturn("unknown_key_id");

        assertThatThrownBy(() -> keyLocator.locate(jwsHeader))
                .isInstanceOf(JWTDecodeException.class)
                .hasMessageContaining(SigningKeyLocatorImpl.PUBLIC_KEY_ERROR);
    }

    @Test
    void resolveSigningKey_ShouldThrowException_WhenKeyIDNull() {
        Map<String, String> signingKeys = new HashMap<>();
        signingKeys.put(PUBLIC_KEY_ID, PUBLIC_KEY);
        Locator<Key> keyLocator = new SigningKeyLocatorImpl(signingKeys);

        when(jwsHeader.getKeyId()).thenReturn(null);

        assertThatThrownBy(() -> keyLocator.locate(jwsHeader))
                .isInstanceOf(JWTDecodeException.class)
                .hasMessageContaining(SigningKeyLocatorImpl.PUBLIC_KEY_ERROR);
    }
}
