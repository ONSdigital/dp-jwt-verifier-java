package com.github.onsdigital;

import com.github.onsdigital.exceptions.JWTDecodeException;
import com.github.onsdigital.exceptions.JWTTokenExpiredException;
import com.github.onsdigital.exceptions.JWTVerificationException;
import com.google.api.client.http.HttpResponse;
import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.BDDMockito.given;


import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JWTVerifierImplTests {
    private final static String SIGNED_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzRleGFtcGxlPSJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iLCJkYXRhIiwicHVibGlzaGluZyIsInRlc3QiXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6Nzk1NzA3MTI5MSwiaWF0IjoxNTYyMTkwNTI0LCJvcmlnaW5fanRpIjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwianRpIjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY2xpZW50X2lkIjoiNTdjYmlzaGs0ajI0cGFiYzEyMzQ1Njc4OTAiLCJ1c2VybmFtZSI6ImphbmVkb2VAZXhhbXBsZS5jb20ifQ.MrdJLEQ_YIG9uxJYguy9343CsW3WQ_TbaVKvbk0-ie_y1_WZF8wbGDybxfBeAQ9cy63f-bsuw4xQU8AavDNolR7F7bwWLPDAwkywauQXnUseDuEiNaA7xq386I0WmrUsTpNmCT7NgHDkDiBLSItxfd1aUxi2Z3lxr49TnzxKFmwZOGNE7k7xSlqzlwOmk78DvvI5RFknmzl1B3LJy7cqEnLK19LqcJcZlC5fzZH23fc8F7wAoKH755ARCVm2HrU2r_8pBXKl89siD0D6oy2f9NWUQikdP9XuCIPnDXNDSzdaDmqxz82vpm2rhWAwxfXLoIyR1eu9Za8VcN1Mk6oWrA";

    private final static String INVALID_KID_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRoaXNpc3dyb25nIn0.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6Nzk1NzA3MTI5MSwiaWF0IjoxNTYyMTkwNTI0LCJvcmlnaW5fanRpIjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwianRpIjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY2xpZW50X2lkIjoiNTdjYmlzaGs0ajI0cGFiYzEyMzQ1Njc4OTAiLCJ1c2VybmFtZSI6ImphbmVkb2VAZXhhbXBsZS5jb20ifQ.tVeYZMwPY-MCZGbZwwNLP5jcORs3obZhTOhzrODKhlS8pK-MYBBIPcb3PNYcJ58jbTacYCblcAZiU3O0NZslUMe-DOJgpPjt14lbr1nc5_gkdFBpVWBBjpionAH0DJ4EL6oaxtdtXGLCTI-OyLJ7kdU5CHZ0zDXTypJNNl7ZQkeDnPPAA27-3CcfSE3JC2ug8E-8yhgom_tDzTBADC2QJNqFmcC0eW69Vdt1rmMlg8pA146c1hZ_knvBH-f2pLnnCbgYHjftJ8ojcMNmKmDE4_M3dfOXt6yLcfUJd_86-bpOU97neZEn_OWVeg_UcUzsnaOhkx02DdunraOdNnt0aw";

    private final static String INVALID_SIGNED_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzRleGFtcGxlPSJ9.eyJzdWIiOiJUSElTIElTIEEgQ0hBTkdFIiwiZGV2aWNlX2tleSI6ImFhYWFhYWFhLWJiYmItY2NjYy1kZGRkLWVlZWVlZWVlZWVlZSIsImNvZ25pdG86Z3JvdXBzIjpbImFkbWluIl0sInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE1NjIxOTA1MjQsImlzcyI6Imh0dHBzOi8vY29nbml0by1pZHAudXMtd2VzdC0yLmFtYXpvbmF3cy5jb20vdXMtd2VzdC0yX2V4YW1wbGUiLCJleHAiOjc5NTcwNzEyOTEsImlhdCI6MTU2MjE5MDUyNCwib3JpZ2luX2p0aSI6ImFhYWFhYWFhLWJiYmItY2NjYy1kZGRkLWVlZWVlZWVlZWVlZSIsImp0aSI6ImFhYWFhYWFhLWJiYmItY2NjYy1kZGRkLWVlZWVlZWVlZWVlZSIsImNsaWVudF9pZCI6IjU3Y2Jpc2hrNGoyNHBhYmMxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJqYW5lZG9lQGV4YW1wbGUuY29tIn0.Ya8sSlFreEEm63HvA5SHw2bipvaaJzE_0tx4P3iqWZrdQYNzYvwMJHZSXcZE82w79Z8o4pl36BHVQF7VkxnQprVuhO48kHw1Ev20xxTlRwwhskM8Mykefu0B8b_2nrDZBMjAaS1JtM_VPvKXxXnYV-1_MhJnByf-9czJjJJB69MNRF2dLU0PARF-W6Gh113Q8lHk1zNBpAaxv--iyfwbB_vC0vTtz0Y6QV3gYZqjnWdD6dWsJiHsdkdB2J3dGyW2lc9Bgv4sb4IotBhFMQGFo6K9uCxjZbN_uPfOU88ykfBa_EaHIsg8sJo1LCM8VoirR1gfwVxcRpVsbrcgiiO4pw";

    private final static String TOKEN_NO_USER = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzRleGFtcGxlPSJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6Nzk1NzA3MTI5MSwiaWF0IjoxNTYyMTkwNTI0LCJvcmlnaW5fanRpIjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwianRpIjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY2xpZW50X2lkIjoiNTdjYmlzaGs0ajI0cGFiYzEyMzQ1Njc4OTAifQ.Ya8sSlFreEEm63HvA5SHw2bipvaaJzE_0tx4P3iqWZrdQYNzYvwMJHZSXcZE82w79Z8o4pl36BHVQF7VkxnQprVuhO48kHw1Ev20xxTlRwwhskM8Mykefu0B8b_2nrDZBMjAaS1JtM_VPvKXxXnYV-1_MhJnByf-9czJjJJB69MNRF2dLU0PARF-W6Gh113Q8lHk1zNBpAaxv--iyfwbB_vC0vTtz0Y6QV3gYZqjnWdD6dWsJiHsdkdB2J3dGyW2lc9Bgv4sb4IotBhFMQGFo6K9uCxjZbN_uPfOU88ykfBa_EaHIsg8sJo1LCM8VoirR1gfwVxcRpVsbrcgiiO4pw";

    private final static String TOKEN_NO_GROUPS = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzRleGFtcGxlPSJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6Nzk1NzA3MTI5MSwiaWF0IjoxNTYyMTkwNTI0LCJvcmlnaW5fanRpIjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwianRpIjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY2xpZW50X2lkIjoiNTdjYmlzaGs0ajI0cGFiYzEyMzQ1Njc4OTAiLCJ1c2VybmFtZSI6ImphbmVkb2VAZXhhbXBsZS5jb20ifQ.F5EAB5F-Hx6RsrRCy3DZkxbcn_FkwUYthqB5acIKuAluTgyK59EsI8UA428w-WZmwD1Io_wLciuZmQNsBC650Bx7_4HmF6YS434d3Pn3XHGKpnqwiusAIse6Vbfkj5U9HWQARQfl2YIrAlfUHLdwjAgqWhqLQ8bUyMoHFLKqfJ4zLyAbyD0806aQIK3oQAkSF8-Xk_RuyBzI5OmF_4ODCwn9h8auX9xKmSsIrpBOhqJtfTWLY1COP822wmzDgJcP-8HfYcS0RXZu9DZOv-xrAsvKXZFod3jIWl7ZdD306VqwVTYjN5W_8YJASqaHS-WCtt1zV3AVe9iRlB1xw-jB0w";

    private final static String TOKEN_EXPIRED_TIME = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzRleGFtcGxlPSJ9.eyJzdWIiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJkZXZpY2Vfa2V5IjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY29nbml0bzpncm91cHMiOlsiYWRtaW4iXSwidG9rZW5fdXNlIjoiYWNjZXNzIiwic2NvcGUiOiJhd3MuY29nbml0by5zaWduaW4udXNlci5hZG1pbiIsImF1dGhfdGltZSI6MTU2MjE5MDUyNCwiaXNzIjoiaHR0cHM6Ly9jb2duaXRvLWlkcC51cy13ZXN0LTIuYW1hem9uYXdzLmNvbS91cy13ZXN0LTJfZXhhbXBsZSIsImV4cCI6MTU2MjE5NDEyNCwiaWF0IjoxNTYyMTkwNTI0LCJvcmlnaW5fanRpIjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwianRpIjoiYWFhYWFhYWEtYmJiYi1jY2NjLWRkZGQtZWVlZWVlZWVlZWVlIiwiY2xpZW50X2lkIjoiNTdjYmlzaGs0ajI0cGFiYzEyMzQ1Njc4OTAiLCJ1c2VybmFtZSI6ImphbmVkb2VAZXhhbXBsZS5jb20ifQ.Jo1Ex-iOlQw8BJaDUFP6rGJM4owdFs90ti53Upri_re01wvHssbDOmIKGjRPbHX8tPi-Gjpdsbdp00RmI56wiIZee7X6VvPjGOZAI-q4InNhS5JIKdJv_CPu33e5TTmOVjVvIOctm_uZNL7Yd9A0Haz3-3BzlT-nUJ5OgTIjYsecHlSpNg-ie7-YY34u40obMNvk4WpqU1zIdbHYpeB08gxHCSSnhXxu-4d1-XGJAWbINEyD93_steGsGDMS4VTiKQl96pAT7LnZLLiPjlkoAC-T9BsOQtK3riUhU2VM0KUTqyhM2rcgTQy-zs-E8_Yf37a77s1_FPkmNbYJsIDInQ";

    private final static String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwdowpUQS8YPrzFamOi7bEM74+yeqoAH0Tm+PLZdWjaIxL13XfxX63jO3iHAJe/Uh74d2vtTuHV7Vkl0wRjjJOuWrj5espG5VxU6xHJG/R2tVDElv05fFZhZn/YCwUJV2Zrz9Z0PIdPHB4eZODo64Qfab+ihgeLlny5l6+srVacWqsQ47i3DdJQOd6MgacvrKt+B0Ior1HKlHR0NneFPNu9zvCg11O1W0yl2+ou0UOPVqF8EfoavvgwbAUWwxeHXcN+TmgKx6Oa4X9ylk+Q0FUewYF020f5j7AW9EZrdu4rBTO2fliV02+DblOh/NTuHEzeCBHp3h4Mg5Bv3NYxY9sQIDAQAB";

    private final static String USERNAME = "janedoe@example.com";

    private final static String USER_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    private final static String PUBLIC_KEY_ID = "1234example=";

    Map<String, String> signingKeys = new HashMap<String, String>() {{
        put(PUBLIC_KEY_ID, PUBLIC_KEY);
    }};
    /**
     * Class under test
     */
    private JWTVerifierImpl verifier;

    @BeforeEach
    void beforeEach() {
        verifier = new JWTVerifierImpl(signingKeys);
    }

    @Test
    void verify_ShouldSucceed_WhenJWTValid() {
        UserDataPayload jwtData = verifier.verify(SIGNED_TOKEN);

        List<String> grps = jwtData.getGroups();

        // assert json data
        assertEquals(USER_ID, jwtData.getId());
        assertEquals(USERNAME, jwtData.getEmail());
        assertEquals(4, grps.size());
        assertEquals("admin", grps.get(0));
        assertEquals("data", grps.get(1));
        assertEquals("publishing", grps.get(2));
        assertEquals("test", grps.get(3));
    }

    @Test
    void verify_ShouldThrowException_WhenKeyIDUnknown() {
        assertThatThrownBy(() -> verifier.verify(INVALID_KID_TOKEN))
                .isInstanceOf(JWTDecodeException.class)
                .hasMessageContaining(SigningKeyResolverImpl.PUBLIC_KEY_ERROR);
    }

    @Test
    void verify_ShouldThrowException_WhenNoUsername() {
        assertThatThrownBy(() -> verifier.verify(TOKEN_NO_USER))
                .isInstanceOf(JWTDecodeException.class)
                .hasMessageContaining(JWTVerifierImpl.MISSING_USERNAME_ERROR);
    }

    @Test
    void verify_ShouldSucceed_WhenNoGroups() {
        UserDataPayload jwtData = verifier.verify(TOKEN_NO_GROUPS);

        List<String> grps = jwtData.getGroups();

        // assert json data
        assertEquals(USER_ID, jwtData.getId());
        assertEquals(USERNAME, jwtData.getEmail());
        assertTrue(grps.isEmpty());
    }

    @Test
    void verify_ShouldThrowException_WhenSignatureInvalid() {
        assertThatThrownBy(() -> verifier.verify(INVALID_SIGNED_TOKEN))
                .isInstanceOf(JWTVerificationException.class)
                .hasMessageContaining(JWTVerifierImpl.SIGNATURE_VERIFICATION_ERROR);
    }

    @Test
    void verify_ShouldThrowException_WhenTokenExpired() {
        assertThatThrownBy(() -> verifier.verify(TOKEN_EXPIRED_TIME))
                .isInstanceOf(JWTTokenExpiredException.class)
                .hasMessageContaining(JWTVerifierImpl.EXPIRED_TOKEN_ERROR);
    }

    @Test
    void verify_ShouldThrowException_WhenJWTNull() {
        assertThatThrownBy(() -> verifier.verify(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("JWT String argument cannot be null or empty.");
    }

    @Test
    void verify_ShouldThrowException_WhenJWTEmpty() {
        assertThatThrownBy(() -> verifier.verify(""))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("JWT String argument cannot be null or empty.");
    }

    @Test
    void verify_ShouldFetchJWTKeys_WhenIdentityApiUrlIsProvided() throws Exception {
        HttpResponse mockResponse = Mockito.mock(HttpResponse.class);
        given(mockResponse.getStatusCode()).willReturn(200);
        Mockito.when(mockResponse.parseAs(Mockito.any())).thenReturn(signingKeys);
        JWTKeyProvider jwtKeyProvider = Mockito.mock(JWTKeyProvider.class);
        Mockito.when(jwtKeyProvider.getJwtKeys()).thenCallRealMethod();
        Mockito.when(jwtKeyProvider.getJwtKeysFromIdentityApi()).thenReturn(mockResponse);

        JWTVerifierImpl jwtVerifier = new JWTVerifierImpl(jwtKeyProvider);
        UserDataPayload jwtData = jwtVerifier.verify(SIGNED_TOKEN);

        List<String> grps = jwtData.getGroups();
        assertEquals(USER_ID, jwtData.getId());
        assertEquals(USERNAME, jwtData.getEmail());
        assertEquals(4, grps.size());
        assertEquals("admin", grps.get(0));
        assertEquals("data", grps.get(1));
        assertEquals("publishing", grps.get(2));
        assertEquals("test", grps.get(3));
    }

    @Test
    void verify_ShouldThrowException_WhenFailedToFetchJwtKeys() throws Exception {
        HttpResponse mockResponse = Mockito.mock(HttpResponse.class);
        given(mockResponse.getStatusCode()).willReturn(500);
        Mockito.when(mockResponse.parseAs(Mockito.any())).thenReturn(signingKeys);
        JWTKeyProvider jwtKeyProvider = Mockito.mock(JWTKeyProvider.class);
        Mockito.when(jwtKeyProvider.getJwtKeys()).thenCallRealMethod();
        Mockito.when(jwtKeyProvider.getJwtKeysFromIdentityApi()).thenReturn(mockResponse);

        Exception exception = assertThrows(Exception.class, () -> new JWTVerifierImpl(jwtKeyProvider));
        Assert.assertThat(exception.getMessage(), CoreMatchers.containsString("Failed to get jet keys:"));
    }

    @Test
    void verify_ShouldThrowException_WhenIdentityApiReturnEmptySuccessResponse() throws Exception {
        HttpResponse mockResponse = Mockito.mock(HttpResponse.class);
        given(mockResponse.getStatusCode()).willReturn(200);
        Mockito.when(mockResponse.parseAs(Mockito.any())).thenReturn(new HashMap<String, String>());
        JWTKeyProvider jwtKeyProvider = Mockito.mock(JWTKeyProvider.class);
        Mockito.when(jwtKeyProvider.getJwtKeys()).thenCallRealMethod();
        Mockito.when(jwtKeyProvider.getJwtKeysFromIdentityApi()).thenReturn(mockResponse);

        Exception exception = assertThrows(Exception.class, () -> new JWTVerifierImpl(jwtKeyProvider));
        Assert.assertThat(exception.getMessage(), CoreMatchers.containsString("JWT keys not found in the response"));
    }
}
