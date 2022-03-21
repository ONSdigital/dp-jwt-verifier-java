package com.github.onsdigital;

import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class JWTKeyProviderImplTest {

    private final static String PUBLIC_KEY_ID = "1234example=";
    private final static String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwdowpUQS8YPrzFamOi7bEM74+yeqoAH0Tm+PLZdWjaIxL13XfxX63jO3iHAJe/Uh74d2vtTuHV7Vkl0wRjjJOuWrj5espG5VxU6xHJG/R2tVDElv05fFZhZn/YCwUJV2Zrz9Z0PIdPHB4eZODo64Qfab+ihgeLlny5l6+srVacWqsQ47i3DdJQOd6MgacvrKt+B0Ior1HKlHR0NneFPNu9zvCg11O1W0yl2+ou0UOPVqF8EfoavvgwbAUWwxeHXcN+TmgKx6Oa4X9ylk+Q0FUewYF020f5j7AW9EZrdu4rBTO2fliV02+DblOh/NTuHEzeCBHp3h4Mg5Bv3NYxY9sQIDAQAB";
    Map<String, String> signingKeys = new HashMap<String, String>() {{
        put(PUBLIC_KEY_ID, PUBLIC_KEY);
    }};

    @Test
    void verify_ShouldThrowException_WhenIdentityApiReturnEmptySuccessResponse() throws Exception {
        HttpResponse mockResponse = Mockito.mock(HttpResponse.class);
        given(mockResponse.getStatusCode()).willReturn(200);
        Mockito.when(mockResponse.parseAs(Mockito.any())).thenReturn(new HashMap<String, String>());
        RequestBuilder mockedRequestBuilder = getMockedRequestBuilder(mockResponse);
        JWTKeyProviderImpl jwtKeyProvider = new JWTKeyProviderImpl("url", 5, 5, 5, mockedRequestBuilder);

        Exception exception = assertThrows(Exception.class, () -> jwtKeyProvider.getJwtKeys());
        Assert.assertThat(exception.getMessage(), CoreMatchers.containsString("JWT keys not found in the response"));
        verify(mockResponse, times(1)).disconnect();
    }


    @Test
    void verify_ShouldFetchJWTKeys_WhenIdentityApiUrlIsProvided() throws Exception {
        HttpResponse mockResponse = Mockito.mock(HttpResponse.class);
        given(mockResponse.getStatusCode()).willReturn(200);
        Mockito.when(mockResponse.parseAs(any())).thenReturn(signingKeys);
        RequestBuilder mockedRequestBuilder = getMockedRequestBuilder(mockResponse);
        JWTKeyProviderImpl jwtKeyProvider = new JWTKeyProviderImpl("url", 5, 5, 5, mockedRequestBuilder);

        Map<String, String> signingKeysFromApi = jwtKeyProvider.getJwtKeys();

        assertEquals(signingKeys, signingKeysFromApi);
        verify(mockResponse, times(1)).disconnect();
    }

    @Test
    void verify_ShouldThrowException_WhenFailedToFetchJwtKeys() throws Exception {
        HttpResponse mockResponse = Mockito.mock(HttpResponse.class);
        given(mockResponse.getStatusCode()).willReturn(500);
        Mockito.when(mockResponse.parseAs(any())).thenReturn(signingKeys);
        RequestBuilder mockedRequestBuilder = getMockedRequestBuilder(mockResponse);
        JWTKeyProviderImpl jwtKeyProvider = new JWTKeyProviderImpl("url", 5, 5, 5, mockedRequestBuilder);

        Exception exception = assertThrows(Exception.class, () -> jwtKeyProvider.getJwtKeys());

        Assert.assertThat(exception.getMessage(), CoreMatchers.containsString("Failed to get jwt keys:"));
        verify(mockResponse, times(1)).disconnect();
    }

    @Test
    void verify_ShouldThrowException_WhenResponseIsNull() throws Exception {
        RequestBuilder mockedRequestBuilder = getMockedRequestBuilder(null);
        JWTKeyProviderImpl jwtKeyProvider = new JWTKeyProviderImpl("url", 5, 5, 5, mockedRequestBuilder);

        Exception exception = assertThrows(Exception.class, () -> jwtKeyProvider.getJwtKeys());

        Assert.assertThat(exception.getMessage(), CoreMatchers.containsString("Failed to get response from server:"));
    }

    private RequestBuilder getMockedRequestBuilder(HttpResponse mockResponse) throws IOException {
        HttpRequest mockRequest = Mockito.mock(HttpRequest.class);
        given(mockRequest.execute()).willReturn(mockResponse);

        RequestBuilder mockRequestBuilder = Mockito.mock(RequestBuilder.class);
        given(mockRequestBuilder.getRequest(anyString(), anyInt(), anyInt(), anyInt())).willReturn(mockRequest);

        return mockRequestBuilder;
    }
}
