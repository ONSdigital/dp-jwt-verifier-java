package com.github.onsdigital;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpBackOffUnsuccessfulResponseHandler;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.util.ExponentialBackOff;

import java.io.IOException;


/**
 * RequestBuilder - builds the http request to fetch data.
 */
public class RequestBuilder {

    RequestBuilder() { }

    /**
     * Builds the http get request with exponential retries.
     * @param url             used to fetch the signing keys
     * @param initialInterval the initial interval in milliseconds to be used for exponential retries
     * @param maxElapsedTime  the max elapsed time in milliseconds to be used for exponential retries
     * @param maxInterval     the max interval in milliseconds to be used for exponential retries
     * @return the http get request with exponential retries
     * @throws IOException if failed to fetch signing keys from the server
     */
    public HttpRequest getRequest(String url, int initialInterval, int maxElapsedTime, int maxInterval) throws IOException {
        ExponentialBackOff backoff = new ExponentialBackOff.Builder()
                .setInitialIntervalMillis(initialInterval)
                .setMaxElapsedTimeMillis(maxElapsedTime)
                .setMaxIntervalMillis(maxInterval)
                .build();

        return new NetHttpTransport()
                .createRequestFactory()
                .buildGetRequest(new GenericUrl(url))
                .setUnsuccessfulResponseHandler(new HttpBackOffUnsuccessfulResponseHandler(backoff));
    }
}
