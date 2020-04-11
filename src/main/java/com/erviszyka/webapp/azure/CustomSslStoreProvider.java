package com.erviszyka.webapp.azure;

import java.security.KeyStore;

import org.springframework.boot.web.server.SslStoreProvider;

public class CustomSslStoreProvider implements SslStoreProvider {
    private final KeyStore keyStore;
    private final KeyStore trustStore;

    public CustomSslStoreProvider(KeyStore keyStore, KeyStore trustStore) {
        this.keyStore = keyStore;
        this.trustStore = trustStore;
    }

    @Override
    public KeyStore getKeyStore() throws Exception {
        return keyStore;
    }

    @Override
    public KeyStore getTrustStore() throws Exception {
        return trustStore;
    }
}
