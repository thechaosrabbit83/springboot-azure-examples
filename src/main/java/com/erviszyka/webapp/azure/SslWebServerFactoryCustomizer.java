package com.erviszyka.webapp.azure;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import com.microsoft.azure.keyvault.spring.certificate.KeyCert;
import com.microsoft.azure.keyvault.spring.certificate.KeyCertReader;
import com.microsoft.azure.keyvault.spring.certificate.KeyCertReaderFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

@Component
public class SslWebServerFactoryCustomizer implements WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> {
    private final String keyAlias;

    public SslWebServerFactoryCustomizer(
            @Value("${server.ssl.key-alias}") String keyAlias) {
        this.keyAlias = keyAlias;
    }

    @Override
    public void customize(ConfigurableServletWebServerFactory factory) {
        try {
            Resource certResource = getCertificateFromAzure();
            KeyCertReader certReader = KeyCertReaderFactory.getReader(certResource.getFilename());

            KeyCert pfx = certReader.read(certResource, null);
            KeyStore keystore = createKeyStore(pfx);

            KeyStore trustStore = createTrustStore(pfx);

            factory.setSslStoreProvider(new CustomSslStoreProvider(keystore, trustStore));

        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("Cannot configure SSL certificate from Azure Vault", e);
        }
    }

    // TODO: get certificate from azure
    private Resource getCertificateFromAzure() {
        return new DefaultResourceLoader().getResource("cert/certificate.pfx");
    }

    private KeyStore createKeyStore(KeyCert keyCert) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setKeyEntry(keyAlias, keyCert.getKey(), new char[0], new Certificate[]{keyCert.getCertificate()});
        return keyStore;
    }

    private KeyStore createTrustStore(KeyCert pfx) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        final KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);

        trustStore.setCertificateEntry("ca", pfx.getCertificate());
        trustStore.setCertificateEntry("cert", pfx.getCertificate());

        return trustStore;
    }
}
