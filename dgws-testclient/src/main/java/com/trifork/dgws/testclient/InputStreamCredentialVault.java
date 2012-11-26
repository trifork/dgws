package com.trifork.dgws.testclient;

import dk.sosi.seal.vault.ArchivableCredentialVault;
import dk.sosi.seal.vault.CredentialVaultException;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Properties;

/**
 *
 */
public class InputStreamCredentialVault extends ArchivableCredentialVault {

    public InputStreamCredentialVault(Properties properties, InputStream keystoreIs, String keyStorePassword) throws CredentialVaultException {
        super(properties, keyStorePassword);

        try {
            if (keystoreIs != null) {
                keyStore.load(keystoreIs, keyStorePassword.toCharArray());
                System.out.println("============>>> keystore loaded from inputstream");
                keystoreIs.close();
            } else {
                keyStore.load(null, keyStorePassword.toCharArray());
            }
        } catch (IOException e) {
            throw new CredentialVaultException("Unable to load KeyStore stream", e);
        } catch (NoSuchAlgorithmException e) {
            throw new CredentialVaultException("Unable to load KeyStore stream", e);
        } catch (CertificateException e) {
            throw new CredentialVaultException("Unable to load KeyStore stream", e);
        }


    }


}
