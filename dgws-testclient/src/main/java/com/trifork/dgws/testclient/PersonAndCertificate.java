package com.trifork.dgws.testclient;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 *
 */
public class PersonAndCertificate {
    private String firstName;
    private String lastName;
    private String email;
    private String cpr;
    private String cvr;
    private X509Certificate certificate;
    private PrivateKey privateKey;

    public PersonAndCertificate(String firstName, String lastName, String email, String cpr, String cvr,
                                X509Certificate certificate, PrivateKey privateKey) {
        super();
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.cpr = cpr;
        this.cvr = cvr;
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public String toString() {
        return firstName + " " + lastName;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getEmail() {
        return email;
    }

    public String getCpr() {
        return cpr;
    }

    public String getCvr() {
        return cvr;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
}
