package com.trifork.dgws.util;

import org.bouncycastle.jce.X509Principal;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents the Subject Number of an OCES certificate. Example format:
 * 'SERIALNUMBER=CVR:25767535-UID:1100080130597 + CN=TDC TOTALL�SNINGER A/S -
 * TDC Test, O=TDC TOTALL�SNINGER A/S // CVR:25767535, C=DK' Note that windows
 * certificate viewer shows these differently
 */
public class CertificateSubject {

    private static final String oRegExpPattern = "(o|O)(\\s)*=([^+,])*";
    private static final Pattern oPattern = Pattern.compile(oRegExpPattern);

    private static final String cRegExpPattern = "(c|C)(\\s)*=([^+,])*";
    private static final Pattern cPattern = Pattern.compile(cRegExpPattern);

    private static final String cnRegExpPattern = "(c|C)(n|N)(\\s)*=([^+,])*";
    private static final Pattern cnPattern = Pattern.compile(cnRegExpPattern);

    /**
     * subject.
     */
    private String subjectString;

    /**
     *
     */
    private String o;
    private String c;
    private String cn;

    /**
     * Constructor that takes a string representation of the certificate subject.
     *
     * @param subject Subject string to parse
     */
    public CertificateSubject(String subject) {

        X500Principal principal = new X500Principal(subject);
        setSubjectString(principal.getName(X500Principal.RFC1779));
        getBase();
    }

    /**
     * Constructor that extracts the subject from a X509 certificate.
     *
     * @param certificate The X509 certificate
     */
    public CertificateSubject(X509Certificate certificate) {

        setSubjectString(certificate.getSubjectX500Principal().getName(X500Principal.RFC1779));
        getBase();
    }

    /**
     * Constructor that takes a X500 principal as parameter.
     *
     * @param subjectDN Subject to parse
     */
    public CertificateSubject(X500Principal subjectDN) {

        setSubjectString(subjectDN.getName(X500Principal.RFC1779));
        getBase();
    }

    /**
     * Sets the subject from the given string.
     *
     * @param subject The subject to set
     */
    private void setSubjectString(String subject) {

        subjectString = subject.trim();
    }

    /**
     * Returns the subject as a String.
     *
     * @return String representation of the subject
     */
    public String getSubjectString() {
        return subjectString;
    }

    public String getO() {
        return o;
    }

    public String getC() {
        return c;
    }

    public String getCn() {
        return cn;
    }

    /**
     * Gets the subject serial number
     *
     * @return The subject serial number
     */
    public String getSerialNumberValue() {
        return parseSerialNumber(subjectString);
    }

    /**
     * Subject Serial Number prefixed with "serialNumber"
     *
     * @return The prefixed serial number
     */
    public String getPrefixedSerialNumber() {
        return SERIALNUMBERPREFIX + "=" + parseSerialNumber(subjectString);
    }

    /**
     * Serial number as text - for parsing.
     */
    public static final String SERIALNUMBERPREFIX = "serialNumber";


    /**
     * Parse subject for serial number.
     *
     * @param subject The subject to parse
     * @return The parsed serial number
     */
    public static String parseSerialNumber(String subject) {
        X509Principal principal = new X509Principal(subject);
        Vector v = principal.getValues(X509Principal.SERIALNUMBER);
        if (v.size() > 0) {
            return v.get(0).toString();
        }
        throw new IllegalArgumentException("could not parse serialnumber [" + subject + "]");
    }

    /*
     * Fetches the base string used in the ldap search. The string is gained from the subject string.
	 * If there is no pattern in the subject string that tells what o= and c= an exception will be thrown.
     */
    private void getBase() {

        Matcher oMatcher = oPattern.matcher(subjectString);
        Matcher cMatcher = cPattern.matcher(subjectString);
        Matcher cnMatcher = cnPattern.matcher(subjectString);

        if (!oMatcher.find() || !cMatcher.find() || !cnMatcher.find()) {
            throw new IllegalArgumentException("Patterns did not match");
        }

        o = getAssignment(oMatcher.group()).trim();
        c = getAssignment(cMatcher.group()).trim();
        cn = getAssignment(cnMatcher.group()).trim();
    }

    private String getAssignment(String text) {
        String[] assignmentParts = text.split("=");
        return assignmentParts[1];
    }

    /**
     * Try to get the cvr number as a string value from the certificate, if such exists
     *
     * @return Whether a cvr number string value could be parsed.
     */
    public String getCvrNumberString() {

        String serialNumberValue = getSerialNumberValue();
        Pattern regEx = Pattern.compile("CVR:\\d+");
        Matcher match = regEx.matcher(serialNumberValue);

        if (!match.find()) {
            throw new IllegalArgumentException("Pattern did not match");
        }

        String cvrNumber = match.group();
        cvrNumber = cvrNumber.replace("CVR:", "");
        cvrNumber = cvrNumber.trim();

        if (cvrNumber != null && !cvrNumber.isEmpty()) {
            return cvrNumber;
        } else {
            throw new IllegalArgumentException("CVR number could not be retrieved");
        }
    }

    @Override
    public int hashCode() {
        return subjectString.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }

        if (!(obj instanceof CertificateSubject)) {
            return false;
        }

        CertificateSubject other = (CertificateSubject) obj;

        return other.subjectString.equals(subjectString);
    }

    @Override
    public String toString() {
        return subjectString;
    }
}