package com.trifork.dgws.testclient;

import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 *
 */
public class Helper {
    public static String sendRequest(String url, String action, String docXml, boolean failOnError) throws IOException, ServiceException {
        URL u = new URL(url);
        HttpURLConnection uc = (HttpURLConnection) u.openConnection();
        uc.setDoOutput(true);
        uc.setDoInput(true);
        uc.setRequestMethod("POST");
        uc.setRequestProperty("SOAPAction", "\"" + action + "\"");
        uc.setRequestProperty("Content-Type", "text/xml; charset=utf-8;");
        OutputStream os = uc.getOutputStream();

        IOUtils.write(docXml, os, "UTF-8");
        os.flush();
        os.close();

        InputStream is;
        if (uc.getResponseCode() != 200) {
            is = uc.getErrorStream();
        } else {
            is = uc.getInputStream();
        }
        String res = IOUtils.toString(is);

        is.close();
        if (uc.getResponseCode() != 200 && (uc.getResponseCode() != 500 || failOnError)) {
            throw new ServiceException(res);
        }
        uc.disconnect();

        return res;
    }

    public static class ServiceException extends Exception {

        private static final long serialVersionUID = -391997961358118049L;
        private final String res;

        public ServiceException(String res) {
            this.res = res;
        }

        @Override
        public String getMessage() {
            return super.getMessage() + ". Result = "+res;
        }

        public String getResponse() {
            return res;
        }
    }
}
