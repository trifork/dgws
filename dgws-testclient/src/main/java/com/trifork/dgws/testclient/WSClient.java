package com.trifork.dgws.testclient;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

import java.io.File;
import java.io.IOException;

/**
 *
 */
public class WSClient {
    private static final Logger logger = Logger.getLogger(WSClient.class);

    private static final String PROPERTY_XML_BODY_FILE = "xmlfile";
    private static final String PROPERTY_SOAPACTION = "soapaction";

    public static void main(String[] args) throws Exception {
        String path = null, soapAction = null;

        String xmlFile = System.getProperty(PROPERTY_XML_BODY_FILE);

        if (args.length != 0) {
            String name = WSClient.class.getName();
            System.out.println("Usage: " + name + " -D" + PROPERTY_XML_BODY_FILE + "=<path_to_xml_file_to_use_as_body> [-D" + PROPERTY_SOAPACTION + "=<soapAction>]\n");
            System.out.println("\t" + name + " -D" + PROPERTY_XML_BODY_FILE + "=getVaccinationCardRequest.xml");
            System.out.println("\tor");
            System.out.println("\t" + name + " -D" + PROPERTY_XML_BODY_FILE + "=getVaccinationCardRequest.xml -D" + PROPERTY_SOAPACTION + "=\"http://vaccinationsregister.dk/schemas/2010/07/01#GetVaccinationCard\"");
            System.exit(0);
        }


        WSClient wsClient = new WSClient();
        File xmlFileForBody = null;
        if (xmlFile != null) {
            Resource res = new FileSystemResource(xmlFile);
            if (!res.exists()) {
                throw new RuntimeException("Input '" + path + "' not found");
            } else {
                xmlFileForBody = res.getFile();
            }
        }

        String response = wsClient.callWebService(xmlFileForBody);

        System.out.println(XmlPrettyPrint.formatXml(response));
    }

    private ClassPathXmlApplicationContext applicationContext;

    public WSClient() {
        applicationContext = new ClassPathXmlApplicationContext("applicationContext.xml");
    }

    public String callWebService(File xmlBody) throws Exception {
        DGWSRequestHelper requestHelper = applicationContext.getBean(DGWSRequestHelper.class);
        logger.info(XmlPrettyPrint.formatXml(requestHelper.getSoapEnvelope(getPayload(xmlBody))));

        return requestHelper.makeRequest(getPayload(xmlBody));
    }

    public String getPayload(File file) throws IOException {
        if (file == null) return "";
        return FileUtils.readFileToString(file, "UTF-8");

    }
}
