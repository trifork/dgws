package com.trifork.dgws.annotations;

import com.trifork.dgws.sosi.SOSISecurityInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.context.annotation.ImportResource;
import org.springframework.core.type.AnnotationMetadata;

import java.util.Map;

@Configuration
@ImportResource("classpath:/dk/trifork/dgws/dgws-protection.xml")
public class DgwsConfiguration implements ImportAware {
    Boolean production;
    Boolean skipSosi;

    public void setImportMetadata(AnnotationMetadata importMetadata) {
        final Map<String, Object> meta = importMetadata.getAnnotationAttributes("com.trifork.dgws.annotations.EnableDgwsProtection");
        production = Boolean.parseBoolean(meta.get("production").toString());
        skipSosi = Boolean.parseBoolean(meta.get("skipSOSI").toString());
    }

    @Bean
    public SOSISecurityInterceptor sosiSecurityInterceptor() {
        SOSISecurityInterceptor interceptor = new SOSISecurityInterceptor();
        if (production != null && production.booleanValue()) {
            interceptor.setProduction(true);
        }
        else {
            interceptor.setProduction(false);
        }

        if (skipSosi != null && skipSosi.booleanValue()) {
            interceptor.setCanSkipSosi(true);
        }
        else {
            interceptor.setCanSkipSosi(false);
        }
        return interceptor;


    }
}
