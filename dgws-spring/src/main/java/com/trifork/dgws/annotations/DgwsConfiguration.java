package com.trifork.dgws.annotations;

import com.trifork.dgws.sosi.SOSISecurityInterceptor;
import org.springframework.context.EmbeddedValueResolverAware;
import org.springframework.context.annotation.*;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.util.StringValueResolver;

import java.util.Map;

@Configuration
@ImportResource("classpath:/dk/trifork/dgws/dgws-protection.xml")
public class DgwsConfiguration implements ImportAware, EmbeddedValueResolverAware {
    Boolean production = true;
    Boolean skipSosi = false;
    private StringValueResolver resolver;

    public void setImportMetadata(AnnotationMetadata importMetadata) {
        final Map<String, Object> meta = importMetadata.getAnnotationAttributes(EnableDgwsProtection.class.getName());
        if (meta.containsKey("production")) {
            production = resolveBoolean(meta.get("production"));
        }
        if (meta.containsKey("skipSOSI")) {
            skipSosi = resolveBoolean(meta.get("skipSOSI"));
        }
    }

    private boolean resolveBoolean(Object value) {
        return Boolean.parseBoolean(resolver.resolveStringValue(value.toString()));
    }

    @Bean
    public SOSISecurityInterceptor sosiSecurityInterceptor() {
        SOSISecurityInterceptor interceptor = new SOSISecurityInterceptor();
        interceptor.setProduction(production);
        interceptor.setCanSkipSosi(skipSosi);
        return interceptor;
    }

    public void setEmbeddedValueResolver(StringValueResolver resolver) {
        this.resolver = resolver;
    }
}
