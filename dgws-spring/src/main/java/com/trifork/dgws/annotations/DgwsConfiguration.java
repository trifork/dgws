package com.trifork.dgws.annotations;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportResource;

@Configuration
@ImportResource("classpath:/dk/trifork/dgws/dgws-protection.xml")
public class DgwsConfiguration {
}
