package com.trifork.dgws.annotations;

import org.springframework.context.annotation.Import;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import(DgwsConfiguration.class)
public @interface EnableDgwsProtection {
    String test() default "false";
    String skipSOSI() default "false";
}
