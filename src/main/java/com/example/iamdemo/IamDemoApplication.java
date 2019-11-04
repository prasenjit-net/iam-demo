package com.example.iamdemo;

import net.prasenjit.crypto.store.CryptoKeyFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.security.cert.X509Certificate;

@RestController
@SpringBootApplication
public class IamDemoApplication extends WebSecurityConfigurerAdapter {

    public static void main(String[] args) {
        SpringApplication.run(IamDemoApplication.class, args);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/saml2/service-provider-metadata/**")
                .permitAll()
                .anyRequest().authenticated()
                .and()
                .saml2Login();
    }

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {

        CryptoKeyFactory factory = CryptoKeyFactory.builder()
                .locationStr("classpath:keystore.jks")
                .type("JKS")
                .build();
        //SAML configuration
        //Mapping this application to one or more Identity Providers
        RelyingPartyRegistration reg = RelyingPartyRegistration.withRegistrationId("test-saml")
                .idpWebSsoUrl("https://wso2is.prasenjit.net/samlsso")
                .remoteIdpEntityId("wso2is.prasenjit.net")
                .assertionConsumerServiceUrlTemplate("{baseUrl}/login/saml2/sso/{registrationId}")
                .credentials(col -> {
                    col.add(new Saml2X509Credential(factory.getPrivateKey("test-saml", "changeit".toCharArray()),
                            (X509Certificate) factory.getCertificate("test-saml"),
                            Saml2X509Credential.Saml2X509CredentialType.SIGNING));
                    col.add(new Saml2X509Credential((X509Certificate) factory.getCertificate("wso2is.prasenjit.net"),
                            Saml2X509Credential.Saml2X509CredentialType.VERIFICATION));
                })
                .build();
        return new InMemoryRelyingPartyRegistrationRepository(reg);
    }

    @RequestMapping("/")
    public Principal home(Principal principal) {
        return principal;
    }
}
