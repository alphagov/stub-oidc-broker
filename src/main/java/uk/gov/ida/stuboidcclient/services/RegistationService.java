package uk.gov.ida.stuboidcclient.services;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.text.ParseException;

public class RegistationService {

    private static final Logger LOG = LoggerFactory.getLogger(RegistationService.class);

    public String sendRegistationRequest(String ssa, String privateKey) throws com.nimbusds.oauth2.sdk.ParseException, JOSEException {
        SignedJWT signedJWT;
        try {
           signedJWT = SignedJWT.parse(ssa);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
        HTTPResponse httpResponse = sendClientRegRequest(signedJWT);
        LOG.info("HTTP RESPONSE AS STRING: " + httpResponse.getContentAsJSONObject().toJSONString());
        return httpResponse.getContentAsJSONObject().toJSONString();
    }


    private HTTPResponse sendClientRegRequest(SignedJWT jwt) {
        URI uri = UriBuilder.fromUri("http://localhost:5510").path("/register").build();
        OIDCClientRegistrationRequest registrationRequest = new OIDCClientRegistrationRequest(
                uri,
                getClientMetadata(),
                jwt,
                null
        );
        try {
            HTTPResponse response = registrationRequest.toHTTPRequest().send();
            return response;
        } catch (IOException e) {
            throw new RuntimeException("Unable to send HTTP Request", e);
        }
    }

    private OIDCClientMetadata getClientMetadata() {
        OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
        clientMetadata.setName("This is some name");
        //TODO - Confirm what we need to set
//        clientMetadata.setApplicationType();
//        clientMetadata.setRedirectionURIs();
//        clientMetadata.setLogoURI();
//        clientMetadata.setSubjectType();
//        clientMetadata.setSectorIDURI();
//        clientMetadata.setTokenEndpointAuthMethod();
//        clientMetadata.setJWKSetURI();
//        clientMetadata.setScope();
//        clientMetadata.setGrantTypes();
//        clientMetadata.setResponseTypes();
//        clientMetadata.setIDTokenJWSAlg();
//        clientMetadata.setRequestObjectJWSAlg();
//        clientMetadata.setSoftwareID();

        return  clientMetadata;
    }
}
