package uk.gov.ida.stuboidcbroker.services.oidcclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.rp.ApplicationType;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.domain.Organisation;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.shared.PKIService;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;

import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PrivateKey;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;

public class RegistrationRequestService {

    private final RedisService redisService;
    private final StubOidcBrokerConfiguration configuration;
    private final PKIService pkiService;

    public RegistrationRequestService(RedisService redisService, StubOidcBrokerConfiguration configuration, PKIService pkiService) {
        this.redisService = redisService;
        this.configuration = configuration;
        this.pkiService = pkiService;
    }

    public String sendRegistrationRequest(String ssa, String privateKey, String brokerDomain, String brokerName, String clientToken) {
        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(ssa);
        } catch (ParseException e) {
            return "Unable to parse SSA:\n\n " + e;
        }
        String httpResponse = sendHttpRegistrationRequest(signedJWT, privateKey, brokerDomain, clientToken);
        String processedHttpResponse = processHttpRegistrationResponse(httpResponse, brokerName);

        return processedHttpResponse;
    }

    public List<Organisation> getListOfBrokersFromResponse(HttpResponse<String> responseBody) {
        JSONParser parser = new JSONParser(JSONParser.MODE_JSON_SIMPLE);
        JSONArray jsonarray;
        try {
            jsonarray = (JSONArray) parser.parse(responseBody.body());
        } catch (net.minidev.json.parser.ParseException e) {
            throw new RuntimeException(e);
        }

        List<Organisation> orgList = jsonarray
                .stream()
                .map(this::createOrganisationObject)
                .collect(Collectors.toList());

        return orgList;
    }

    public HttpResponse<String> getRegisteredBrokersFromDirectory(URI uri) {
        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .uri(uri)
                .build();

        try {
            return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    public String sendHttpRegistrationRequest(SignedJWT jwt, String privateKeyString, String brokerDomain, String clientToken) {
        URI uri = UriBuilder.fromUri(brokerDomain).path(Urls.StubBrokerOPProvider.REGISTER_URI).build();
        JWTClaimsSet registrationRequest = getRegistrationClaims(jwt.serialize(), brokerDomain);
        PrivateKey privateKey = pkiService.convertStringToPrivateKey(privateKeyString);
        SignedJWT signedClientMetadata = generateSignedJWT(registrationRequest, privateKey);

        HttpResponse<String> httpResponse = sendHttpRequest(uri, signedClientMetadata.serialize(), brokerDomain, clientToken);

        return httpResponse.body();
    }

    private Organisation createOrganisationObject(Object obj) {
        JSONObject jsonObj = (JSONObject) obj;
        ObjectMapper objectMapper = new ObjectMapper();
        Organisation org;
        try {
            org = objectMapper.readValue(jsonObj.toJSONString(), Organisation.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return org;
    }

    private JWTClaimsSet getRegistrationClaims(String seralizedSoftwareStatement, String brokerDomain) {
        JWTClaimsSet registrationClaims = new JWTClaimsSet.Builder()
        .issuer(configuration.getSoftwareID())
        .issueTime(new Date())
        .expirationTime(new Date())
        .audience(brokerDomain)
        .jwtID(UUID.randomUUID().toString())
        .claim("redirect_uris", singletonList(UriBuilder.fromUri(configuration.getStubBrokerURI()).path(Urls.StubBrokerClient.REDIRECT_URI).build().toString()))
        .claim("token_endpoint_auth_method", "tls_client_auth")
        .claim("tls_client_auth_subject_dn", "This MUST contain the Distinguished name (DN) of the certificate that the Client will present to the OP token endpoint.")
        .claim("grant_types", singletonList("hybrid"))
        .claim("response_types", asList("code id_token", "code id_token token"))
        .claim("application_type", ApplicationType.WEB)
        .claim("id_token_signed_response_alg", JWSAlgorithm.RS256)
        .claim("request_object_signing_alg", JWSAlgorithm.RS256)
        .claim("software_statement", seralizedSoftwareStatement)
        .build();

        return registrationClaims;
    }

    private SignedJWT generateSignedJWT(JWTClaimsSet registrationRequestClaims, PrivateKey privateKey) {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).build();

        JWSSigner signer = new RSASSASigner(privateKey);
        SignedJWT signedJWT = new SignedJWT(header, registrationRequestClaims);
        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        return signedJWT;
    }

    private HttpResponse<String> sendHttpRequest(URI uri, String postObject, String brokerDomain, String clientToken) {
        JSONObject jwtJson = new JSONObject();
        jwtJson.put("signed-jwt", postObject);
        jwtJson.put("destination-url", brokerDomain);

        HttpRequest request = HttpRequest.newBuilder()
                .header("Content-Type", "application/json")
                .header("Authorization", clientToken)
                .POST(HttpRequest.BodyPublishers.ofString(jwtJson.toJSONString()))
                .uri(uri)
                .build();

        try {
            return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException("This could be 1 out of 2 exceptions. Take your pick", e);
        }
    }

    private String processHttpRegistrationResponse(String httpResponse, String brokerName) {
        if (httpResponse.equals("Failed Validation")) {
            return httpResponse;
        }

        JSONObject jsonObjectResponse;
        try {
            jsonObjectResponse = JSONObjectUtils.parse(httpResponse);
        } catch (ParseException e) {
            return "Unable to parse registration response:\n\n " + httpResponse;
        }

        if (jsonObjectResponse.get("client_id") != null) {
            saveClientID(brokerName, jsonObjectResponse.get("client_id").toString());
        }

        return httpResponse;
    }

    private void saveClientID(String brokerName, String clientID) {
        redisService.set(brokerName, clientID);
    }
}

