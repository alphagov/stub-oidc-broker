package uk.gov.ida.stuboidcbroker.services.oidcprovider;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.client.ClientInformation;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.id.ClientID;
import net.minidev.json.JSONObject;
import org.glassfish.jersey.internal.util.Base64;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;

import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Date;

public class RegistrationHandlerService {

    private final RedisService redisService;
    private final StubOidcBrokerConfiguration configuration;

    public RegistrationHandlerService(RedisService redisService, StubOidcBrokerConfiguration configuration) {
        this.redisService = redisService;
        this.configuration = configuration;
    }

    private final HttpClient httpClient = HttpClient.newBuilder()
            .build();

    public String processHTTPRequest(SignedJWT signedJWT) throws ParseException {
        boolean passedValidation;
        SignedJWT softwareStatement = SignedJWT.parse(signedJWT.getJWTClaimsSet().getClaim("software_statement").toString());

        try {
            passedValidation = validateRegistrationRequest(signedJWT, softwareStatement);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }

        if (passedValidation) {
            return generateClientInformationResponse(signedJWT, softwareStatement).toJSONString();
        } else {
            return "Failed Validation";
        }
    }

    private boolean validateRegistrationRequest(SignedJWT signedJWT, SignedJWT softwareStatement) throws ParseException {
        String softwareJwksEndpoint = softwareStatement.getJWTClaimsSet().getClaim("software_jwks_endpoint").toString();

        URI ssaURI = UriBuilder.fromUri(configuration.getDirectoryURI()).path("directory/" + softwareStatement.getJWTClaimsSet().getClaim("software_client_id") + "/key").build();
        URI softwareURI = UriBuilder.fromUri(softwareJwksEndpoint).build();

        PublicKey ssaPublicKey = getPublicKeyFromDirectoryForSSA(ssaURI);
        PublicKey jwtPublicKey = getPublicKeyFromDirectoryForRequest(softwareURI);

        boolean passedSSASignatureValidation = validateJWTSignatureAndAlgorithm(ssaPublicKey, softwareStatement);
        boolean passedJWTSignatureValidation = validateJWTSignatureAndAlgorithm(jwtPublicKey, signedJWT);


       return passedJWTSignatureValidation && passedSSASignatureValidation;
    }

    private PublicKey getPublicKeyFromDirectoryForRequest(URI directoryEndpoint) throws ParseException {
        HttpResponse<String> response = sendHttpRequest(directoryEndpoint);

        String responseString = response.body();

        JSONObject jsonResponse = JSONObjectUtils.parse(responseString);
        responseString = jsonResponse.get("signing").toString();

        responseString = responseString.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");
        byte[] encodedPublicKey = Base64.decode(responseString.getBytes());

        try {
            X509EncodedKeySpec x509publicKey = new X509EncodedKeySpec(encodedPublicKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(x509publicKey);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private PublicKey getPublicKeyFromDirectoryForSSA(URI directoryEndpoint) {
        HttpResponse<String> response = sendHttpRequest(directoryEndpoint);

        String publicKeyString = response.body();
        publicKeyString = publicKeyString.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");
        byte[] encodedPublicKey = Base64.decode(publicKeyString.getBytes());

        try {
            X509EncodedKeySpec x509publicKey = new X509EncodedKeySpec(encodedPublicKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(x509publicKey);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private boolean validateJWTSignatureAndAlgorithm(PublicKey publicKey, SignedJWT signedJWT) {
        JWSAlgorithm algorithm1 = signedJWT.getHeader().getAlgorithm();

        if (!algorithm1.equals(JWSAlgorithm.RS256)) {
            throw new RuntimeException("Wrong algorithm");
        }

        RSASSAVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
        boolean isVerified;

        try {
             isVerified = signedJWT.verify(verifier);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        return isVerified;
    }

    private HttpResponse<String> sendHttpRequest(URI uri) {
        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .uri(uri)
                .build();

        try {
            return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private JSONObject generateClientInformationResponse(SignedJWT signedJWT, SignedJWT softwareStatement) throws ParseException {
        ClientMetadata clientMetadata;
         String url = softwareStatement.getJWTClaimsSet().getClaim("software_jwks_endpoint").toString();
        try {
            JSONObject responseJson = signedJWT.getJWTClaimsSet().toJSONObject();
            responseJson.remove("software_statement");
             clientMetadata = ClientMetadata.parse(responseJson);
        } catch (com.nimbusds.oauth2.sdk.ParseException| ParseException e) {
            throw new RuntimeException(e);
        }
        ClientID clientID = new ClientID();
        persistClientID(clientID, url);
        ClientInformation clientInformation = new ClientInformation(clientID, new Date(), clientMetadata, null);

        return clientInformation.toJSONObject();
    }

    private void persistClientID(ClientID clientID, String url) {
        String clientIdString = clientID.toString();
        redisService.set(clientIdString, url);
    }
}
