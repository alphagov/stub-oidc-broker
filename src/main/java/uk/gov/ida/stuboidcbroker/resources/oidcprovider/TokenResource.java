package uk.gov.ida.stuboidcbroker.resources.oidcprovider;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientCredentialsSelector;
import com.nimbusds.oauth2.sdk.auth.verifier.Context;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import net.minidev.json.JSONObject;
import org.glassfish.jersey.internal.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.services.oidcprovider.TokenHandlerService;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Path("/")
public class TokenResource {

    private final TokenHandlerService tokenHandlerService;
    private final StubOidcBrokerConfiguration configuration;
    private static final Logger LOG = LoggerFactory.getLogger(TokenResource.class);

    public TokenResource(TokenHandlerService tokenHandlerService, StubOidcBrokerConfiguration configuration) {
        this.tokenHandlerService = tokenHandlerService;
        this.configuration = configuration;
    }

    private final HttpClient httpClient = HttpClient.newBuilder()
            .build();

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/token")
    public Response getProviderTokens(
            MultivaluedMap<String, String> formParams) throws ParseException, JOSEException, InvalidClientException {
        LOG.info("Token end point");

        if (formParams.get("client_assertion") == null) {
            return Response.status(Response.Status.FORBIDDEN).build();
        }
            PrivateKeyJWT privateKeyJWT = PrivateKeyJWT.parse(formParams);

            ClientCredentialsSelector<ClientMetadata> clientCredentialsSelector = new ClientCredentialsSelector<>() {
                @Override
                public List<Secret> selectClientSecrets(ClientID claimedClientID, ClientAuthenticationMethod authMethod, Context<ClientMetadata> context) {
                    return null;
                }

                @Override
                public List<? extends PublicKey> selectPublicKeys(ClientID claimedClientID, ClientAuthenticationMethod authMethod, JWSHeader jwsHeader, boolean forceRefresh, Context<ClientMetadata> context) {
                    String clientID = privateKeyJWT.getClientID().toString();
                    URI uri = UriBuilder.fromUri(tokenHandlerService.getCertificateUrl(clientID)).build();

                    try {
                        return Collections.singletonList(getPublicKeyFromDirectory(uri));
                    } catch (java.text.ParseException e) {
                        throw new RuntimeException(e);
                    }
                }
            };

            ClientAuthenticationVerifier authenticationVerifier = new ClientAuthenticationVerifier(clientCredentialsSelector, Collections.singleton(new Audience(configuration.getStubBrokerURI() + "/token")));
            authenticationVerifier.verify(privateKeyJWT, null, null);

        Optional<String> authCodeString = formParams.get("code").stream().findFirst();
        AuthorizationCode authCode = new AuthorizationCode(authCodeString.orElseThrow(() -> new RuntimeException("AuthorizationCode is null at token endpoint")));

        OIDCTokenResponse response = new OIDCTokenResponse(tokenHandlerService.getTokens(authCode));

        return Response.ok(response.toJSONObject()).build();
    }

    private PublicKey getPublicKeyFromDirectory(URI directoryEndpoint) throws java.text.ParseException {
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
}
