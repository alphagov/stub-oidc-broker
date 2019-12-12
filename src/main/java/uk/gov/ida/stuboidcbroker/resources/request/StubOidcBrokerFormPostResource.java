package uk.gov.ida.stuboidcbroker.resources.request;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import io.dropwizard.views.View;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.AuthnRequestGeneratorService;
import uk.gov.ida.stuboidcbroker.services.AuthnResponseValidationService;
import uk.gov.ida.stuboidcbroker.services.RedisService;
import uk.gov.ida.stuboidcbroker.services.TokenRequestService;
import uk.gov.ida.stuboidcbroker.views.RPResponseView;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Path("/formPost")
public class StubOidcBrokerFormPostResource {

    private static final Logger LOG = LoggerFactory.getLogger(StubOidcBrokerFormPostResource.class);

    private final TokenRequestService tokenRequestService;
    private final AuthnRequestGeneratorService authnRequestGeneratorService;
    private final AuthnResponseValidationService authnResponseValidationService;
    private final StubOidcBrokerConfiguration configuration;
    private final RedisService redisService;
    private URI authorisationURI;
    private URI redirectUri;
    private String brokerDomain;
    private String brokerName;


    public StubOidcBrokerFormPostResource(
            StubOidcBrokerConfiguration configuration,
            TokenRequestService tokenRequestService,
            AuthnRequestGeneratorService authnRequestGeneratorService,
            AuthnResponseValidationService authnResponseValidationService,
            RedisService redisService) {
        this.configuration = configuration;
        this.tokenRequestService = tokenRequestService;
        this.authnRequestGeneratorService = authnRequestGeneratorService;
        this.authnResponseValidationService = authnResponseValidationService;
        this.redisService = redisService;
        redirectUri = UriBuilder.fromUri(configuration.getStubBrokerURI()).path(Urls.StubBroker.REDIRECT_FORM_URI).build();
    }

    @POST
    @Path("/serviceAuthenticationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response formPostAuthenticationRequest(@FormParam("brokerDomain") String domain) {
        List<String> orgList = Arrays.asList(domain.split(","));
        String brokerDomain = orgList.get(0);
        String brokerName = orgList.get(1);
        this.brokerDomain = brokerDomain;
        this.brokerName = brokerName;
        authorisationURI = UriBuilder.fromUri(brokerDomain).path(Urls.StubOp.AUTHORISATION_ENDPOINT_FORM_URI).build();
        return Response
                .status(302)
                .location(authnRequestGeneratorService.generateFormPostAuthenticationRequest(
                        authorisationURI,
                        getClientID(brokerName),
                        redirectUri,
                        new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN),
                        brokerName)
                        .toURI())
                        .build();
    }

    @POST
    @Path("/idpAuthenticationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response sendIdpAuthenticationRequest(@FormParam("idpDomain") String domain) {
        List<String> orgList = Arrays.asList(domain.split(","));
        String idpDomain = orgList.get(0);
        String idpName = orgList.get(1);

        String transactionId = new ClientID().toString();

        URI idpUri = UriBuilder.fromUri(idpDomain).path("/request").queryParam("transaction-id", transactionId).build();

        storeTransactionID(transactionId, idpUri.toString());

        return Response
                .status(302)
                .location(idpUri)
                .build();
    }

    @POST
    @Path("/response/POST")
    @Produces(MediaType.APPLICATION_JSON)
    public View handAuthenticationResponse() throws URISyntaxException {

        String rpUri = redisService.get("");

        return new RPResponseView(new URI(rpUri), "Success", Integer.toString(HttpStatus.SC_OK));
    }

    @GET
    @Path("/serviceAuthenticationRequestCodeIDToken")
    @Produces(MediaType.APPLICATION_JSON)
    public Response serviceAuthenticationRequestCodeIDToken() {
        return Response
                .status(302)
                .location(authnRequestGeneratorService.generateFormPostAuthenticationRequest(
                        authorisationURI,
                        getClientID(brokerName),
                        redirectUri,
                        new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN),
                        "idp-name")
                        .toURI())
                        .build();
    }

    @POST
    @Path("/validateAuthenticationResponse")
    @Produces(MediaType.TEXT_HTML)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public View validateAuthenticationResponse(String postBody) throws IOException, java.text.ParseException, ParseException, URISyntaxException {

        URI rpUri = UriBuilder.fromUri(configuration.getStubTrustframeworkRP()).path(Urls.RP.AUTHORISATION_ENDPOINT_URI).build();

        if (postBody == null || postBody.isEmpty()) {
            return new RPResponseView(rpUri, "Post Body is empty", Integer.toString(HttpStatus.SC_BAD_REQUEST));
        }

        Optional<String> errors = authnResponseValidationService.checkResponseForErrors(postBody);

        if (errors.isPresent()) {
            return new RPResponseView(rpUri, "Errors in Response: " + errors.get(), Integer.toString(HttpStatus.SC_BAD_REQUEST));
        }

        AuthorizationCode authorizationCode = authnResponseValidationService.handleAuthenticationResponse(postBody, getClientID(brokerName));

        String userInfoInJson = retrieveTokenAndUserInfo(authorizationCode);

        return new RPResponseView(rpUri, userInfoInJson, Integer.toString(HttpStatus.SC_OK));
    }


    private String retrieveTokenAndUserInfo(AuthorizationCode authCode) {

            OIDCTokens tokens = tokenRequestService.getTokens(authCode, getClientID(brokerName), brokerDomain);

            String verifiableCredential = tokenRequestService.getVerifiableCredential(tokens.getBearerAccessToken(), brokerDomain);
//            UserInfo userInfo = tokenService.getUserInfo(tokens.getBearerAccessToken());

//            String userInfoToJson = userInfo.toJSONObject().toJSONString();
            return verifiableCredential;
    }

    private void storeTransactionID(String transactionID, String rpResponsePath) {

        redisService.set(transactionID, rpResponsePath);
    }

    private ClientID getClientID(String brokerName) {
        String client_id = redisService.get(brokerName);
        if (client_id != null) {
            return new ClientID(client_id);
        }
        return new ClientID();
    }
}
