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
    private String domain;
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
    public Response formPostAuthenticationRequest(@FormParam("idpDomain") String idpDomain) {
        List<String> orgList = Arrays.asList(idpDomain.split(","));
        String domain = orgList.get(0);
        String brokerName = orgList.get(1);
        this.domain = domain;
        this.brokerName = brokerName;
        authorisationURI = UriBuilder.fromUri(domain).path(Urls.StubOp.AUTHORISATION_ENDPOINT_FORM_URI).build();
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
        if (postBody == null || postBody.isEmpty()) {
            return new RPResponseView(new URI(configuration.getStubTrustframeworkRP()), "Post Body is empty", Integer.toString(HttpStatus.SC_BAD_REQUEST));
        }

        Optional<String> errors = authnResponseValidationService.checkResponseForErrors(postBody);

        if (errors.isPresent()) {
            return new RPResponseView(new URI(configuration.getStubTrustframeworkRP()), "Errors in Response: " + errors.get(), Integer.toString(HttpStatus.SC_BAD_REQUEST));
        }

        AuthorizationCode authorizationCode = authnResponseValidationService.handleAuthenticationResponse(postBody, getClientID(brokerName));

        String userInfoInJson = retrieveTokenAndUserInfo(authorizationCode);

        return new RPResponseView(new URI(configuration.getStubTrustframeworkRP()), userInfoInJson, Integer.toString(HttpStatus.SC_OK));
    }


    private String retrieveTokenAndUserInfo(AuthorizationCode authCode) {

            OIDCTokens tokens = tokenRequestService.getTokens(authCode, getClientID(brokerName), domain);

            String verifiableCredential = tokenRequestService.getVerifiableCredential(tokens.getBearerAccessToken(), domain);
//            UserInfo userInfo = tokenService.getUserInfo(tokens.getBearerAccessToken());

//            String userInfoToJson = userInfo.toJSONObject().toJSONString();
            return verifiableCredential;
    }

    private ClientID getClientID(String brokerName) {
        String client_id = redisService.get(brokerName);
        if (client_id != null) {
            return new ClientID(client_id);
        }
        return new ClientID();
    }
}
