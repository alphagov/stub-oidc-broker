package uk.gov.ida.stuboidcbroker.resources.oidcclient;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import io.dropwizard.views.View;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.oidcclient.AuthnRequestGeneratorService;
import uk.gov.ida.stuboidcbroker.services.oidcclient.AuthnResponseValidationService;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;
import uk.gov.ida.stuboidcbroker.services.oidcclient.TokenRequestService;
import uk.gov.ida.stuboidcbroker.views.AuthenticationCallbackViewHttp;
import uk.gov.ida.stuboidcbroker.views.AuthenticationCallbackViewHttps;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.ida.stuboidcbroker.services.shared.QueryParameterHelper.splitQuery;

//This class is an alternative to the AuthorizationRequestClientResource. Both are designed for the OpenID connect Hybrid flow. It's an example of how the client can parse the authentication response from the client using javascript. This is done in the authenticationCallbackHttp.mustache to parse the fragment of the response for the client.
//What is currently happening as an alternative to the above method, is that the OP provider is sending the response through a HTML page meaning that the client isn't required to parse the response using Javascript.
@Deprecated
@Path("/")
public class StubOidcBrokerResource {

    private final StubOidcBrokerConfiguration configuration;
    private final TokenRequestService tokenRequestService;
    private final AuthnRequestGeneratorService authnRequestGeneratorService;
    private final AuthnResponseValidationService authnResponseValidationService;
    private final RedisService redisService;
    private String brokerDomain;

    public StubOidcBrokerResource(
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
    }

    @POST
    @Path("/serviceAuthenticationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response serviceAuthenticationRequest(@FormParam("brokerDomain") String idpDomain) {
        List<String> orgList = Arrays.asList(idpDomain.split(","));
        String domain = orgList.get(0);
        String brokerName = orgList.get(1);
        this.brokerDomain = domain;
        URI requestURI = UriBuilder.fromUri(
                domain).path(Urls.StubBrokerOPProvider.AUTHORISATION_ENDPOINT_URI)
                .build();

        URI redirectURI = UriBuilder.fromUri(
                configuration.getStubBrokerURI()).path(Urls.StubBrokerClient.REDIRECT_URI)
                .build();

        return Response
                .status(302)
                .location(authnRequestGeneratorService.generateAuthenticationRequest(
                        requestURI,
                        getClientID(brokerDomain),
                        redirectURI,
                        new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN),
                        "transaction-id")
                        .toURI())
                        .build();
    }

    @GET
    @Path("/authenticationCallback")
    public View authenticationCallback() {
        if (configuration.isLocal()) {
            return new AuthenticationCallbackViewHttp();
        } else {
            return new AuthenticationCallbackViewHttps();
        }
    }

    @POST
    @Path("/validateAuthenticationResponse")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response validateAuthenticationResponse(String postBody) throws java.text.ParseException, ParseException {
        Map<String, String> authenticationParams = splitQuery(postBody);

        if (postBody.isEmpty()) {
            return Response.status(500).entity("PostBody is empty").build();
        }

        Optional<String> errors = authnResponseValidationService.checkResponseForErrors(authenticationParams);

        if (errors.isPresent()) {
            return Response.status(400).entity(errors.get()).build();
        }

        AuthorizationCode authorizationCode = authnResponseValidationService.handleAuthenticationResponse(authenticationParams, getClientID(brokerDomain));
        return Response.ok(authorizationCode.getValue()).build();
    }

    @GET
    @Path("/retrieveTokenAndUserInfo")
    @Produces(MediaType.APPLICATION_JSON)
    public Response retrieveTokenAndUserInfo(@Context UriInfo uriInfo) throws IOException, JOSEException {

            String query = uriInfo.getRequestUri().getQuery();
            Map<String, String> authenticationParams = splitQuery(query);
            String authCode = authenticationParams.get("code");

            OIDCTokens tokens = tokenRequestService.getTokens(new AuthorizationCode(authCode), getClientID(brokerDomain), brokerDomain);
            UserInfo userInfo = tokenRequestService.getUserInfo(tokens.getBearerAccessToken(), brokerDomain);

            String userInfoToJson = userInfo.toJSONObject().toJSONString();
            return Response.ok(userInfoToJson).build();
    }

    private ClientID getClientID(String brokerName) {
       String client_id = redisService.get(brokerName);
        if (client_id != null) {
            return new ClientID(client_id);
        }
        return new ClientID();
    }
}
