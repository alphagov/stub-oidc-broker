package uk.gov.ida.stuboidcbroker.resources.request;

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
import uk.gov.ida.stuboidcbroker.services.AuthnRequestGeneratorService;
import uk.gov.ida.stuboidcbroker.services.RedisService;
import uk.gov.ida.stuboidcbroker.services.TokenRequestService;
import uk.gov.ida.stuboidcbroker.services.AuthnResponseValidationService;
import uk.gov.ida.stuboidcbroker.views.AuthenticationCallbackViewHttp;
import uk.gov.ida.stuboidcbroker.views.AuthenticationCallbackViewHttps;
import uk.gov.ida.stuboidcbroker.views.StartPageView;

import javax.ws.rs.Consumes;
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
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.Map;
import java.util.Optional;

import static uk.gov.ida.stuboidcbroker.services.QueryParameterHelper.splitQuery;

@Path("/")
public class StubOidcBrokerResource {

    private final StubOidcBrokerConfiguration configuration;
    private final TokenRequestService tokenRequestService;
    private final AuthnRequestGeneratorService authnRequestGeneratorService;
    private final AuthnResponseValidationService authnResponseValidationService;
    private final RedisService redisService;

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

    @GET
    @Path("/")
    public View startPage() {
        return new StartPageView();
    }

    @GET
    @Path("/serviceAuthenticationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response serviceAuthenticationRequest() {
        URI requestURI = UriBuilder.fromUri(
                configuration.getStubOpURI()).path(Urls.StubOp.AUTHORISATION_ENDPOINT_URI)
                .build();

        URI redirectURI = UriBuilder.fromUri(
                configuration.getStubBrokerURI()).path(Urls.StubBroker.REDIRECT_URI)
                .build();

        return Response
                .status(302)
                .location(authnRequestGeneratorService.generateAuthenticationRequest(
                        requestURI,
                        getClientID(),
                        redirectURI,
                        new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN))
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
    public Response validateAuthenticationResponse(String postBody) throws IOException, java.text.ParseException, ParseException {
        if (postBody == null || postBody.isEmpty()) {
            return Response.status(500).entity("PostBody is empty").build();
        }

        Optional<String> errors = authnResponseValidationService.checkResponseForErrors(postBody);

        if (errors.isPresent()) {
            return Response.status(400).entity(errors.get()).build();
        }

        AuthorizationCode authorizationCode = authnResponseValidationService.handleAuthenticationResponse(postBody, getClientID());
        return Response.ok(authorizationCode.getValue()).build();
    }

    @GET
    @Path("/retrieveTokenAndUserInfo")
    @Produces(MediaType.APPLICATION_JSON)
    public Response retrieveTokenAndUserInfo(@Context UriInfo uriInfo) throws UnsupportedEncodingException {

            String query = uriInfo.getRequestUri().getQuery();
            Map<String, String> authenticationParams = splitQuery(query);
            String authCode = authenticationParams.get("code");

            OIDCTokens tokens = tokenRequestService.getTokens(new AuthorizationCode(authCode), getClientID());
            UserInfo userInfo = tokenRequestService.getUserInfo(tokens.getBearerAccessToken());

            String userInfoToJson = userInfo.toJSONObject().toJSONString();
            return Response.ok(userInfoToJson).build();
    }

    private ClientID getClientID() {
       String client_id = redisService.get("CLIENT_ID");
        if (client_id != null) {
            return new ClientID(client_id);
        }
        return new ClientID();
    }
}
