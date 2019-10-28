package uk.gov.ida.stuboidcclient.resources;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import io.dropwizard.views.View;
import uk.gov.ida.stuboidcclient.configuration.StubOidcClientConfiguration;
import uk.gov.ida.stuboidcclient.rest.Urls;
import uk.gov.ida.stuboidcclient.services.AuthnRequestService;
import uk.gov.ida.stuboidcclient.services.TokenService;
import uk.gov.ida.stuboidcclient.services.AuthnResponseService;
import uk.gov.ida.stuboidcclient.views.AuthenticationCallbackView;
import uk.gov.ida.stuboidcclient.views.StartPageView;

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

import static uk.gov.ida.stuboidcclient.services.QueryParameterHelper.splitQuery;

@Path("/")
public class StubOidcClientResource {

    private static final ClientID CLIENT_ID = new ClientID("stub-oidc-client");
    private final StubOidcClientConfiguration stubClientConfiguration;
    private final TokenService tokenService;
    private final AuthnRequestService authnRequestService;
    private final AuthnResponseService authnResponseService;

    public StubOidcClientResource(
            StubOidcClientConfiguration stubClientConfiguration,
            TokenService tokenService,
            AuthnRequestService authnRequestService,
            AuthnResponseService authnResponseService) {
        this.stubClientConfiguration = stubClientConfiguration;
        this.tokenService = tokenService;
        this.authnRequestService = authnRequestService;
        this.authnResponseService = authnResponseService;
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
                stubClientConfiguration.getStubOpURI()).path(Urls.StubOp.AUTHORISATION_ENDPOINT_URI)
                .build();

        URI redirectURI = UriBuilder.fromUri(
                stubClientConfiguration.getStubClientURI()).path(Urls.StubClient.REDIRECT_URI)
                .build();

        return Response
                .status(302)
                .location(authnRequestService.generateAuthenticationRequest(
                        requestURI,
                        CLIENT_ID,
                        redirectURI,
                        new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN))
                        .toURI())
                        .build();
    }

    @GET
    @Path("/authenticationCallback")
    public View authenticationCallback() {
        return new AuthenticationCallbackView();
    }

    @POST
    @Path("/validateAuthenticationResponse")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response validateAuthenticationResponse(String postBody) throws IOException, java.text.ParseException, ParseException {
        if (postBody == null || postBody.isEmpty()) {
            return Response.status(500).entity("PostBody is empty").build();
        }

        Optional<String> errors = authnResponseService.checkResponseForErrors(postBody);

        if (errors.isPresent()) {
            return Response.status(400).entity(errors.get()).build();
        }

        AuthorizationCode authorizationCode = authnResponseService.handleAuthenticationResponse(postBody, CLIENT_ID);
        return Response.ok(authorizationCode.getValue()).build();
    }

    @GET
    @Path("/retrieveTokenAndUserInfo")
    @Produces(MediaType.APPLICATION_JSON)
    public Response retrieveTokenAndUserInfo(@Context UriInfo uriInfo) throws UnsupportedEncodingException {

            String query = uriInfo.getRequestUri().getQuery();
            Map<String, String> authenticationParams = splitQuery(query);
            String authCode = authenticationParams.get("code");

            OIDCTokens tokens = tokenService.getTokens(new AuthorizationCode(authCode), CLIENT_ID);
            UserInfo userInfo = tokenService.getUserInfo(tokens.getBearerAccessToken());

            String userInfoToJson = userInfo.toJSONObject().toJSONString();
            return Response.ok(userInfoToJson).build();
    }
}
