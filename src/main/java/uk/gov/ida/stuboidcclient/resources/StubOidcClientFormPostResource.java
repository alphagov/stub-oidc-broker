package uk.gov.ida.stuboidcclient.resources;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import uk.gov.ida.stuboidcclient.configuration.StubOidcClientConfiguration;
import uk.gov.ida.stuboidcclient.rest.Urls;
import uk.gov.ida.stuboidcclient.services.AuthnRequestService;
import uk.gov.ida.stuboidcclient.services.AuthnResponseService;
import uk.gov.ida.stuboidcclient.services.TokenService;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.util.Optional;

@Path("/formPost")
public class StubOidcClientFormPostResource {

    private static final ClientID CLIENT_ID = new ClientID("stub-oidc-client");
    private final StubOidcClientConfiguration stubClientConfiguration;
    private final TokenService tokenService;
    private final AuthnRequestService authnRequestService;
    private final AuthnResponseService authnResponseService;
    private URI authorisationURI;
    private URI redirectUri;


    public StubOidcClientFormPostResource(
            StubOidcClientConfiguration stubClientConfiguration,
            TokenService tokenService,
            AuthnRequestService authnRequestService,
            AuthnResponseService authnResponseService) {
        this.stubClientConfiguration = stubClientConfiguration;
        this.tokenService = tokenService;
        this.authnRequestService = authnRequestService;
        this.authnResponseService = authnResponseService;
        authorisationURI = UriBuilder.fromUri(stubClientConfiguration.getStubOpURI()).path(Urls.StubOp.AUTHORISATION_ENDPOINT_FORM_URI).build();
        redirectUri = UriBuilder.fromUri(stubClientConfiguration.getStubClientURI()).path(Urls.StubClient.REDIRECT_FORM_URI).build();
    }

    @GET
    @Path("/serviceAuthenticationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response formPostAuthenticationRequest() {

        return Response
                .status(302)
                .location(authnRequestService.generateFormPostAuthenticationRequest(
                        authorisationURI,
                        CLIENT_ID,
                        redirectUri,
                        new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN))
                        .toURI())
                        .build();
    }

    @GET
    @Path("/serviceAuthenticationRequestCodeIDToken")
    @Produces(MediaType.APPLICATION_JSON)
    public Response serviceAuthenticationRequestCodeIDToken() {

        return Response
                .status(302)
                .location(authnRequestService.generateFormPostAuthenticationRequest(
                        authorisationURI,
                        CLIENT_ID,
                        redirectUri,
                        new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN))
                        .toURI())
                        .build();
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

        String userInfoInJson = retrieveTokenAndUserInfo(authorizationCode);

        return Response.ok(userInfoInJson).build();
    }


    private String retrieveTokenAndUserInfo(AuthorizationCode authCode) {

            OIDCTokens tokens = tokenService.getTokens(authCode, CLIENT_ID);
            UserInfo userInfo = tokenService.getUserInfo(tokens.getBearerAccessToken());

            String userInfoToJson = userInfo.toJSONObject().toJSONString();
            return userInfoToJson;
    }
}
