package uk.gov.ida.verifystubclient.resources;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import uk.gov.ida.verifystubclient.configuration.VerifyStubClientConfiguration;
import uk.gov.ida.verifystubclient.services.AuthnRequestService;
import uk.gov.ida.verifystubclient.services.AuthnResponseService;
import uk.gov.ida.verifystubclient.services.TokenService;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;

@Path("/formPost")
public class StubClientFormPostResource {

    private static final ClientID CLIENT_ID = new ClientID("verify-stub-client");
    private final VerifyStubClientConfiguration stubClientConfiguration;
    private final TokenService tokenService;
    private final AuthnRequestService authnRequestService;
    private final AuthnResponseService authnResponseService;

    public StubClientFormPostResource(
            VerifyStubClientConfiguration stubClientConfiguration,
            TokenService tokenService,
            AuthnRequestService authnRequestService,
            AuthnResponseService authnResponseService) {
        this.stubClientConfiguration = stubClientConfiguration;
        this.tokenService = tokenService;
        this.authnRequestService = authnRequestService;
        this.authnResponseService = authnResponseService;
    }

    @GET
    @Path("/serviceAuthenticationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response formPostAuthenticationRequest() {

        return Response
                .status(302)
                .location(authnRequestService.generateFormPostAuthenticationRequest(
                        stubClientConfiguration.getAuthorisationEndpointFormPostURI(),
                        CLIENT_ID,
                        stubClientConfiguration.getRedirectFormPostURI(),
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
                        stubClientConfiguration.getAuthorisationEndpointFormPostURI(),
                        CLIENT_ID,
                        stubClientConfiguration.getRedirectFormPostURI(),
                        new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN))
                        .toURI())
                        .build();
    }

    @POST
    @Path("/validateAuthenticationResponse")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response validateAuthenticationResponse(String postBody) throws IOException, java.text.ParseException, ParseException {
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
