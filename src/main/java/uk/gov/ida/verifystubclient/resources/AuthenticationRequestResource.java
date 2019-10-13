package uk.gov.ida.verifystubclient.resources;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import io.dropwizard.views.View;
import uk.gov.ida.verifystubclient.configuration.VerifyStubClientConfiguration;
import uk.gov.ida.verifystubclient.services.ClientService;
import uk.gov.ida.verifystubclient.views.StartPageView;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

@Path("/")
public class AuthenticationRequestResource {

    private final VerifyStubClientConfiguration stubClientConfiguration;
    private final ClientService clientService;

    public AuthenticationRequestResource(
            VerifyStubClientConfiguration stubClientConfiguration,
            ClientService clientService) {
        this.stubClientConfiguration = stubClientConfiguration;
        this.clientService = clientService;
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

        ClientID clientID = new ClientID("stub-client");

        return Response
                .status(302)
                .location(clientService.generateAuthenticationRequest(
                        stubClientConfiguration.getAuthorisationEndpointURI(),
                        clientID,
                        stubClientConfiguration.getRedirectURI()).toURI())
                        .build();
    }

    @GET
    @Path("/authenticationCallback")
    @Produces(MediaType.APPLICATION_JSON)
    public Response authenticationCallback(@Context UriInfo uriInfo) {

        try {
            AuthenticationResponse authenticationResponse = AuthenticationResponseParser.parse(uriInfo.getRequestUri());
            AuthorizationCode authorizationCode = authenticationResponse.toSuccessResponse().getAuthorizationCode();
            UserInfo userInfo = getClaims(authorizationCode);

            return Response.ok(userInfo).build();
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private UserInfo getClaims(AuthorizationCode authorizationCode) {
        //Gets the ID token and Access token from the OpenID Provider
        OIDCTokens tokens = clientService.getTokens(authorizationCode);

        //Get the user info from the OpenID Provider using the Access Token/Bearer Token
        UserInfo userInfo = clientService.getUserInfo(tokens.getBearerAccessToken());


        return userInfo;
    }

}
