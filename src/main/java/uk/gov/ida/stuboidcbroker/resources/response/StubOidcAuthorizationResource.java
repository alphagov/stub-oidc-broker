package uk.gov.ida.stuboidcbroker.resources.response;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import io.dropwizard.views.View;
import uk.gov.ida.stuboidcbroker.services.AuthnRequestValidationService;
import uk.gov.ida.stuboidcbroker.views.BrokerErrorResponseView;
import uk.gov.ida.stuboidcbroker.views.BrokerResponseView;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriInfo;
import java.net.URI;

@Path("/authorizeFormPost")
public class StubOidcAuthorizationResource {

    private final AuthnRequestValidationService validationService;

    public StubOidcAuthorizationResource(AuthnRequestValidationService validationService) {
        this.validationService = validationService;
    }

    //TODO: The spec states there should be a post method for this endpoint as well
    @GET
    @Path("/authorize")
    @Produces(MediaType.TEXT_HTML)
    public View authorize(@Context UriInfo uriInfo) {
        URI uri = uriInfo.getRequestUri();

        try {
            AuthenticationRequest authenticationRequest = AuthenticationRequest.parse(uri);

            AuthenticationResponse response = validationService.handleAuthenticationRequest(authenticationRequest);

            if (!response.indicatesSuccess()) {
                AuthenticationErrorResponse errorResponse = response.toErrorResponse();
                return new BrokerErrorResponseView(
                        errorResponse.getErrorObject().getCode(),
                        errorResponse.getErrorObject().getDescription(),
                        errorResponse.getErrorObject().getHTTPStatusCode(),
                        errorResponse.getState(),
                        errorResponse.getRedirectionURI());
            } else {
                AuthenticationSuccessResponse successResponse = response.toSuccessResponse();
                return new BrokerResponseView(
                        authenticationRequest.getState(),
                        successResponse.getAuthorizationCode(),
                        successResponse.getIDToken(),
                        authenticationRequest.getRedirectionURI(),
                        successResponse.getAccessToken());
            }

        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse URI: " + uri.toString() + " to authentication request", e);
        }
    }
}
