package uk.gov.ida.stuboidcbroker.resources.response;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import io.dropwizard.views.View;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.AuthnRequestValidationService;
import uk.gov.ida.stuboidcbroker.views.BrokerErrorResponseView;
import uk.gov.ida.stuboidcbroker.views.BrokerResponseView;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.net.URI;

@Path("/authorizeFormPost")
public class StubOidcAuthorizationResource {

    private final AuthnRequestValidationService validationService;
    private final StubOidcBrokerConfiguration configuration;

    public StubOidcAuthorizationResource(AuthnRequestValidationService validationService, StubOidcBrokerConfiguration configuration) {
        this.validationService = validationService;
        this.configuration = configuration;
    }

    //TODO: The spec states there should be a post method for this endpoint as well
    @GET
    @Path("/authorize")
    public Object authorize(@Context UriInfo uriInfo, @QueryParam("transaction-id") String transactionID) {
        URI uri = uriInfo.getRequestUri();

        try {
            AuthenticationRequest authenticationRequest = AuthenticationRequest.parse(uri);

            AuthenticationErrorResponse errorResponse = validationService.handleAuthenticationRequest(authenticationRequest, transactionID);

            if (errorResponse != null) {
                return new BrokerErrorResponseView(
                        errorResponse.getErrorObject().getCode(),
                        errorResponse.getErrorObject().getDescription(),
                        errorResponse.getErrorObject().getHTTPStatusCode(),
                        errorResponse.getState(),
                        errorResponse.getRedirectionURI(),
                        transactionID);
            }
            URI idpUri = UriBuilder.fromUri(configuration.getVerifiableCredentialURI()).path(Urls.IDP.AUTHENTICATION_URI).queryParam("transaction-id", transactionID).build();
            return Response
                    .status(302)
                    .location(idpUri)
                    .build();

        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse URI: " + uri.toString() + " to authentication request", e);
        }
    }

    @GET
    @Path("/response")
    @Produces(MediaType.TEXT_HTML)
    public View authorizeResponseHandler(@QueryParam("transaction-id") String transactionID) throws ParseException {
        AuthenticationSuccessResponse successResponse = validationService.handleAuthenticationRequestResponse(transactionID);
        return new BrokerResponseView(
                successResponse.getState(),
                successResponse.getAuthorizationCode(),
                successResponse.getIDToken(),
                successResponse.getRedirectionURI(),
                successResponse.getAccessToken(),
                transactionID);
    }
}
