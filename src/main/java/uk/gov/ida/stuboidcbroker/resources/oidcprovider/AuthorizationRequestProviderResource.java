package uk.gov.ida.stuboidcbroker.resources.oidcprovider;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.AuthnRequestValidationService;
import uk.gov.ida.stuboidcbroker.views.BrokerErrorResponseView;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.Optional;

@Path("/authorizeFormPost")
public class AuthorizationRequestProviderResource {

    private final AuthnRequestValidationService validationService;
    private final StubOidcBrokerConfiguration configuration;

    public AuthorizationRequestProviderResource(AuthnRequestValidationService validationService, StubOidcBrokerConfiguration configuration) {
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

            Optional<AuthenticationErrorResponse> errorResponse = validationService.handleAuthenticationRequest(authenticationRequest, transactionID);

            if (errorResponse.isPresent()) {
                return new BrokerErrorResponseView(
                        errorResponse.get().getErrorObject().getCode(),
                        errorResponse.get().getErrorObject().getDescription(),
                        errorResponse.get().getErrorObject().getHTTPStatusCode(),
                        errorResponse.get().getState(),
                        errorResponse.get().getRedirectionURI(),
                        transactionID);
            }
            URI idpUri = UriBuilder.fromUri(
                    configuration.getIdpURI())
                    .path(Urls.IDP.AUTHENTICATION_URI)
                    .queryParam("transaction-id", transactionID)
                    .queryParam("redirect-path", Urls.StubBrokerClient.RESPONSE_FOR_BROKER)
                    .build();

            return Response
                    .status(302)
                    .location(idpUri)
                    .build();

        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse URI: " + uri.toString() + " to authentication request", e);
        }
    }
}
