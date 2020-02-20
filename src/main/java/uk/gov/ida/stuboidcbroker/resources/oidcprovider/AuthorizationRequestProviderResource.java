package uk.gov.ida.stuboidcbroker.resources.oidcprovider;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import io.dropwizard.views.View;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.oidcprovider.AuthnRequestValidationService;
import uk.gov.ida.stuboidcbroker.services.shared.PickerService;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;
import uk.gov.ida.stuboidcbroker.views.BrokerErrorResponseView;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import static uk.gov.ida.stuboidcbroker.services.shared.QueryParameterHelper.splitQuery;

@Path("/authorizeFormPost")
public class AuthorizationRequestProviderResource {

    private final AuthnRequestValidationService authnRequestValidationService;
    private final StubOidcBrokerConfiguration configuration;
    private final RedisService redisService;
    private final PickerService pickerService;

    public AuthorizationRequestProviderResource(
            AuthnRequestValidationService authnRequestValidationService,
            StubOidcBrokerConfiguration configuration,
            RedisService redisService,
            PickerService pickerService) {
        this.authnRequestValidationService = authnRequestValidationService;
        this.configuration = configuration;
        this.redisService = redisService;
        this.pickerService = pickerService;
    }

    //TODO: The spec states there should be a post method for this endpoint as well
    @GET
    @Path("/authorize")
    public Object authorize(
            @Context UriInfo uriInfo,
            @QueryParam("transaction-id") String transactionID) {

        AuthenticationRequest authenticationRequest = parseURIInfo(uriInfo);
        Optional<AuthenticationErrorResponse> errorResponse = authnRequestValidationService.handleAuthenticationRequest(
                authenticationRequest, transactionID);

        if (errorResponse.isPresent()) {
            return new BrokerErrorResponseView(
                    errorResponse.get().getErrorObject().getCode(),
                    errorResponse.get().getErrorObject().getDescription(),
                    errorResponse.get().getErrorObject().getHTTPStatusCode(),
                    errorResponse.get().getState(),
                    errorResponse.get().getRedirectionURI(),
                    transactionID);
        }
        Map<String, String> params = splitQuery(redisService.get(transactionID));
        URI idpUri = UriBuilder.fromUri(
                configuration.getIdpURI())
                .path(Urls.IDP.AUTHENTICATION_URI)
                .queryParam("claims", Base64.getEncoder().encodeToString(params.get("claims").getBytes()))
                .queryParam("transaction-id", transactionID)
                .queryParam("redirect-path", Urls.StubBrokerClient.RESPONSE_FOR_BROKER)
                .build();

        return Response
                .status(302)
                .location(idpUri)
                .build();
    }

    @GET
    @Path("/authorize-sp")
    public View authorizeServiceProvider(
            @Context UriInfo uriInfo,
            @QueryParam("transaction-id") String transactionID) {

        AuthenticationRequest authenticationRequest = parseURIInfo(uriInfo);
        Optional<AuthenticationErrorResponse> errorResponse = authnRequestValidationService.handleAuthenticationRequest(
                authenticationRequest, transactionID);

        return errorResponse.map(error -> {
            View brokerErrorResponseView = new BrokerErrorResponseView(
                    error.getErrorObject().getCode(),
                    error.getErrorObject().getDescription(),
                    error.getErrorObject().getHTTPStatusCode(),
                    error.getState(),
                    error.getRedirectionURI(),
                    transactionID);
            return brokerErrorResponseView;
        }).orElseGet(() -> {
            storeRpResponseURI(transactionID, authenticationRequest.getRedirectionURI().toString());
            storeRequestedClaims(transactionID, authenticationRequest.getClaims());
            return pickerService.generatePickerPageView(transactionID);});
    }

    private AuthenticationRequest parseURIInfo(UriInfo uriInfo) {
        URI requestURI = uriInfo.getRequestUri();
        AuthenticationRequest authenticationRequest;
        try {
            authenticationRequest = AuthenticationRequest.parse(requestURI);
        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse URI: " + requestURI.toString() + " for authentication request", e);
        }
        return authenticationRequest;
    }

    private void storeRpResponseURI(String transactionID, String rpResponsePath) {

        redisService.set(transactionID + "service-provider", rpResponsePath);
    }

    private void storeRequestedClaims(String transactionID, ClaimsRequest claims) {

        redisService.set(transactionID + "claims", claims.toString());
    }
}
