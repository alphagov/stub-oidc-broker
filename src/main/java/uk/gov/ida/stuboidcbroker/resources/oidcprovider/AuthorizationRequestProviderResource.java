package uk.gov.ida.stuboidcbroker.resources.oidcprovider;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import io.dropwizard.views.View;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.domain.Organisation;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.oidcprovider.AuthnRequestValidationService;
import uk.gov.ida.stuboidcbroker.services.shared.PickerService;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;
import uk.gov.ida.stuboidcbroker.views.BrokerErrorResponseView;
import uk.gov.ida.stuboidcbroker.views.PickerView;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Path("/authorizeFormPost")
public class AuthorizationRequestProviderResource {

    private final AuthnRequestValidationService validationService;
    private final StubOidcBrokerConfiguration configuration;
    private final RedisService redisService;
    private final PickerService pickerService;

    public AuthorizationRequestProviderResource(
            AuthnRequestValidationService validationService,
            StubOidcBrokerConfiguration configuration,
            RedisService redisService,
            PickerService pickerService) {
        this.validationService = validationService;
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

        URI uri = uriInfo.getRequestUri();
        AuthenticationRequest authenticationRequest;

        try {
            authenticationRequest = AuthenticationRequest.parse(uri);
        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse URI: " + uri.toString() + " to authentication request", e);
        }

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
    }

    //This is the same as the above but this supplies us a picker page. There might be a nicer way of doing this where we are not duplicating code
    @GET
    @Path("/authorize-sp")
    public View authorizeServiceProvider(
            @Context UriInfo uriInfo,
            @QueryParam("transaction-id") String transactionID) {

        URI requestURI = uriInfo.getRequestUri();
        AuthenticationRequest authenticationRequest;
        try {
            authenticationRequest = AuthenticationRequest.parse(requestURI);
        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse URI: " + requestURI.toString() + " for authentication request", e);
        }
        Optional<AuthenticationErrorResponse> errorResponse = validationService.handleAuthenticationRequest(authenticationRequest, transactionID);

        return errorResponse.map(error -> {
            View brokerErrorResponseView = new BrokerErrorResponseView(
                    error.getErrorObject().getCode(),
                    error.getErrorObject().getDescription(),
                    error.getErrorObject().getHTTPStatusCode(),
                    error.getState(),
                    error.getRedirectionURI(),
                    transactionID);
            return brokerErrorResponseView;
        }).orElseGet(() -> generatePickerPageView(authenticationRequest.getRedirectionURI(), transactionID));
    }

    private PickerView generatePickerPageView(URI rpURI, String transactionID) {
        storeRpResponseURI(transactionID, rpURI.toString());
        String scheme = configuration.getScheme();

        URI idpRequestURI = UriBuilder.fromUri(configuration.getDirectoryURI())
                .path(Urls.Directory.REGISTERED_IDPS + scheme)
                .build();
        URI brokerRequestURI = UriBuilder.fromUri(configuration.getDirectoryURI())
                .path(Urls.Directory.REGISTERED_BROKERS + scheme)
                .build();

        List<Organisation> idps = pickerService.getOrganisationsFromDirectory(idpRequestURI);
        List<Organisation> brokers = pickerService.getOrganisationsFromDirectory(brokerRequestURI);

        List<Organisation> registeredBrokers = brokers
                .stream()
                .filter(org -> redisService.get(org.getName()) != null)
                .collect(Collectors.toList());

        String redirectUri = UriBuilder.fromUri(configuration.getStubBrokerURI())
                .path(Urls.StubBrokerClient.REDIRECT_FOR_SERVICE_PROVIDER_URI)
                .build().toString();

        String rpCreateIdentityUri = UriBuilder
            .fromUri(rpURI)
            .replacePath(Urls.StubRpPathsAssumptions.RP_CREATE_IDENTITY_PATH)
            .build()
            .toString();

        return new PickerView(idps, registeredBrokers, transactionID, configuration.getBranding(),
                scheme, configuration.getDirectoryURI(), redirectUri, rpCreateIdentityUri);
    }

    private void storeRpResponseURI(String transactionID, String rpResponsePath) {

        redisService.set(transactionID + "service-provider", rpResponsePath);
    }
}
