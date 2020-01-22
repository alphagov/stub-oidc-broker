package uk.gov.ida.stuboidcbroker.resources.oidcprovider;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import io.dropwizard.views.View;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.domain.Organisation;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.oidcprovider.AuthnRequestValidationService;
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
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Path("/authorizeFormPost")
public class AuthorizationRequestProviderResource {

    private final AuthnRequestValidationService validationService;
    private final StubOidcBrokerConfiguration configuration;
    private final RedisService redisService;

    public AuthorizationRequestProviderResource(AuthnRequestValidationService validationService, StubOidcBrokerConfiguration configuration, RedisService redisService) {
        this.validationService = validationService;
        this.configuration = configuration;
        this.redisService = redisService;
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

    //TODO: The spec states there should be a post method for this endpoint as well
    @GET
    @Path("/authorize-sp")
    public View authorize(@Context UriInfo uriInfo, @QueryParam("transaction-id") String transactionID, @QueryParam("response-uri") String spURI) {
        URI requestURI = uriInfo.getRequestUri();

        try {
            AuthenticationRequest authenticationRequest = AuthenticationRequest.parse(requestURI);

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


            URI serviceProviderURI = UriBuilder.fromUri(spURI).build();

            storeTransactionID(transactionID + "service-provider", serviceProviderURI.toString());

            String scheme = configuration.getScheme();
            URI idpRequestURI = UriBuilder.fromUri(configuration.getDirectoryURI()).path(Urls.Directory.REGISTERED_IDPS + scheme)
                    .build();
            URI brokerRequestURI = UriBuilder.fromUri(configuration.getDirectoryURI()).path(Urls.Directory.REGISTERED_BROKERS + scheme)
                    .build();

            HttpResponse<String> idpsResponse = getOrganisations(idpRequestURI);
            HttpResponse<String> brokersResponse = getOrganisations(brokerRequestURI);

            List<Organisation> idps = getOrganisationsFromResponse(idpsResponse);
            List<Organisation> brokers = getOrganisationsFromResponse(brokersResponse);
            List<Organisation> registeredBrokers = brokers.stream()
                    .filter(org -> redisService.get(org.getName()) != null)
                    .collect(Collectors.toList());

            return new PickerView(idps, registeredBrokers, transactionID, configuration.getBranding(), configuration.getScheme(), configuration.getDirectoryURI());

        } catch (ParseException | IOException e) {
            throw new RuntimeException("Unable to parse URI: " + requestURI.toString() + " to authentication request", e);
        }
    }

    private List<Organisation> getOrganisationsFromResponse(HttpResponse<String> responseBody) throws IOException {
        JSONParser parser = new JSONParser(JSONParser.MODE_JSON_SIMPLE);
        JSONArray jsonarray;
        try {
            jsonarray = (JSONArray) parser.parse(responseBody.body());
        } catch (net.minidev.json.parser.ParseException e) {
            throw new RuntimeException(e);
        }

        List<Organisation> orgList = new ArrayList<>();

        for (Object obj : jsonarray) {
            JSONObject jsonObj = (JSONObject) obj;
            ObjectMapper objectMapper = new ObjectMapper();
            Organisation org = objectMapper.readValue(jsonObj.toJSONString(), Organisation.class);
            orgList.add(org);
        }
        return orgList;
    }

    private HttpResponse<String> getOrganisations(URI uri) {
        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .uri(uri)
                .build();

        try {
            return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private void storeTransactionID(String transactionID, String rpResponsePath) {

        redisService.set(transactionID, rpResponsePath);
    }
}
