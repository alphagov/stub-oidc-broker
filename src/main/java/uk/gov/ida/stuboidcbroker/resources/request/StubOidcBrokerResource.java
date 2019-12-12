package uk.gov.ida.stuboidcbroker.resources.request;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import io.dropwizard.views.View;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.domain.Organisation;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.AuthnRequestGeneratorService;
import uk.gov.ida.stuboidcbroker.services.RedisService;
import uk.gov.ida.stuboidcbroker.services.TokenRequestService;
import uk.gov.ida.stuboidcbroker.services.AuthnResponseValidationService;
import uk.gov.ida.stuboidcbroker.views.AuthenticationCallbackViewHttp;
import uk.gov.ida.stuboidcbroker.views.AuthenticationCallbackViewHttps;
import uk.gov.ida.stuboidcbroker.views.RegistrationView;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
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
import java.util.Arrays;
import java.util.List;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;

import static uk.gov.ida.stuboidcbroker.services.QueryParameterHelper.splitQuery;

@Path("/")
public class StubOidcBrokerResource {

    private final StubOidcBrokerConfiguration configuration;
    private final TokenRequestService tokenRequestService;
    private final AuthnRequestGeneratorService authnRequestGeneratorService;
    private final AuthnResponseValidationService authnResponseValidationService;
    private final RedisService redisService;
    private String brokerDomain;
    private String brokerName;

    public StubOidcBrokerResource(
            StubOidcBrokerConfiguration configuration,
            TokenRequestService tokenRequestService,
            AuthnRequestGeneratorService authnRequestGeneratorService,
            AuthnResponseValidationService authnResponseValidationService,
            RedisService redisService) {
        this.configuration = configuration;
        this.tokenRequestService = tokenRequestService;
        this.authnRequestGeneratorService = authnRequestGeneratorService;
        this.authnResponseValidationService = authnResponseValidationService;
        this.redisService = redisService;
    }

    @GET
    @Path("/")
    public View startPage() throws IOException {
        String scheme = configuration.getScheme();
        URI brokerRequestURI = UriBuilder.fromUri(configuration.getDirectoryURI()).path(Urls.Directory.REGISTERED_BROKERS + scheme)
                .build();

        HttpResponse<String> brokersResponse = getOrganisations(brokerRequestURI);
        List<Organisation> brokers = getOrganisationsFromResponse(brokersResponse);

        return new RegistrationView(brokers);
    }

    @POST
    @Path("/serviceAuthenticationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response serviceAuthenticationRequest(@FormParam("brokerDomain") String idpDomain) {
        List<String> orgList = Arrays.asList(idpDomain.split(","));
        String domain = orgList.get(0);
        String brokerName = orgList.get(1);
        this.brokerDomain = domain;
        this.brokerName = brokerName;
        URI requestURI = UriBuilder.fromUri(
                domain).path(Urls.StubOp.AUTHORISATION_ENDPOINT_URI)
                .build();

        URI redirectURI = UriBuilder.fromUri(
                configuration.getStubBrokerURI()).path(Urls.StubBroker.REDIRECT_URI)
                .build();

        return Response
                .status(302)
                .location(authnRequestGeneratorService.generateAuthenticationRequest(
                        requestURI,
                        getClientID(brokerDomain),
                        redirectURI,
                        new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN))
                        .toURI())
                        .build();
    }

    @GET
    @Path("/authenticationCallback")
    public View authenticationCallback() {
        if (configuration.isLocal()) {
            return new AuthenticationCallbackViewHttp();
        } else {
            return new AuthenticationCallbackViewHttps();
        }
    }

    @POST
    @Path("/validateAuthenticationResponse")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response validateAuthenticationResponse(String postBody) throws IOException, java.text.ParseException, ParseException {
        if (postBody == null || postBody.isEmpty()) {
            return Response.status(500).entity("PostBody is empty").build();
        }

        Optional<String> errors = authnResponseValidationService.checkResponseForErrors(postBody);

        if (errors.isPresent()) {
            return Response.status(400).entity(errors.get()).build();
        }

        AuthorizationCode authorizationCode = authnResponseValidationService.handleAuthenticationResponse(postBody, getClientID(brokerDomain));
        return Response.ok(authorizationCode.getValue()).build();
    }

    @GET
    @Path("/retrieveTokenAndUserInfo")
    @Produces(MediaType.APPLICATION_JSON)
    public Response retrieveTokenAndUserInfo(@Context UriInfo uriInfo) throws UnsupportedEncodingException {

            String query = uriInfo.getRequestUri().getQuery();
            Map<String, String> authenticationParams = splitQuery(query);
            String authCode = authenticationParams.get("code");

            OIDCTokens tokens = tokenRequestService.getTokens(new AuthorizationCode(authCode), getClientID(brokerDomain), brokerDomain);
            UserInfo userInfo = tokenRequestService.getUserInfo(tokens.getBearerAccessToken(), brokerDomain);

            String userInfoToJson = userInfo.toJSONObject().toJSONString();
            return Response.ok(userInfoToJson).build();
    }

    private ClientID getClientID(String brokerName) {
       String client_id = redisService.get(brokerName);
        if (client_id != null) {
            return new ClientID(client_id);
        }
        return new ClientID();
    }

    private List<Organisation> getOrganisationsFromResponse(HttpResponse<String> responseBody) throws IOException {
        JSONParser parser = new JSONParser(JSONParser.MODE_JSON_SIMPLE);
        JSONArray jsonarray;
        try {
            jsonarray = (JSONArray) parser.parse(responseBody.body());
        } catch (net.minidev.json.parser.ParseException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        List<Organisation> orgList = new ArrayList<>();
        for(int i = 0; i < jsonarray.size(); i++) {
            JSONObject obj = (JSONObject) jsonarray.get(i);
            ObjectMapper objectMapper = new ObjectMapper();
            Organisation org = objectMapper.readValue(obj.toJSONString(), Organisation.class);
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
}
