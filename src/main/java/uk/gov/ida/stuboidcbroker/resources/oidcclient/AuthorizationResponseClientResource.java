package uk.gov.ida.stuboidcbroker.resources.oidcclient;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import io.dropwizard.views.View;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.AuthnResponseValidationService;
import uk.gov.ida.stuboidcbroker.services.RedisService;
import uk.gov.ida.stuboidcbroker.services.TokenRequestService;
import uk.gov.ida.stuboidcbroker.views.RPResponseView;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.ida.stuboidcbroker.services.QueryParameterHelper.splitQuery;

@Path("/formPost")
public class AuthorizationResponseClientResource {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationResponseClientResource.class);

    private final StubOidcBrokerConfiguration configuration;
    private final TokenRequestService tokenRequestService;
    private final AuthnResponseValidationService authnResponseValidationService;
    private final RedisService redisService;

    public AuthorizationResponseClientResource(
            StubOidcBrokerConfiguration configuration,
            TokenRequestService tokenRequestService,
            AuthnResponseValidationService authnResponseValidationService,
            RedisService redisService) {
        this.configuration = configuration;
        this.tokenRequestService = tokenRequestService;
        this.authnResponseValidationService = authnResponseValidationService;
        this.redisService = redisService;
    }

    @POST
    @Path("/validateAuthenticationResponse")
    @Produces(MediaType.TEXT_HTML)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public View validateAuthenticationResponse(String postBody) throws IOException, java.text.ParseException, ParseException {
        Map<String, String> authenticationParams = splitQuery(postBody);
        String transactionID = authenticationParams.get("transactionID");
        String rpDomain = redisService.get(transactionID);
        LOG.info("RP Domain is :" + rpDomain);
        URI rpUri = UriBuilder.fromUri(rpDomain).build();

        if (postBody.isEmpty()) {
            return new RPResponseView(rpUri, "Post Body is empty", Integer.toString(HttpStatus.SC_BAD_REQUEST));
        }

        Optional<String> errors = authnResponseValidationService.checkResponseForErrors(authenticationParams);

        if (errors.isPresent()) {
            return new RPResponseView(rpUri, "Errors in Response: " + errors.get(), Integer.toString(HttpStatus.SC_BAD_REQUEST));
        }

        String brokerName = getBrokerName(transactionID);
        String brokerDomain = getBrokerDomain(transactionID);
        AuthorizationCode authorizationCode = authnResponseValidationService.handleAuthenticationResponse(authenticationParams, getClientID(brokerName));
        String userInfoInJson = retrieveTokenAndUserInfo(authorizationCode, brokerName, brokerDomain);

        return new RPResponseView(rpUri, userInfoInJson, Integer.toString(HttpStatus.SC_OK));
    }

    @POST
    @Path("/idpAuthenticationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response sendIdpAuthenticationRequest(@FormParam("idpDomain") String domain, @FormParam("transactionID") String transactionID) {
        List<String> orgList = Arrays.asList(domain.split(","));
        String idpDomain = orgList.get(0);
        String idpName = orgList.get(1);

        URI idpUri = UriBuilder.fromUri(idpDomain).path(Urls.IDP.AUTHENTICATION_URI)
                .queryParam("transaction-id", transactionID)
                .queryParam("redirect-path", Urls.StubBroker.IDP_AUTHENTICATION_RESPONE)
                .build();
        LOG.info("IDP URI is: " + idpUri);

        return Response
                .status(302)
                .location(idpUri)
                .build();
    }

    @GET
    @Path("/idpAuthenticationResponse")
    @Produces(MediaType.TEXT_HTML)
    public View handAuthenticationResponse(@QueryParam("transaction-id") String transactionID) {
        String rpUri = redisService.get(transactionID);
        String verifiableCredential = getVerifiableCredential(new BearerAccessToken());

        LOG.info("RP URI is: " + rpUri);
        URI rpUriDomain = UriBuilder.fromUri(rpUri).build();

        return new RPResponseView(rpUriDomain, verifiableCredential, Integer.toString(HttpStatus.SC_OK));
    }

    private String retrieveTokenAndUserInfo(AuthorizationCode authCode, String brokerName, String brokerDomain) {

        OIDCTokens tokens = tokenRequestService.getTokens(authCode, getClientID(brokerName), brokerDomain);

//            UserInfo userInfo = tokenService.getUserInfo(tokens.getBearerAccessToken());

//            String userInfoToJson = userInfo.toJSONObject().toJSONString();
        return tokenRequestService.getVerifiableCredential(tokens.getBearerAccessToken(), brokerDomain);
    }

    private String getBrokerName(String transactionID) {
        return redisService.get(transactionID + "-brokername");
    }

    private String getBrokerDomain(String transactionID) {
        return redisService.get(transactionID + "-brokerdomain");
    }

    private ClientID getClientID(String brokerName) {
        String client_id = redisService.get(brokerName);
        if (client_id != null) {
            return new ClientID(client_id);
        }
        return new ClientID();
    }

    public String getVerifiableCredential(AccessToken accessToken) {

        URI userInfoURI = UriBuilder.fromUri(configuration.getIdpURI())
                .path(Urls.IDP.CREDENTIAL_URI).build();

        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .header("Authorization", accessToken.toAuthorizationHeader())
                .uri(userInfoURI)
                .build();

        HttpResponse<String> responseBody;
        try {
            responseBody = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
        return responseBody.body();
    }
}
