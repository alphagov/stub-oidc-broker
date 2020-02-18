package uk.gov.ida.stuboidcbroker.resources.oidcclient;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import io.dropwizard.views.View;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.domain.Organisation;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.oidcclient.AuthnResponseValidationService;
import uk.gov.ida.stuboidcbroker.services.oidcclient.TokenRequestService;
import uk.gov.ida.stuboidcbroker.services.oidcprovider.AuthnResponseGeneratorService;
import uk.gov.ida.stuboidcbroker.services.shared.PickerService;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;
import uk.gov.ida.stuboidcbroker.views.BrokerResponseView;
import uk.gov.ida.stuboidcbroker.views.PickerView;
import uk.gov.ida.stuboidcbroker.views.RPResponseView;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static uk.gov.ida.stuboidcbroker.services.shared.QueryParameterHelper.splitQuery;

@Path("/formPost")
public class AuthorizationResponseClientResource {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationResponseClientResource.class);

    private final TokenRequestService tokenRequestService;
    private final AuthnResponseValidationService authnResponseValidationService;
    private final RedisService redisService;
    private final AuthnResponseGeneratorService generatorService;
    private final StubOidcBrokerConfiguration configuration;
    private final PickerService pickerService;

    public AuthorizationResponseClientResource(
            TokenRequestService tokenRequestService,
            AuthnResponseValidationService authnResponseValidationService,
            RedisService redisService,
            AuthnResponseGeneratorService generatorService,
            StubOidcBrokerConfiguration configuration,
            PickerService pickerService) {
        this.tokenRequestService = tokenRequestService;
        this.authnResponseValidationService = authnResponseValidationService;
        this.redisService = redisService;
        this.generatorService = generatorService;
        this.configuration = configuration;
        this.pickerService = pickerService;
    }

    @POST
    @Path("/validateAuthenticationResponse")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public View validateAuthenticationResponse(String postBody) {

        Map<String, String> authenticationParams = splitQuery(postBody);
        String transactionID = authenticationParams.get("transactionID");
        String rpDomain = redisService.get(transactionID  + "response-uri");
        LOG.info("RP Domain is :" + rpDomain);
        URI rpUri = UriBuilder.fromUri(rpDomain).build();

        if (postBody.isEmpty()) {
            return new RPResponseView(rpUri, "Post Body is empty", Integer.toString(HttpStatus.SC_BAD_REQUEST));
        }

        Optional<String> errors = authnResponseValidationService.checkResponseForErrors(authenticationParams);

        return errors
                .map(e -> new RPResponseView(
                        rpUri,
                        "Errors in Response: " + e,
                        Integer.toString(HttpStatus.SC_BAD_REQUEST)))
                .orElseGet(() -> new RPResponseView(
                        rpUri,
                        getUserInfoForRPResponse(transactionID, authenticationParams),
                        Integer.toString(HttpStatus.SC_OK)));
    }

    @POST
    @Path("/validateAuthenticationResponseForServiceProvider")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public View validateAuthenticationResponseForService(String postBody) {

        Map<String, String> authenticationParams = splitQuery(postBody);
        String transactionID = authenticationParams.get("transactionID");

        if (authenticationParams.containsKey("error")) {
            String scheme = configuration.getScheme();
            URI idpRequestURI = UriBuilder.fromUri(configuration.getDirectoryURI()).path(Urls.Directory.REGISTERED_IDPS + scheme)
                    .build();
            URI brokerRequestURI = UriBuilder.fromUri(configuration.getDirectoryURI()).path(Urls.Directory.REGISTERED_BROKERS + scheme)
                    .build();

            List<Organisation> idps = pickerService.getOrganisationsFromDirectory(idpRequestURI);
            List<Organisation> brokers = pickerService.getOrganisationsFromDirectory(brokerRequestURI);

            List<Organisation> registeredBrokers = brokers.stream()
                    .filter(org -> redisService.get(org.getName()) != null)
                    .collect(Collectors.toList());

            String redirectUri = UriBuilder.fromUri(configuration.getStubBrokerURI())
                    .path(Urls.StubBrokerClient.REDIRECT_FOR_SERVICE_PROVIDER_URI )
                    .build().toString();


            return new PickerView(idps, registeredBrokers,
                    transactionID, configuration.getBranding(),
                    configuration.getScheme(), configuration.getDirectoryURI(),
                    redirectUri, authenticationParams.get("error"),
                    authenticationParams.get("error_description")
                );
        }

        redisService.set(transactionID + "response-from-broker", postBody);
        AuthenticationSuccessResponse successResponse = generatorService.handleAuthenticationRequestResponse(transactionID);

        return new BrokerResponseView(
                successResponse.getState(),
                successResponse.getAuthorizationCode(),
                successResponse.getIDToken(),
                successResponse.getRedirectionURI(),
                successResponse.getAccessToken(),
                transactionID);
    }

    private String getUserInfoForRPResponse(String transactionID, Map<String, String> authenticationParams) {
        String brokerName = getBrokerName(transactionID);
        String brokerDomain = getBrokerDomain(transactionID);
        AuthorizationCode authorizationCode = authnResponseValidationService.handleAuthenticationResponse(authenticationParams, getClientID(brokerName));
        String userInfoInJson = retrieveTokenAndUserInfo(authorizationCode, brokerName, brokerDomain);

        return userInfoInJson;
    }

    private String retrieveTokenAndUserInfo(AuthorizationCode authCode, String brokerName, String brokerDomain) {

        OIDCTokens tokens = tokenRequestService.getTokens(authCode, getClientID(brokerName), brokerDomain);
//      UserInfo userInfo = tokenService.getUserInfo(tokens.getBearerAccessToken());
//      String userInfoToJson = userInfo.toJSONObject().toJSONString();

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
}
