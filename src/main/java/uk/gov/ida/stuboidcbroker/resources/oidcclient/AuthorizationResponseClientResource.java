package uk.gov.ida.stuboidcbroker.resources.oidcclient;

import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import io.dropwizard.views.View;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.stuboidcbroker.services.oidcclient.AuthnResponseValidationService;
import uk.gov.ida.stuboidcbroker.services.oidcprovider.AuthnResponseGeneratorService;
import uk.gov.ida.stuboidcbroker.services.oidcprovider.UserInfoService;
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
import java.util.Map;
import java.util.Optional;

import static uk.gov.ida.stuboidcbroker.services.shared.QueryParameterHelper.splitQuery;

@Path("/formPost")
public class AuthorizationResponseClientResource {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizationResponseClientResource.class);

    private final AuthnResponseValidationService authnResponseValidationService;
    private final RedisService redisService;
    private final AuthnResponseGeneratorService generatorService;
    private final PickerService pickerService;
    private final UserInfoService userInfoService;

    public AuthorizationResponseClientResource(
            AuthnResponseValidationService authnResponseValidationService,
            RedisService redisService,
            AuthnResponseGeneratorService generatorService,
            PickerService pickerService,
            UserInfoService userInfoService) {
        this.authnResponseValidationService = authnResponseValidationService;
        this.redisService = redisService;
        this.generatorService = generatorService;
        this.pickerService = pickerService;
        this.userInfoService = userInfoService;
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
                        userInfoService.getUserInfoForRPResponse(transactionID, authenticationParams),
                        Integer.toString(HttpStatus.SC_OK)));
    }

    @POST
    @Path("/validateAuthenticationResponseForServiceProvider")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public View validateAuthenticationResponseForService(String postBody) {

        Map<String, String> authenticationParams = splitQuery(postBody);
        String transactionID = authenticationParams.get("transactionID");

        if (authenticationParams.containsKey("error")) {
            PickerView pickerView = pickerService.generatePickerPageView(transactionID, authenticationParams.get("error"), authenticationParams.get("error_description"));
            return pickerView;
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
}
