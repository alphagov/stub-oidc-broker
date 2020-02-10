package uk.gov.ida.stuboidcbroker.services.oidcprovider;

import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;

import java.util.Optional;

public class AuthnRequestValidationService {

    private final TokenHandlerService tokenHandlerService;
    private final RedisService redisService;

    public AuthnRequestValidationService(TokenHandlerService tokenHandlerService, RedisService redisService) {
        this.tokenHandlerService = tokenHandlerService;
        this.redisService = redisService;
    }

    public Optional<AuthenticationErrorResponse> handleAuthenticationRequest(AuthenticationRequest authenticationRequest, String transactionID) {

        validateRedirectURI(authenticationRequest);
        Optional<ErrorObject> errorObject = validateAuthenticationRequest(authenticationRequest);

        return errorObject
                .map(e -> Optional.of(new AuthenticationErrorResponse(
                        authenticationRequest.getRedirectionURI(),
                        errorObject.get(),
                        null,
                        ResponseMode.FRAGMENT)))
                .orElseGet(() -> {
                    redisService.set(transactionID, authenticationRequest.toQueryString());
                    return Optional.empty();
                });
    }

    private void validateRedirectURI(AuthenticationRequest authenticationRequest) {
        //3.1.2.1 - Redirect URI is a required field and must be present. If not then throw an exception.
        //Further validation to do as per FAPI Part 1, section 5.2.2
        if (authenticationRequest.getRedirectionURI() == null) {
            throw new RuntimeException("RedirectURI must not be null");
        }
    }

    private Optional<ErrorObject> validateAuthenticationRequest(AuthenticationRequest authenticationRequest) {
        if (!authenticationRequest.getResponseType().contains("code") && !authenticationRequest.getResponseType().contains("id_token")) {
            //3.1.2.1 & 3.1.2.2 (OpenID spec)- Response Type is a required field and must be validated
            return Optional.of(new ErrorObject("invalid_request_object", "stub OP only supports response types which include BOTH code and id_token"));
        } else if (authenticationRequest.getScope() == null || !authenticationRequest.getScope().toString().equals("openid")) {
            //3.1.2.1 & 3.1.2.2 (OpenID spec)- Validate the a scope is present and contains an 'openid' scope value.
            return Optional.of(new ErrorObject("invalid_request_object", "authentication Request must contain a scope value of 'openid; to be a valid OpenID Connect request"));
        } else if (authenticationRequest.getNonce() == null) {
            //3.2.2.11 (OpenID spec)- Nonce must be present for the Hybrid flow
            return Optional.of(new ErrorObject("invalid_request_object", "nonce cannot be null"));
        } else if (authenticationRequest.getClientID() == null) {
            //3.1.2.1 & 3.1.2.2 (OpenID spec) Client ID is a required field and must be validated
            return Optional.of(new ErrorObject("invalid_request_object", "client ID cannot be null"));
        } else if (!validateClientID(authenticationRequest.getClientID())) {
            return Optional.of(new ErrorObject("invalid_request_object", "Client has not been registerd with this OP"));
        } else if (authenticationRequest.getState() == null) {
            //Although Optional in OpenID spec it is expected as defined in FAPI Part 1, section 5.2.3
            return Optional.of(new ErrorObject("invalid_request_object", "state should not be be null"));
        }
        return Optional.empty();
    }

    private boolean validateClientID(ClientID clientID) {
        return redisService.get(clientID.toString()) != null;
    }
}
