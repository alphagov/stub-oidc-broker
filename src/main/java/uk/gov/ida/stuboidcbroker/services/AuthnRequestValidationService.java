package uk.gov.ida.stuboidcbroker.services;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import org.eclipse.jetty.http.HttpStatus;

import java.util.Optional;

public class AuthnRequestValidationService {

    private final TokenGeneratorService tokenGeneratorService;
    private final RedisService redisService;

    public AuthnRequestValidationService(TokenGeneratorService tokenGeneratorService, RedisService redisService) {
        this.tokenGeneratorService = tokenGeneratorService;
        this.redisService = redisService;
    }

    public AuthenticationResponse handleAuthenticationRequest(AuthenticationRequest authenticationRequest) {

        validateRedirectURI(authenticationRequest);
        Optional<ErrorObject> errorObject = validateAuthenticationRequest(authenticationRequest);

        if (errorObject.isPresent()) {
            return new AuthenticationErrorResponse(
                    authenticationRequest.getRedirectionURI(),
                    errorObject.get(),
                    null,
                    ResponseMode.FRAGMENT);
    }

        AuthorizationCode authorizationCode = tokenGeneratorService.getAuthorizationCode();

        AccessToken accessToken = new BearerAccessToken();

        AccessToken returnedAccessToken = null;
        if (authenticationRequest.getResponseType().contains("token")) {
            returnedAccessToken = accessToken;
        }

        JWT idToken = tokenGeneratorService.generateAndGetIdToken(authorizationCode, authenticationRequest, accessToken);

        return new AuthenticationSuccessResponse(
                authenticationRequest.getRedirectionURI(),
                authorizationCode,
                idToken,
                returnedAccessToken,
                authenticationRequest.getState(),
                null,
                null
        );
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
            return Optional.of(new ErrorObject("invalid_request_object", "stub OP only supports response types which include BOTH code and id_token", HttpStatus.BAD_REQUEST_400));
        } else if (authenticationRequest.getScope() == null || !authenticationRequest.getScope().toString().equals("openid")) {
            //3.1.2.1 & 3.1.2.2 (OpenID spec)- Validate the a scope is present and contains an 'openid' scope value.
            return Optional.of(new ErrorObject("invalid_request_object", "authentication Request must contain a scope value of 'openid; to be a valid OpenID Connect request", HttpStatus.BAD_REQUEST_400));
        } else if (authenticationRequest.getNonce() == null) {
            //3.2.2.11 (OpenID spec)- Nonce must be present for the Hybrid flow
            return Optional.of(new ErrorObject("invalid_request_object", "nonce cannot be null", HttpStatus.BAD_REQUEST_400));
        } else if (authenticationRequest.getClientID() == null) {
            //3.1.2.1 & 3.1.2.2 (OpenID spec) Client ID is a required field and must be validated
            return Optional.of(new ErrorObject("invalid_request_object", "client ID cannot be null", HttpStatus.BAD_REQUEST_400));
        } else if (!validateClientID(authenticationRequest.getClientID())) {
            return Optional.of(new ErrorObject("invalid_request_object", "Client has not been registerd with this OP", HttpStatus.BAD_REQUEST_400));
        } else if(authenticationRequest.getState() == null) {
            //Although Optional in OpenID spec it is expected as defined in FAPI Part 1, section 5.2.3
            return Optional.of(new ErrorObject("invalid_request_object", "state should not be be null", HttpStatus.BAD_REQUEST_400));
        }
        return Optional.empty();
    }

    private boolean validateClientID(ClientID clientID) {
        return redisService.get(clientID.toString()) != null;
    }
}
