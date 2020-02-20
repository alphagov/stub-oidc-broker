package uk.gov.ida.stuboidcbroker.services.oidcprovider;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;

public class AuthnResponseGeneratorService {

    private TokenHandlerService tokenHandlerService;
    private RedisService redisService;

    public AuthnResponseGeneratorService(TokenHandlerService tokenHandlerService, RedisService redisService) {
        this.tokenHandlerService = tokenHandlerService;
        this.redisService = redisService;
    }

    public AuthenticationSuccessResponse handleAuthenticationRequestResponse(String transactionID) {
        String serialisedRequest = redisService.get(transactionID);

        AuthenticationRequest authenticationRequest;
        try {
            authenticationRequest = AuthenticationRequest.parse(serialisedRequest);
        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse authentication request", e);
        }
        AuthorizationCode authorizationCode = new AuthorizationCode();
        AccessToken accessToken = new BearerAccessToken();
        AccessToken returnedAccessToken = null;

        if (authenticationRequest.getResponseType().contains("token")) {
            returnedAccessToken = accessToken;
        }

        JWT idToken = tokenHandlerService.generateAndGetIdToken(authorizationCode, authenticationRequest, accessToken);

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

    public AuthenticationErrorResponse handleAuthenticationErrorResponse(String transactionID, ErrorObject errorCode) {
        //TODO - Map errorcode to OIDCError object

        String serialisedRequest = redisService.get(transactionID);

        AuthenticationRequest authenticationRequest;
        try {
            authenticationRequest = AuthenticationRequest.parse(serialisedRequest);
        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse authentication request", e);
        }

        return new AuthenticationErrorResponse(
                authenticationRequest.getRedirectionURI(),
                errorCode,
                authenticationRequest.getState(),
                null);
    }
}
