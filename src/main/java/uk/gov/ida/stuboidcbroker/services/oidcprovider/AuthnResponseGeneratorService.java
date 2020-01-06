package uk.gov.ida.stuboidcbroker.services.oidcprovider;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
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

    public AuthenticationSuccessResponse handleAuthenticationRequestResponse(String transactionID) throws ParseException {
        String serialisedRequest = redisService.get(transactionID);
        AuthenticationRequest authenticationRequest = AuthenticationRequest.parse(serialisedRequest);
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
}
