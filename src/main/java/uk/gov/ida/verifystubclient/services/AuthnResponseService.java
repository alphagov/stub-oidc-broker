package uk.gov.ida.verifystubclient.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.claims.CodeHash;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import net.minidev.json.JSONObject;

import java.io.IOException;
import java.util.Map;

import static uk.gov.ida.verifystubclient.services.QueryParameterHelper.splitQuery;

public class AuthnResponseService {

    private final TokenService tokenService;

    public AuthnResponseService(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    public AuthorizationCode handleAuthenticationResponse(String postBody, ClientID clientID)
            throws ParseException, java.text.ParseException, IOException {

        Map<String, String> authenticationParams = splitQuery(postBody);

        String authCode = authenticationParams.get("code");
        AuthorizationCode authorizationCode = new AuthorizationCode(authCode);

        String id_token = authenticationParams.get("id_token");
        SignedJWT signedJWT = SignedJWT.parse(id_token);
        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
        IDTokenClaimsSet idToken = new IDTokenClaimsSet(jwtClaimsSet);
        String stringAccessToken = authenticationParams.get("access_token");

        validateCHash(authorizationCode, idToken);

        if (stringAccessToken != null && stringAccessToken.length() > 0) {
            AccessToken accessToken = retrieveAccessToken(stringAccessToken);
            validateAccessTokenHash(accessToken, idToken);
        }

        String state = authenticationParams.get("state");
        String nonce = tokenService.getNonce(state);
        validateNonce(nonce, idToken);
        validateNonceUsageCount(tokenService.getNonceUsageCount(nonce));

        validateIssuer(idToken);

        validateAudience(clientID, idToken);

        validateIDTokenSignature(signedJWT);

        return authorizationCode;
    }

    private AccessToken retrieveAccessToken(String stringAccessToken) throws ParseException {

    if (isJSONValid(stringAccessToken)) {
        JSONObject accessTokenJson = JSONObjectUtils.parse(stringAccessToken);
        return AccessToken.parse(accessTokenJson);
    }
        return new BearerAccessToken(stringAccessToken);
    }

    private static boolean isJSONValid(String jsonInString ) {
        try {
            final ObjectMapper mapper = new ObjectMapper();
            mapper.readTree(jsonInString);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private void validateCHash(AuthorizationCode authCode, IDTokenClaimsSet idToken) {
        //3.3.2.40 - The Value of c_hash in the ID token MUST match the value produced by the authentication
        //code. 16.11 - The c_hash in the ID Token enables Clients to prevent Authorization Code substitution
        CodeHash authCodeHash = CodeHash.compute(authCode, JWSAlgorithm.RS256);
        CodeHash idTokencodeHash = idToken.getCodeHash();

        if (!authCodeHash.equals(idTokencodeHash)) {
            throw new RuntimeException("CodeHashes are not equal");
        }
    }

    private void validateNonce(String nonce, IDTokenClaimsSet idToken) {
        //3.2.3.11 - The value of the nonce Claim MUST be checked to verify that it is the same
        //value as the one that was sent in the Authentication Request. The Client SHOULD
        //check the nonce value for replay attacks. This is also helps mitigates for the cut and pasted code attack.

        Nonce responseNonce = idToken.getNonce();

        if (!nonce.equals(responseNonce.getValue())) {
            throw new RuntimeException("Nonces are not equal");
        }
    }

    private void validateNonceUsageCount(Long nonceUsageCount) {
        // Count is set to 1 after initial creation, so will be 2 after first lookup.
        // Anything else should be rejected here.
        if (nonceUsageCount != 2) {
            throw new RuntimeException("Nonce has been used too many times");
        }
    }

    private void validateAudience(ClientID clientId, IDTokenClaimsSet idToken) {
        //2 The audience is required so throw exception when there is none present
        if (idToken.getAudience().isEmpty()) {
            throw new RuntimeException("No audience present within IDToken");
        }
        //3.1.3.7 - The Client MUST validate that the audience Claim contains it's client_id value.
        //The audience claim may contain multiple values but it must be rejected if the ID token does not list the Client
        //as a valid audience. It is up to the client whether to reject if it contains any other audience claims that are not trusted.
        for (Audience audience : idToken.getAudience()) {
            if (!audience.getValue().equals(clientId.getValue())) {
                throw new RuntimeException("INVALID AUDIENCE: " + audience.getValue() + " - Verify Stub Client only trusts audience where the client id is: " + clientId.getValue());
            }
        }
        //TODO - As per 3.1.3.7 - We might need more specific validation to check if there are multiple audiences and if the client trusts them. As per point 3,4 and 5 on 3.1.3.7.a
    }

    private void validateIssuer(IDTokenClaimsSet idToken) {
        //3.1.37 - The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the iss (issuer) Claim.
        Issuer issuer = idToken.getIssuer();
        if (!issuer.getValue().equals("verify-stub-op")) {
            throw new RuntimeException("Incorrect issuer - Issuer expected: verify-stub-op but issuer received was: " + issuer.getValue());
        }
        //TODO - Get the issuer from the Discovery when it is implemented
    }

    private void validateState() {
        //TODO As per 10.12 on RFC6749 to mitigate against Cross-Site Request Forgery
        //and compare the STATE parameter against what was sent in to the request to that
        //which was received in the response

        //We could store this in redis by creating a random unique idenfier that is stored in the user session. This will be the
        //key in which is stored against the state in redis.
    }

    private void validateExpiryTime() {
        //TODO 3.1.37
        //The current time MUST be before the time represented by the exp Claim
    }

    private void validateIDTokenSignature(SignedJWT signedJWT) {
        //3.2.2.11 The Client MUST validate the signature of the ID Token according to the JWS using
        //the algorith specified in the alg Header parameter of the JOSE Header
        JWSAlgorithm algorithm = signedJWT.getHeader().getAlgorithm();

        //TODO - Create Signing key pair and validate
        //Feels that this falls more into layer 4 once we have started looking into PKI
    }

    private void validateAccessTokenHash(AccessToken accessToken, IDTokenClaimsSet idToken) {
        //3.2.2.9 - The value of at_hash in the ID Token MUST match that produced by the client.
        AccessTokenHash accessTokenHash = AccessTokenHash.compute(accessToken, JWSAlgorithm.RS256);
        AccessTokenHash idTokenAccessTokenHash = idToken.getAccessTokenHash();

        if (!accessTokenHash.equals(idTokenAccessTokenHash)) {
            throw new RuntimeException("AccessTokenHashes are not equal");
        }
    }
}
