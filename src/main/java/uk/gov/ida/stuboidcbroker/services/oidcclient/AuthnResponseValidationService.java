package uk.gov.ida.stuboidcbroker.services.oidcclient;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.claims.CodeHash;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;

import java.text.ParseException;
import java.util.Map;
import java.util.Optional;

public class AuthnResponseValidationService {

    private final TokenRequestService tokenRequestService;

    public AuthnResponseValidationService(TokenRequestService tokenRequestService) {
        this.tokenRequestService = tokenRequestService;
    }

    public AuthorizationCode handleAuthenticationResponse(Map<String, String> authenticationParams, ClientID clientID) {

        String authCode = authenticationParams.get("code");
        AuthorizationCode authorizationCode = new AuthorizationCode(authCode);

        String id_token = authenticationParams.get("id_token");

        IDTokenClaimsSet idToken;
        try {
            SignedJWT signedJWT = SignedJWT.parse(id_token);
            JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
            idToken = new IDTokenClaimsSet(jwtClaimsSet);
        } catch (ParseException | com.nimbusds.oauth2.sdk.ParseException e) {
            throw new RuntimeException(e);
        }

        String stringAccessToken = authenticationParams.get("access_token");

        if (stringAccessToken != null && stringAccessToken.length() > 0) {
            AccessToken accessToken = new BearerAccessToken(stringAccessToken);
            validateAccessTokenHash(accessToken, idToken);
        }

        String state = authenticationParams.get("state");
        String nonce = tokenRequestService.getNonce(state);

        validateCHash(authorizationCode, idToken);

        validateNonce(nonce, idToken);
        validateNonceUsageCount(tokenRequestService.getNonceUsageCount(nonce));

        validateIssuer(idToken);

        validateAudience(clientID, idToken);

        return authorizationCode;
    }

    public Optional<String> checkResponseForErrors(Map<String, String> authenticationParams) {

        if (authenticationParams.get("error") != null) {
            return Optional.of(authenticationParams.get("error") + " : " + authenticationParams.get("error_description"));
        }
        return Optional.empty();
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
        idToken.getAudience().forEach(aud -> {
            if (!aud.getValue().equals(clientId.getValue()))
                throw new RuntimeException(
                        "INVALID AUDIENCE: " + aud.getValue() +
                        " - Stub OIDC Client only trusts audience where the client id is: " + clientId.getValue());
        });

        //TODO - As per 3.1.3.7 - We might need more specific validation to check if there are multiple audiences and if the client trusts them. As per point 3,4 and 5 on 3.1.3.7.a
    }

    private void validateIssuer(IDTokenClaimsSet idToken) {
        //3.1.37 - The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery) MUST exactly match the value of the iss (issuer) Claim.
        Issuer issuer = idToken.getIssuer();
        if (!issuer.getValue().equals("stub-oidc-op")) {
            throw new RuntimeException("Incorrect issuer - Issuer expected: stub-oidc-op but issuer received was: " + issuer.getValue());
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
