package uk.gov.ida.stuboidcbroker.services.oidcclient;

import com.google.common.base.Predicate;
import com.google.common.collect.Maps;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import org.checkerframework.checker.nullness.compatqual.NullableDecl;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static uk.gov.ida.stuboidcbroker.services.shared.QueryParameterHelper.splitQuery;

public class AuthnRequestGeneratorService {

    private final RedisService redisService;

    public AuthnRequestGeneratorService(RedisService redisService) {
        this.redisService = redisService;
    }

    public AuthenticationRequest generateIdentityAuthenticationRequest(
            URI requestUri,
            ClientID clientID,
            URI redirectUri,
            ResponseType responseType,
            String transactionID) {
        Scope scope = new Scope("openid");

        State state = new State();
        Nonce nonce = new Nonce();

        AuthenticationRequest authenticationRequest = new AuthenticationRequest.Builder(
                responseType,
                scope, clientID, redirectUri)
                .responseMode(ResponseMode.FORM_POST)
                .endpointURI(requestUri)
                .state(state)
                .nonce(nonce)
                .claims(getRequestedClaimsForIdentity(transactionID))
                .customParameter("transaction-id", transactionID)
                .build();

        redisService.set("state::" + state.getValue(), nonce.getValue());
        redisService.incr("nonce::" + nonce.getValue());

        return authenticationRequest;
    }


    public void storeBrokerNameAndDomain(String transactionID, String brokerName, String brokerDomain) {
        redisService.set(transactionID + "-brokername", brokerName);
        redisService.set(transactionID + "-brokerdomain", brokerDomain);
    }


    public ClientID getClientIDByBrokerName(String brokerName) {
        String client_id = redisService.get(brokerName);
        if (client_id != null) {
            return new ClientID(client_id);
        } else {
            throw new RuntimeException("No client ID exists");
        }
    }

    private ClaimsRequest getRequestedClaimsForIdentity(String transactionId) {
        try {
        String claimsQueryJson = redisService.get(transactionId + "claims");
        ClaimsRequest cr = ClaimsRequest.parse(claimsQueryJson);
        Set<String> userInfoClaims = cr.getUserInfoClaimNames(false);
        for (String userInfoClaim : userInfoClaims) {
            boolean isIdentityClaim = Arrays.asList(IDENTITY_CLAIMS).contains(userInfoClaim);
            if (!isIdentityClaim) {
                cr.removeUserInfoClaims(userInfoClaim);
            }
        }
        return cr;
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    public static String[] IDENTITY_CLAIMS = new String[] {
        "name",
        "family_name",
        "given_name",
        "middle_name",
        "gender",
        "birthday"
    };

    private String getRequestedClaims(String transactionId){
        String claims = redisService.get(transactionId + "claims");
        // this is a hack, it should ideally cast/translate into ClaimsRequest object
        return claims;
    }
}
