package uk.gov.ida.verifystubclient.services;


import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;

import java.net.URI;

public class AuthnRequestService {

    private final RedisService redisService;

    public AuthnRequestService(RedisService redisService) {
        this.redisService = redisService;
    }

    public AuthenticationRequest generateAuthenticationRequest(
            String requestUri,
            ClientID clientID,
            String redirectUri) {
        Scope scope = new Scope("openid");

        State state = new State();
        Nonce nonce = new Nonce();
        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
                URI.create(requestUri),
                new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN),
                scope, clientID, URI.create(redirectUri), state, nonce);

        redisService.set("state::" + state.getValue(), nonce.getValue());
        redisService.incr("nonce::" + nonce.getValue());

        return authenticationRequest;
    }
}
