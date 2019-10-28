package uk.gov.ida.stuboidcclient.services;

import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;

import java.net.URI;

public class AuthnRequestService {

    private final RedisService redisService;

    public AuthnRequestService(RedisService redisService) {
        this.redisService = redisService;
    }

    public AuthenticationRequest generateAuthenticationRequest(
            URI requestUri,
            ClientID clientID,
            URI redirectUri,
            ResponseType responseType) {
        Scope scope = new Scope("openid");

        State state = new State();
        Nonce nonce = new Nonce();
        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
                requestUri,
                responseType,
                scope, clientID, redirectUri, state, nonce);

        redisService.set("state::" + state.getValue(), nonce.getValue());
        redisService.incr("nonce::" + nonce.getValue());

        return authenticationRequest;
    }

    public AuthenticationRequest generateFormPostAuthenticationRequest(
            URI requestUri,
            ClientID clientID,
            URI redirectUri,
            ResponseType responseType) {
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
                .build();

        redisService.set("state::" + state.getValue(), nonce.getValue());
        redisService.incr("nonce::" + nonce.getValue());

        return authenticationRequest;
    }
}
