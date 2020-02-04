package uk.gov.ida.stuboidcbroker.resources.oidcclient;

import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import io.dropwizard.views.View;
import org.apache.http.HttpStatus;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;
import uk.gov.ida.stuboidcbroker.views.RPResponseView;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.List;

@Path("/formPost")
public class IdpClientResource {

    private final RedisService redisService;
    private final StubOidcBrokerConfiguration configuration;

    public IdpClientResource(RedisService redisService, StubOidcBrokerConfiguration configuration) {
        this.redisService = redisService;
        this.configuration = configuration;
    }

    @POST
    @Path("/idpAuthenticationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response sendIdpAuthenticationRequest(@FormParam("idpDomain") String domain, @FormParam("transactionID") String transactionID) {
        List<String> orgList = Arrays.asList(domain.split(","));
        String idpDomain = orgList.get(0);
        String idpName = orgList.get(1);

        String redirectPath;

        if (redisService.get(transactionID + "response-uri") != null) {
            redirectPath = Urls.StubBrokerClient.IDP_RESPONSE;
        } else {
            redirectPath = Urls.StubBrokerClient.RESPONSE_FOR_BROKER;
        }
        URI idpUri = UriBuilder.fromUri(idpDomain).path(Urls.IDP.AUTHENTICATION_URI)
                .queryParam("transaction-id", transactionID)
                .queryParam("redirect-path", redirectPath)
                .build();

        return Response
                .status(302)
                .location(idpUri)
                .build();
    }

    @GET
    @Path("/idpAuthenticationResponse")
    @Produces(MediaType.TEXT_HTML)
    public View handAuthenticationResponse(@QueryParam("transaction-id") String transactionID) {
        String rpUri = redisService.get(transactionID + "response-uri");
        String verifiableCredential = getVerifiableCredential(new BearerAccessToken());

        URI rpUriDomain = UriBuilder.fromUri(rpUri).build();

        return new RPResponseView(rpUriDomain, verifiableCredential, Integer.toString(HttpStatus.SC_OK));
    }

    public String getVerifiableCredential(AccessToken accessToken) {

        URI userInfoURI = UriBuilder.fromUri(configuration.getIdpURI())
                .path(Urls.IDP.CREDENTIAL_URI).build();

        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .header("Authorization", accessToken.toAuthorizationHeader())
                .uri(userInfoURI)
                .build();

        HttpResponse<String> responseBody;
        try {

            responseBody = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
        return responseBody.body();
    }
}
