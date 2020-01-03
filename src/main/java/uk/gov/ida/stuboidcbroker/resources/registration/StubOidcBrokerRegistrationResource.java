package uk.gov.ida.stuboidcbroker.resources.registration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import io.dropwizard.views.View;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.domain.Organisation;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.RedisService;
import uk.gov.ida.stuboidcbroker.services.RegistrationHandlerService;
import uk.gov.ida.stuboidcbroker.services.RegistrationSenderService;
import uk.gov.ida.stuboidcbroker.views.RegistrationView;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Path("/")
public class StubOidcBrokerRegistrationResource {

    private final RegistrationSenderService registrationSenderService;
    private final RegistrationHandlerService registrationHandlerService;
    private final RedisService redisService;
    private final StubOidcBrokerConfiguration configuration;

    public StubOidcBrokerRegistrationResource(RegistrationSenderService registrationSenderService, RegistrationHandlerService registrationHandlerService, RedisService redisService, StubOidcBrokerConfiguration configuration) {
        this.registrationSenderService = registrationSenderService;
        this.registrationHandlerService = registrationHandlerService;
        this.redisService = redisService;
        this.configuration = configuration;
    }

    @GET
    @Path("/")
    public View registrationPage() throws IOException {
        String scheme = configuration.getScheme();
        URI brokerRequestURI = UriBuilder.fromUri(configuration.getDirectoryURI()).path(Urls.Directory.REGISTERED_BROKERS + scheme)
                .build();

        HttpResponse<String> brokersResponse = getOrganisations(brokerRequestURI);
        List<Organisation> brokers = getOrganisationsFromResponse(brokersResponse);

        return new RegistrationView(brokers);
    }

    @POST
    @Path("/sendRegistrationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response sendRegistrationRequest(@FormParam("ssa") String ssa, @FormParam("privateKey") String privateKey, @FormParam("brokerDomain") String brokerDomain) throws JOSEException, java.text.ParseException, IOException {
        // get ssa for this broker from directory
        // get private key for this broker directory
        List<String> orgList = Arrays.asList(brokerDomain.split(","));
        String domain = orgList.get(0).trim();
        String brokerName = orgList.get(1).trim();
        String responseString = registrationSenderService.sendRegistrationRequest(ssa, privateKey, domain, brokerName);

        return Response.ok(responseString).build();
    }

    @POST
    @Path("/register")
    @Produces(MediaType.APPLICATION_JSON)
    public Response register(String requestBody) throws ParseException, com.nimbusds.oauth2.sdk.ParseException {
        JSONObject jwtObject = JSONObjectUtils.parse(requestBody);
        String signedJwt = jwtObject.get("signed-jwt").toString();
        SignedJWT signedJWT = SignedJWT.parse(signedJwt);
        String response = registrationHandlerService.processHTTPRequest(signedJWT);

        return Response.ok(response).build();
    }

    @GET
    @Path("/resetClientID")
    public void clientReset() {
        redisService.delete("CLIENT_ID");
    }

    private List<Organisation> getOrganisationsFromResponse(HttpResponse<String> responseBody) throws IOException {
        JSONParser parser = new JSONParser(JSONParser.MODE_JSON_SIMPLE);
        JSONArray jsonarray;
        try {
            jsonarray = (JSONArray) parser.parse(responseBody.body());
        } catch (net.minidev.json.parser.ParseException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        List<Organisation> orgList = new ArrayList<>();
        for(int i = 0; i < jsonarray.size(); i++) {
            JSONObject obj = (JSONObject) jsonarray.get(i);
            ObjectMapper objectMapper = new ObjectMapper();
            Organisation org = objectMapper.readValue(obj.toJSONString(), Organisation.class);
            orgList.add(org);
        }
        return orgList;
    }

    private HttpResponse<String> getOrganisations(URI uri) {
        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .uri(uri)
                .build();

        try {
            return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
