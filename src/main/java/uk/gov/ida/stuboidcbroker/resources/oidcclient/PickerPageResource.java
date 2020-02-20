package uk.gov.ida.stuboidcbroker.resources.oidcclient;

import com.nimbusds.oauth2.sdk.id.ClientID;
import io.dropwizard.views.View;
import uk.gov.ida.stuboidcbroker.services.shared.PickerService;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;
import uk.gov.ida.stuboidcbroker.views.PickerView;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.UriBuilder;
import java.net.URI;

@Path("/")
public class PickerPageResource {
    private final RedisService redisService;
    private final PickerService pickerService;

    public PickerPageResource(RedisService redisService, PickerService pickerService) {
        this.redisService = redisService;
        this.pickerService = pickerService;
    }

    @GET
    @Path("/picker")
    public View pickerPage(@QueryParam("response-uri") String rpURI) {

        String transactionId = new ClientID().toString();
        URI rpResponseURI = UriBuilder.fromUri(rpURI).build();
        storeRpResponseUri(transactionId + "response-uri", rpResponseURI.toString());

        PickerView pickerView = pickerService.generatePickerPageView(transactionId);

        return pickerView;
    }

    private void storeRpResponseUri(String transactionID, String rpResponsePath) {
        redisService.set(transactionID, rpResponsePath);
    }
}
