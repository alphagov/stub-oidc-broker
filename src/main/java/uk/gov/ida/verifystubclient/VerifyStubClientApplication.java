package uk.gov.ida.verifystubclient;

import com.nimbusds.oauth2.sdk.id.ClientID;
import io.dropwizard.Application;
import io.dropwizard.jersey.jackson.JsonProcessingExceptionMapper;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import io.dropwizard.views.ViewBundle;
import uk.gov.ida.verifystubclient.configuration.VerifyStubClientConfiguration;
import uk.gov.ida.verifystubclient.resources.AuthenticationRequestResource;
import uk.gov.ida.verifystubclient.services.ClientService;
import uk.gov.ida.verifystubclient.services.RedisService;

public class VerifyStubClientApplication extends Application<VerifyStubClientConfiguration> {

    public static void main(String[] args) throws Exception {
        new VerifyStubClientApplication().run(args);
    }

    @Override
    public void run(VerifyStubClientConfiguration configuration, Environment environment) {
        RedisService redisService = new RedisService(configuration);

        environment.jersey().register(new AuthenticationRequestResource(configuration, new ClientService(configuration, redisService)));
        environment.jersey().register(new JsonProcessingExceptionMapper(true));
    }

    @Override
    public void initialize(final Bootstrap<VerifyStubClientConfiguration> bootstrap) {
        bootstrap.addBundle(new ViewBundle<>());
    }

}
