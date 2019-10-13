package uk.gov.ida.verifystubclient;

import io.dropwizard.Application;
import io.dropwizard.jersey.jackson.JsonProcessingExceptionMapper;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import io.dropwizard.views.ViewBundle;
import uk.gov.ida.verifystubclient.configuration.VerifyStubClientConfiguration;
import uk.gov.ida.verifystubclient.resources.AuthenticationRequestResource;
import uk.gov.ida.verifystubclient.services.ClientService;

public class VerifyStubClientApplication extends Application<VerifyStubClientConfiguration> {

    public static void main(String[] args) throws Exception {
        new VerifyStubClientApplication().run(args);
    }

    @Override
    public void run(VerifyStubClientConfiguration configuration, Environment environment) {
        environment.jersey().register(new AuthenticationRequestResource(configuration, new ClientService(configuration)));
        environment.jersey().register(new JsonProcessingExceptionMapper(true));
    }

    @Override
    public void initialize(final Bootstrap<VerifyStubClientConfiguration> bootstrap) {
        bootstrap.addBundle(new ViewBundle<>());
    }

}
