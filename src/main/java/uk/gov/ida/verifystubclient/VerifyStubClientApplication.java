package uk.gov.ida.verifystubclient;

import io.dropwizard.Application;
import io.dropwizard.jersey.jackson.JsonProcessingExceptionMapper;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import io.dropwizard.views.ViewBundle;
import uk.gov.ida.verifystubclient.configuration.VerifyStubClientConfiguration;
import uk.gov.ida.verifystubclient.resources.StubClientFormPostResource;
import uk.gov.ida.verifystubclient.resources.StubClientResource;
import uk.gov.ida.verifystubclient.services.AuthnRequestService;
import uk.gov.ida.verifystubclient.services.AuthnResponseService;
import uk.gov.ida.verifystubclient.services.TokenService;
import uk.gov.ida.verifystubclient.services.RedisService;

public class VerifyStubClientApplication extends Application<VerifyStubClientConfiguration> {

    public static void main(String[] args) throws Exception {
        new VerifyStubClientApplication().run(args);
    }

    @Override
    public void run(VerifyStubClientConfiguration configuration, Environment environment) {
        RedisService redisService = new RedisService(configuration);

        TokenService tokenService = new TokenService(configuration, redisService);
        AuthnRequestService authnRequestService = new AuthnRequestService(redisService);
        AuthnResponseService authResponseService = new AuthnResponseService(tokenService);

        environment.jersey().register(new StubClientResource(configuration, tokenService, authnRequestService, authResponseService));
        environment.jersey().register(new StubClientFormPostResource(configuration, tokenService, authnRequestService, authResponseService));
        environment.jersey().register(new JsonProcessingExceptionMapper(true));
    }

    @Override
    public void initialize(final Bootstrap<VerifyStubClientConfiguration> bootstrap) {
        bootstrap.addBundle(new ViewBundle<>());
    }

}
