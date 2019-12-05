package uk.gov.ida.stuboidcbroker;

import io.dropwizard.Application;
import io.dropwizard.assets.AssetsBundle;
import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.jersey.jackson.JsonProcessingExceptionMapper;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import io.dropwizard.views.ViewBundle;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.resources.request.StubOidcBrokerFormPostResource;
import uk.gov.ida.stuboidcbroker.resources.StubOidcBrokerPickerResource;
import uk.gov.ida.stuboidcbroker.resources.registration.StubOidcBrokerRegistrationResource;
import uk.gov.ida.stuboidcbroker.resources.request.StubOidcBrokerResource;
import uk.gov.ida.stuboidcbroker.services.AuthnRequestService;
import uk.gov.ida.stuboidcbroker.services.AuthnResponseService;
import uk.gov.ida.stuboidcbroker.services.RegistrationHandlerService;
import uk.gov.ida.stuboidcbroker.services.RegistrationSenderService;
import uk.gov.ida.stuboidcbroker.services.TokenRequestService;
import uk.gov.ida.stuboidcbroker.services.RedisService;

public class StubOidcBrokerApplication extends Application<StubOidcBrokerConfiguration> {

    public static void main(String[] args) throws Exception {
        new StubOidcBrokerApplication().run(args);
    }

    @Override
    public void run(StubOidcBrokerConfiguration configuration, Environment environment) {
        RedisService redisService = new RedisService(configuration);

        TokenRequestService tokenRequestService = new TokenRequestService(configuration, redisService);
        AuthnRequestService authnRequestService = new AuthnRequestService(redisService);
        AuthnResponseService authResponseService = new AuthnResponseService(tokenRequestService);
        RegistrationSenderService registrationSenderService = new RegistrationSenderService(redisService, configuration);
        RegistrationHandlerService registrationHandlerService = new RegistrationHandlerService(redisService, configuration);


        environment.jersey().register(new StubOidcBrokerResource(configuration, tokenRequestService, authnRequestService, authResponseService, redisService));
        environment.jersey().register(new StubOidcBrokerFormPostResource(configuration, tokenRequestService, authnRequestService, authResponseService, redisService));
        environment.jersey().register(new JsonProcessingExceptionMapper(true));
        environment.jersey().register(new StubOidcBrokerRegistrationResource(registrationSenderService, redisService));
        environment.jersey().register(new StubOidcBrokerPickerResource(configuration));
    }

    @Override
    public void initialize(final Bootstrap<StubOidcBrokerConfiguration> bootstrap) {
        bootstrap.addBundle(new ViewBundle<>());
        bootstrap.addBundle(new AssetsBundle("/stylesheets", "/stylesheets", null, "css"));
        bootstrap.addBundle(new AssetsBundle("/javascript", "/javascript", null, "js"));
        bootstrap.addBundle(new AssetsBundle("/assets/fonts", "/assets/fonts", null, "fonts"));
        bootstrap.addBundle(new AssetsBundle("/assets/images", "/assets/images", null, "images"));
        bootstrap.setConfigurationSourceProvider(
                new SubstitutingSourceProvider(
                        bootstrap.getConfigurationSourceProvider(),
                        new EnvironmentVariableSubstitutor(false)));
    }

}
