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
import uk.gov.ida.stuboidcbroker.resources.oidcclient.AuthorizationResponseClientResource;
import uk.gov.ida.stuboidcbroker.resources.oidcclient.IdpClientResource;
import uk.gov.ida.stuboidcbroker.resources.oidcprovider.AuthorizationResponseProviderResource;
import uk.gov.ida.stuboidcbroker.resources.oidcprovider.RegistrationHandlerResource;
import uk.gov.ida.stuboidcbroker.resources.oidcclient.AuthorizationRequestClientResource;
import uk.gov.ida.stuboidcbroker.resources.oidcclient.PickerPageResource;
import uk.gov.ida.stuboidcbroker.resources.oidcclient.RegistrationRequestResource;
import uk.gov.ida.stuboidcbroker.resources.oidcclient.StubOidcBrokerResource;
import uk.gov.ida.stuboidcbroker.resources.oidcprovider.AuthorizationRequestProviderResource;
import uk.gov.ida.stuboidcbroker.resources.oidcprovider.TokenResource;
import uk.gov.ida.stuboidcbroker.resources.oidcprovider.UserInfoResource;
import uk.gov.ida.stuboidcbroker.services.oidcclient.AuthnRequestGeneratorService;
import uk.gov.ida.stuboidcbroker.services.oidcprovider.AuthnRequestValidationService;
import uk.gov.ida.stuboidcbroker.services.oidcclient.AuthnResponseValidationService;
import uk.gov.ida.stuboidcbroker.services.oidcprovider.AuthnResponseGeneratorService;
import uk.gov.ida.stuboidcbroker.services.oidcprovider.RegistrationHandlerService;
import uk.gov.ida.stuboidcbroker.services.oidcclient.RegistrationRequestService;
import uk.gov.ida.stuboidcbroker.services.oidcprovider.TokenHandlerService;
import uk.gov.ida.stuboidcbroker.services.oidcclient.TokenRequestService;
import uk.gov.ida.stuboidcbroker.services.oidcprovider.UserInfoService;
import uk.gov.ida.stuboidcbroker.services.shared.PickerService;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;

public class StubOidcBrokerApplication extends Application<StubOidcBrokerConfiguration> {

    public static void main(String[] args) throws Exception {
        new StubOidcBrokerApplication().run(args);
    }

    @Override
    public void run(StubOidcBrokerConfiguration configuration, Environment environment) {
        RedisService redisService = new RedisService(configuration);

        registerResources(environment, configuration, redisService);
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

    private void registerResources(Environment environment, StubOidcBrokerConfiguration configuration, RedisService redisService) {
        TokenHandlerService tokenHandlerService = new TokenHandlerService(redisService, configuration);
        PickerService pickerService = new PickerService(configuration, redisService);
        RegistrationHandlerService registrationHandlerService = new RegistrationHandlerService(redisService, configuration);
        AuthnRequestValidationService authnRequestValidationService = new AuthnRequestValidationService(redisService);
        AuthnResponseGeneratorService authnResponseGeneratorService = new AuthnResponseGeneratorService(tokenHandlerService, redisService);
        TokenRequestService tokenRequestService = new TokenRequestService(configuration, redisService);
        AuthnRequestGeneratorService authnRequestGeneratorService = new AuthnRequestGeneratorService(redisService);
        AuthnResponseValidationService authResponseService = new AuthnResponseValidationService(tokenRequestService);
        RegistrationRequestService registrationRequestService = new RegistrationRequestService(redisService, configuration);
        UserInfoService userInfoService = new UserInfoService(configuration, tokenRequestService, authResponseService, redisService);

        environment.jersey().register(new StubOidcBrokerResource(configuration, tokenRequestService, authnRequestGeneratorService, authResponseService, redisService));
        environment.jersey().register(new AuthorizationRequestClientResource( authnRequestGeneratorService));
        environment.jersey().register(new JsonProcessingExceptionMapper(true));
        environment.jersey().register(new RegistrationRequestResource(registrationRequestService, redisService, configuration));
        environment.jersey().register(new PickerPageResource(redisService, pickerService));
        environment.jersey().register(new AuthorizationResponseClientResource(authResponseService, redisService, authnResponseGeneratorService, pickerService, userInfoService));
        environment.jersey().register(new IdpClientResource(redisService, configuration));
        environment.jersey().register(new TokenResource(tokenHandlerService, configuration));
        environment.jersey().register(new UserInfoResource(tokenHandlerService, redisService, authResponseService, tokenRequestService, userInfoService));
        environment.jersey().register(new AuthorizationResponseProviderResource(authnResponseGeneratorService));
        environment.jersey().register(new AuthorizationRequestProviderResource(authnRequestValidationService, configuration, redisService, pickerService));
        environment.jersey().register(new RegistrationHandlerResource(registrationHandlerService, configuration));
    }
}
