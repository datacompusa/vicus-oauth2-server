<?php

namespace OAuth2Server\Vicus;

use OAuth2Server\ScopeManager;
use OAuth2Server\SessionManager;
use OAuth2Server\ClientManager;
use OAuth2\AuthServer;
use OAuth2\ResourceServer;
use OAuth2\Grant\Password as PasswordGrantType;
use OAuth2\Grant\AuthCode as AuthCodeGrantType;
use OAuth2\Grant\ClientCredentials as ClientCredentialsGrantType;
use OAuth2\Grant\RefreshToken as RefreshTokenGrantType;
use Pimple\Container;
use Datacomp\Vicus\ServiceProviderInterface;
use \RuntimeException;

class OAuth2ServiceProvider implements ServiceProviderInterface
{
    /**
     * Registers services on the given app.
     *
     * This method should only be used to configure services and parameters.
     * It should not get services.
     *
     * @param Application $container An Application instance
     * @throws RuntimeException if options are invalid.
     */
    public function register(Container $container)
    {
        $container['oauth2.session_manager'] = function() use ($container) {
            return new SessionManager($container['db']);
        };

        $container['oauth2.client_manager'] = function() use ($container) {
            return new ClientManager($container['db']);
        };

        $container['oauth2.scope_manager'] = $function() use ($container) {
            return new ScopeManager($container['db']);
        };

        $container['oauth2.resource_server'] = function() use ($container) {
            return new ResourceServer($container['oauth2.session_manager']);
        };

        $container['oauth2.auth_server'] = function() use ($container) {
            $authServer = new AuthServer($container['oauth2.client_manager'], $container['oauth2.session_manager'], $container['oauth2.scope_manager']);

            $options = isset($container['oauth2.options']) ? $container['oauth2.options'] : array();

            if (array_key_exists('access_token_ttl', $options)) {
                $authServer->setExpiresIn($options['access_token_ttl']);
            }

            // Configure grant types.
            if (array_key_exists('grant_types', $options) && is_array($options['grant_types'])) {
                foreach ($container['oauth2.options']['grant_types'] as $type) {
                    switch ($type) {
                        case 'authorization_code':
                            $authServer->addGrantType(new AuthCodeGrantType());
                            break;
                        case 'client_credentials':
                            $authServer->addGrantType(new ClientCredentialsGrantType());
                            break;
                        case 'password':
                            if (!is_callable($options['password_verify_callback'])) {
                                throw new RuntimeException('To use the OAuth2 "password" grant type, the "password_verify_callback" option must be set to a callback function.');
                            }
                            $grantType = new PasswordGrantType();
                            $grantType->setVerifyCredentialsCallback($options['password_verify_callback']);
                            $authServer->addGrantType($grantType);
                            break;
                        case 'refresh_token':
                            $authServer->addGrantType(new RefreshTokenGrantType());
                            break;
                        default:
                            throw new RuntimeException('Invalid grant type "' . $type . '" specified in oauth2.options.');
                    }
                }
            }

            return $authServer;
        };

    }

    /**
     * Bootstraps the application.
     *
     * This method is called after all services are registered
     * and should be used for "dynamic" configuration (whenever
     * a service must be requested).
     */
    public function boot(Container $container)
    {
    }

}
