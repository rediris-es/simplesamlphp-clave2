<?php
/**
 * The IdP class for SAML 2.0 eIDAS Protocol (It is nearly a copy of
 * SimpleSAML_IdP class, as we could not use it due to metadata being
 * hardcoded in the constructor, and could not extend it due to PHP
 * static inheritance characteristics).
 *
 * @author Francisco José Aragó Monzonís, RedIRIS <francisco.arago@externos.rediris.es>
 * @package Clave
 */

use SimpleSAML\Auth\Simple;
use SimpleSAML\Configuration;
use SimpleSAML\Error\Error;
use SimpleSAML\IdP\LogoutHandlerInterface;

class sspmod_clave_IdP
{

    /**
     * A cache for resolving IdP id's.
     *
     * @var array
     */
    private static array $idpCache = array();
    
    
    /**
     * The identifier for this IdP.
     *
     * @var string
     */
    private string $id;
    
    
    /**
     * The configuration for this IdP.
     *
     * @var SimpleSAML\Configuration
     */
    private Configuration $config;


    /**
     * Our authsource.
     *
     * @var SimpleSAML\Auth\Simple
     */
    private Simple $authSource;


    

    /**
     * Retrieve the ID of this IdP.
     *
     * @return string The ID of this IdP.
     */
    public function getId(): string
    {
        return $this->id;
    }
    
    
    
    /**
     * Retrieve the configuration for this IdP.
     *
     * @return SimpleSAML\Configuration The configuration object.
     */
    public function getConfig(): Configuration
    {
        return $this->config;
    }


    /**
     * Retrieve an IdP by ID.
     *
     * @param string $id The identifier of the IdP.
     *
     * @return sspmod_clave_IdP
     * @throws Exception
     */
    public static function getById(string $id): sspmod_clave_IdP
    {
        assert('is_string($id)');

        if (isset(self::$idpCache[$id])) {
            return self::$idpCache[$id];
        }

        $idp = new self($id);
        self::$idpCache[$id] = $idp;
        return $idp;
    }


    /**
     * Retrieve the IdP "owning" the state.
     *
     * @param array &$state The state array.
     *
     * @return sspmod_clave_IdP
     * @throws Exception
     */
    public static function getByState(array &$state): sspmod_clave_IdP
    {
        assert('isset($state["core:IdP"])');

        return self::getById($state['core:IdP']);
    }




    /**
     * Is the current user authenticated?
     *
     * @return boolean True if the user is authenticated, false otherwise.
     */
    public function isAuthenticated(): bool
    {
        return $this->authSource->isAuthenticated();
    }


    /**
     * Initialize an IdP.
     *
     * @param string $id The identifier of this IdP.
     *
     * If the IdP is disabled or no such auth source was found.
     * @throws Exception
     */
    private function __construct(string $id)
    {
        assert('is_string($id)');
        
        $this->id = $id;
        
        //Get the Hosted IdP config
        $this->config = sspmod_clave_Tools::getMetadataSet($id,"clave-idp-hosted");
        SimpleSAML\Logger::debug('Clave Idp hosted metadata: '.print_r($this->config,true));
        
        
        //Get the associated AuthSource (as defined in config, and wrapped in the Simple auth class)
        $auth = $this->config->getString('auth');
        if (SimpleSAML\Auth\Source::getById($auth) !== null) {
            $this->authSource = new SimpleSAML\Auth\Simple($auth);
        } else {
            throw new SimpleSAML\Error\Exception('No such "'.$auth.'" auth source found.');
        }
        
    }


    /**
     * Process authentication requests. Same implementation as
     * base. but need to override as the callback has the base class
     * hardcoded instead of getting the actual instance classname   // TODO: file an issue on this to ssp
     *
     * @param array &$state The authentication request state.
     * @throws \SimpleSAML\Error\Exception
     */
    public function handleAuthenticationRequest(array &$state)
    {
        assert('isset($state["Responder"])');

        SimpleSAML\Logger::debug('------------------STATE at idp.handleauthreq (start): '.print_r($state,true));

        $state['core:IdP'] = $this->id;

        if (isset($state['SPMetadata']['entityid'])) {
            $spEntityId = $state['SPMetadata']['entityid'];
        } elseif (isset($state['SPMetadata']['entityID'])) {
            $spEntityId = $state['SPMetadata']['entityID'];
        } else {
            $spEntityId = null;
        }
        $state['core:SP'] = $spEntityId;

        // first, check whether we need to authenticate the user
        if (isset($state['ForceAuthn']) && (bool) $state['ForceAuthn']) {
            // force authentication is in effect
            $needAuth = true;
        } else {
            $needAuth = !$this->isAuthenticated();
        }
        
        $state['IdPMetadata'] = $this->getConfig()->toArray();
        $state['ReturnCallback'] = array('sspmod_clave_IdP', 'postAuth');  // TODO: when sure it's working, switch for get_class(). Also, try to change it on the ssp code to see if my patch would work

        SimpleSAML\Logger::debug('------------------STATE at idp.handleauthreq (end): '.print_r($state,true));
        
        try {
            if ($needAuth) {
                $this->authenticate($state);
                assert('FALSE');
            } else {
                $this->reauthenticate($state);
            }
            $this->postAuth($state);
        } catch (SimpleSAML\Error\Exception $e) {
            SimpleSAML\Auth\State::throwException($state, $e);
        } catch (Exception $e) {
            $e = new SimpleSAML\Error\UnserializableException($e);
            SimpleSAML\Auth\State::throwException($state, $e);
        }
    }


    /**
     * Called after authproc has run.
     *
     * @param array $state The authentication request state array.
     * @throws Exception
     */
    public static function postAuthProc(array $state)
    {
        assert('is_callable($state["Responder"])');

        if (isset($state['core:SP'])) {
            $session = SimpleSAML\Session::getSessionFromRequest();
            $session->setData(
                'core:idp-ssotime',
                $state['core:IdP'].';'.$state['core:SP'],
                time(),
                SimpleSAML\Session::DATA_TIMEOUT_SESSION_END
            );
        }

        call_user_func($state['Responder'], $state);
        assert('FALSE');
    }


    /**
     * The user is authenticated. TODO: same as above. File for issue, then remove when solved
     *
     * @param array $state The authentication request state array.
     *
     * @throws SimpleSAML\Error\Exception If we are not authenticated.
     * @throws Exception
     */
    public static function postAuth(array $state)
    {
        $idp = sspmod_clave_IdP::getByState($state);   // TODO: when sure it's working, switch for self::. Also, try to change it on the ssp code to see if my patch would work

        if (!$idp->isAuthenticated()) {
            throw new SimpleSAML\Error\Exception('Not authenticated.');
        }

        $state['Attributes'] = $idp->authSource->getAttributes();

        $spMetadata = $state['SPMetadata'] ?? array();

        if (isset($state['core:SP'])) {
            $session = SimpleSAML\Session::getSessionFromRequest();
            $previousSSOTime = $session->getData('core:idp-ssotime', $state['core:IdP'].';'.$state['core:SP']);
            if ($previousSSOTime !== null) {
                $state['PreviousSSOTimestamp'] = $previousSSOTime;
            }
        }

        $idpMetadata = $idp->getConfig()->toArray();

        $pc = new SimpleSAML\Auth\ProcessingChain($idpMetadata, $spMetadata, 'idp');

        $state['ReturnCall'] = array('sspmod_clave_IdP', 'postAuthProc'); // TODO: when sure it's working, switch for get_class(). Also, try to change it on the ssp code to see if my patch would work
        $state['Destination'] = $spMetadata;
        $state['Source'] = $idpMetadata;

        $pc->processState($state);

        self::postAuthProc($state);
    }
    



    /**
     * Authenticate the user.
     *
     * This function authenticates the user.
     *
     * @param array &$state The authentication request state.
     *
     * If we were asked to do passive authentication.
     * @throws Error
     */
    private function authenticate(array &$state)
    {
        if (isset($state['isPassive']) && (bool) $state['isPassive']) {
            throw new Error('Passive authentication not supported.');
        }
        SimpleSAML\Logger::debug('------------------STATE at idp.authenticate: '.print_r($state,true));
        $this->authSource->login($state);
    }

    
    

    /**
     * Re-authenticate the user.
     *
     * This function re-authenticates an user with an existing session. This gives the authentication source a chance
     * to do additional work when re-authenticating for SSO.
     *
     * Note: This function is not used when ForceAuthn=true.
     *
     * @param array &$state The authentication request state.
     *
     * @throws SimpleSAML\Error\Exception If there is no auth source defined for this IdP.
     */
    private function reauthenticate(array &$state)
    {
        $sourceImpl = $this->authSource->getAuthSource();
        if ($sourceImpl == NULL) {
            throw new SimpleSAML\Error\Exception('No such auth source defined.');
        }

        $sourceImpl->reauthenticate($state);
    }


    
    // TODO: We override them to mark that eIDAS implements no
    // logout. Clave in Spain does, so later port the logout mechanism
    // here (remember it was non-standard, see whether it fits, clave2
    // will fit) by removing the overrides and implementing the needed
    // functions on the specific clave class (see the implementations
    // of these functions on the base class for reference on it). For
    // the eIDAS specific class, just move there the exception (or
    // maybe it will be better to implement a transparent empty
    // function, to allow for future multi-protocol logout support).
    
    
    /**
     * Find the logout handler of this IdP.
     *
     * @return LogoutHandlerInterface The logout handler class.
     *
     * @throws SimpleSAML\Error\Exception If we cannot find a logout handler.
     */
    public function getLogoutHandler(): LogoutHandlerInterface
    {
        throw new SimpleSAML\Error\Exception('Logout not supported in eIDAS.');
    }


    /**
     * Finish the logout operation.
     *
     * This function will never return.
     *
     * @param array &$state The logout request state.
     * @throws \SimpleSAML\Error\Exception
     */
    public function finishLogout(array &$state)
    {
        throw new SimpleSAML\Error\Exception('Logout not supported in eIDAS.');
    }


    /**
     * Process a logout request.
     *
     * This function will never return.
     *
     * @param array       &$state The logout request state.
     * @param string|null $assocId The association we received the logout request from, or null if there was no
     * association.
     * @throws \SimpleSAML\Error\Exception
     */
    public function handleLogoutRequest(array &$state, ?string $assocId)
    {
        throw new SimpleSAML\Error\Exception('Logout not supported in eIDAS.');
    }


    /**
     * Process a logout response.
     *
     * This function will never return.
     *
     * @param string $assocId The association that is terminated.
     * @param string|null $relayState The RelayState from the start of the logout.
     * @param SimpleSAML\Error\Exception|null $error The error that occurred during session termination (if any).
     * @throws \SimpleSAML\Error\Exception
     */
    public function handleLogoutResponse(string $assocId, ?string $relayState, SimpleSAML\Error\Exception $error = null)
    {
        throw new SimpleSAML\Error\Exception('Logout not supported in eIDAS.');
    }


    /**
     * Log out, then redirect to a URL.
     *
     * This function never returns.
     *
     * @param string $url The URL the user should be returned to after logout.
     * @throws \SimpleSAML\Error\Exception
     */
    public function doLogoutRedirect($url)
    {
        throw new SimpleSAML\Error\Exception('Logout not supported in eIDAS.');
    }


    /**
     * Redirect to a URL after logout.
     *
     * This function never returns.
     *
     * @param sspmod_clave_IdP $idp Deprecated. Will be removed.
     * @param array          &$state The logout state from doLogoutRedirect().
     * @throws \SimpleSAML\Error\Exception
     */
    public static function finishLogoutRedirect(sspmod_clave_IdP $idp, array $state)
    {
        throw new SimpleSAML\Error\Exception('Logout not supported in eIDAS.');
    }
    
    
}

