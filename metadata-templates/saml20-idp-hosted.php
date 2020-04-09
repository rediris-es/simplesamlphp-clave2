<?php
/**
 * SAML 2.0 IdP configuration for simpleSAMLphp.
 *
 * See: https://simplesamlphp.org/docs/stable/simplesamlphp-reference-idp-hosted
 */

$metadata['__DYNAMIC:1__'] = array(
	/*
	 * The hostname of the server (VHOST) that will use this SAML entity.
	 *
	 * Can be '__DEFAULT__', to use this entry by default.
	 */
	'host' => '__DEFAULT__',

    /* X.509 key and certificate. Relative to the cert directory. */
    //   'privatekey' => 'server.key',
    //   'certificate' => 'server.crt',
    'privatekey'  => 'eIDAS_Bridge.key',
    'certificate' => 'eIDAS_Bridge.crt',

    
    /*                                                                 
     * Authentication source to use. Must be one that is configured in
     * 'config/authsources.php'.                                          
     */
    'auth' => 'eidas', //This bridges to the eIDAS SP
    
    'saml20.sign.response'  => true,
    'saml20.sign.assertion' => true,
    'redirect.sign'         => true,
    'redirect.validate'     => true,
    
    // eIDAS specification requires assertions to be encrypted. This value 
	// is overriden by the same parameter in the specific remote sp 
	// metadata object.
    'assertion.encryption' => true,
    
);
