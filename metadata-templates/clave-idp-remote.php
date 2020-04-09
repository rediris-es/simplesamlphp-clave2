<?php
/**
 * SAML 2.0 eIDAS remote IdP metadata for simpleSAMLphp.
 *
 * All possible options included in this example in comments
 */

//Clave.es Development Environment
$claveMeta['eIDASnode'] = array(
    
    // Unique identifier
    'entityID' => 'https://eidas.node/metadata.php',
    
    
    // Endpoint URL of the SSO service
	'SingleSignOnService'  => 'https://eidas.node/sso.php',

    // Endpoint URL of the SLO service (if not set, 
	// will logout at the bridge and return)
	//'SingleLogoutService'  => 'https://eidas.node/slo.php',
    
    
    //Accept only signed SLO request
    'sign.logout' => true,
    
    //Sign all emmitted redirects
    'redirect.sign' => true,
    
    //Validate all received redirects
    'redirect.validate' => true,
    
    
    //Certificate of the remote IDP [Concatenated Base64 of the PEM]
    //(legacy support parameter, it is added along those found in
    //'keys')
    'certData' => 'MII...zsbzFg==',

    //Certificate(s) of the remote IDP [Concatenated Base64 of the PEM]
    'keys' =>
    array (
        0 =>
        array (
            'encryption' => true,
            'signing' => true,
            'type' => 'X509Certificate',
            'X509Certificate' => 'MII...zsbzFg==',
        ),

        1 =>
        array (
            'encryption' => true,
            'signing' => true,
            'type' => 'X509Certificate',
            'X509Certificate' => 'MIIHsT.../Z6+CT7o=',
        ),              
    ),
    
);
