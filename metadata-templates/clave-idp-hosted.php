<?php
/**
 * SAML 2.0 eIDAS IdP configuration for simpleSAMLphp.
 *
 * All possible options included in this example in comments
 */


$claveMeta['__DYNAMIC:1__'] = array(
    
    //Unique identifier
    'entityID' => 'http://eidas.bridge/metadata.php',
    
    //Auth Source
    'auth' => 'eidas', //This bridges to the eIDAS SP
    
    
    
    //[Mandatory] Dialect of SAML 2.0 to be expected by the IdP (value
    //in remote SP metadata will override this)
    //Possible values: 'stork','eidas'
    'dialect' => 'eidas',
    
    //[Mandatory] Details relative to the specific implementation of
    //the dialect
    //Possible values: 'stork','clave-1.0','eidas','clave-2.0'
    'subdialect' => 'eidas',
    
    
    
    //[Optional] The issuer of the responses to the SP side. In other
    //federations, this would be the metadata URL, but Stork does not
    //give any importance to this field, anyway, could be used
    //properly in the future.  eIDAS sets on the Issuer the IdP
    //metadata URL. If this parameter is not set, that's what will be
    //used
    'issuer' => 'http://eidas.bridge/metadata.php',
    
    
    //[Mandatory] X.509 hosted IdP key and certificate to sign
    //responses back for the SP. Relative to the cert directory.
    'privatekey'  => 'bridge_idp.key',
    'certificate' => 'bridge_idp.crt',
    
    
    //[Optional] Default:false. If true the list of authorised SPs
    //will be taken from the SAML 2.0 metadata file (saml20-sp-remote)
    //instead of using the Clave one (clave-sp-remote). This way, both
    //IdPs can have a shared authorised SP list.
    //'sp.useSaml20Meta' => false,
    
    
    // [Optional] List of the POST parameters that will be forwarded
    // along with the request (if not set, none will be)
    'idp.post.allowed'  => array('RelayState'),
    
    
    // [Optional] Set if the IdP must encrypt the outbound assertions
    // using the SP's certificate (default:false)
    //'assertion.encryption' => true,
    
    
    // [Optional] True if the assertions must be parsed to add the
    // stork extensions or false to keep the assertions as received
    // (not altering any possible existing signature)
    //'assertion.storkize' => false,
    
    
    // [Optional] Key algorithm uri for assertion encryption
    // (default:AES-256)
    //'assertion.encryption.keyAlgorithm' => 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
    
    
    // SP configuration to be loaded (from clave-sp-hosted)
    'hostedSP' => 'eidasSP', // TODO: extinguish from here, it is defined in the authsource and that one should be used
    
);