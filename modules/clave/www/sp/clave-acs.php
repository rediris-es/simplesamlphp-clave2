<?php

/**
 * Assertion consumer service handler for clave authentication source SP
 *
 */


SimpleSAML_Logger::info('eIDAS - SP.ACS: Accessing SAML 2.0 - eIDAS SP Assertion Consumer Service');


// Get the ID of the AuthSource from the queried URL
if (!array_key_exists('PATH_INFO', $_SERVER)) {
    throw new SimpleSAML_Error_BadRequest('Missing authentication source ID in assertion consumer service URL');
}
$sourceId = substr($_SERVER['PATH_INFO'], 1);
$source = SimpleSAML_Auth_Source::getById($sourceId, 'sspmod_clave_Auth_Source_SP');


//Get the AuthSource config
$metadata = $source->getMetadata();
SimpleSAML_Logger::debug('Metadata on acs:'.print_r($metadata,true));


//Get the hosted SP metadata
$hostedSP = $metadata->getString('hostedSP', NULL);
if($hostedSP == NULL)
    throw new SimpleSAML_Error_Exception("'hosted SP' parameter not found in $sourceId Auth Source configuration.");
$spMetadata = sspmod_clave_Tools::getMetadataSet($hostedSP,"clave-sp-hosted");
SimpleSAML_Logger::debug('Clave SP hosted metadata: '.print_r($spMetadata,true));


//Get remote IdP metadata
$remoteIdPMeta = $source->getIdPMetadata("");




//Get the dialect mode the hosted SP must expect
$SPdialect    = $spMetadata->getString('dialect');
$SPsubdialect = $spMetadata->getString('subdialect');




//Receive SAML Response
if(!isset($_REQUEST['SAMLResponse']))
   	throw new SimpleSAML_Error_BadRequest('No SAMLResponse POST param received.');

$resp = base64_decode($_REQUEST['SAMLResponse']);
SimpleSAML_Logger::debug("Received response: ".$resp);



//Here we will accumulate the attributes to be returned to the remote SP
$attributes = array();





//Process the response
$eidas = new sspmod_clave_SPlib();

if ($SPdialect === 'eidas')
    $eidas->setEidasMode();


//Get the ID of the request that triggered this response
$id = $eidas->getInResponseToFromReq($resp);


//Load the stored state associated with this request
$state = SimpleSAML_Auth_State::loadState($id, 'clave:sp:req');
SimpleSAML_Logger::debug('State on ACS:'.print_r($state,true));



//Check that the indicated AuthSource matches the one sotred in the
//state associated to the request
assert('array_key_exists("clave:sp:AuthId", $state)');
if ($state['clave:sp:AuthId'] !== $sourceId) {
    throw new SimpleSAML_Error_Exception(
        'The authentication source id in the URL does not match the authentication source which sent the request '//.' !== '.$sourceId.print_r($state,true)//.'
    );
}




//List of POST parameters coming in the response that we will forward or turn into attributes (depending on the hosted IdP protocol)
$allowedRespPostParams = $spMetadata->getArray('sp.post.allowed', array());

//Check if the additionally accepted POST params must be trasferred as
//such in the state or as attributes (so they are processed by the
//SAML2Int IdP)
if($state['idp:postParams:mode'] == 'forward'){
    
    //Get allowed post params to be forwarded to the SP
    $forwardedParams = array();
    foreach ($_POST as $name => $value){
        if(in_array($name,$allowedRespPostParams))
            $forwardedParams[$name] = $value;
    }
    $state['idp:postParams'] = $forwardedParams;
    
}else{
    //Add additional post params as attributes on the response (it is
    //expected that these params will be promoted to attrs in the future)
    foreach ($_POST as $name => $value){
        if(in_array($name,$allowedRespPostParams))
            $attributes[$name] = $value;
    }
}




//Which are the possible Issuers of the received response
// * Warning! issuer is variable when authenticating on stork (they put
// * the country code of origin of the citizen in there). Also in Clave,
// * it includes the chosen IdP
$expectedIssuers = NULL;


//Add the certificate(s) of the remote IdP to validate the signature and (possibly) decrypt the assertion
//We support the old single entry, and also the new list of certificates
$keys = $remoteIdPMeta->getArray('keys',NULL);
if($keys !== NULL){
    foreach($keys as $key){
        //Here we should be selecting signature/encryption certs, but
        //as the library uses the same ones for both purposes, we just
        //ignore this check.
        if(!$key['X509Certificate'] || $key['X509Certificate'] == "")
            continue;
        
        $eidas->addTrustedCert($key['X509Certificate']);
    }
}

$certData = $remoteIdPMeta->getString('certData', NULL);
if($certData !== NULL){
    SimpleSAML_Logger::debug("Remote IdP Certificate as stored in the metadata (legacy parameter): ".$certData);
    $eidas->addTrustedCert($certData);
}






$eidas->setValidationContext($id,
                             $state['clave:sp:returnPage'],
                             $expectedIssuers,
                             $state['clave:sp:mandatoryAttrs']);

//Expect encrypted assertions and try to decrypt them with the SP
//private key, also, don't ignore any existing plain assertion (this
//may change in the future)
$spkeypem  = sspmod_clave_Tools::readCertKeyFile($spMetadata->getString('privatekey', NULL));
$expectEncrypted = $spMetadata->getBoolean('assertions.encrypted', true);
$onlyEncrypted   = $spMetadata->getBoolean('assertions.encrypted.only', false);

$eidas->setDecipherParams($spkeypem,$expectEncrypted,$onlyEncrypted);
//SimpleSAML_Logger::debug("Private Key loaded from hosted SP metadata: ".$spkeypem);



//Validate the response
$eidas->validateStorkResponse($resp);



//Authentication was successful
$statusInfo = "";
if($eidas->isSuccess($statusInfo)){
    SimpleSAML_Logger::info("Authentication Successful");

    //TODO: this in only specific for clave 1.0 maybe for clave-2.0 keep an eye and add it
    if($SPsubdialect === "clave-1.0"){
        //Add the Issuer as an attribute (as it tells which idpp was used)
        SimpleSAML_Logger::debug('Adding issuer as attribute usedIdP:'.$eidas->getRespIssuer());
        $attributes['usedIdP'] = array($eidas->getRespIssuer());
    }
    
    
    
    //Add to the returned attributes, the attributes that came on the response
    $attributes = array_merge($attributes, $eidas->getAttributes());
    
    
    
    //Log for statistics: received successful Response from remote clave IdP
    $statsData = array(
        'spEntityID' => $spMetadata->getString('entityid', NULL),
        'idpEntityID' => $eidas->getRespIssuer(),
        'protocol' => 'saml2-'.$SPdialect,
    );
    if (isset($state['saml:AuthnRequestReceivedAt'])) {
        $statsData['logintime'] = microtime(TRUE) - $state['saml:AuthnRequestReceivedAt'];
    }
    SimpleSAML_Stats::log('clave:sp:Response', $statsData);
    

    //Data needed to process the response // TODO: this is specific for this AuthSource. Harmonise with the others, so I can support standard SAML authsource (or offer two ways and try both of them)
    
    //SAML standard return state values
    
    if(isset($_POST['RelayState']))
        $state['saml:RelayState'] = $_POST['RelayState'];
    
    $state['AuthnInstant'] = $eidas->getAuthnInstant();
    $state['saml:Binding'] = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    $state['saml:AuthnContextClassRef'] =  $eidas->getAuthnContextClassRef();
    
    
    //Set the nameID of the response
    $nameID = $eidas->getRespNameID();
    if($nameID !== null && $nameID !== '')
        $state['saml:sp:NameID'] = $nameID;

    //Set the nameIDFormat
    $nameIDFormat = $eidas->getRespNameIDFormat();
    if($nameIDFormat !== null && $nameIDFormat !== '')
        $state['saml:NameIDFormat'] = $nameIDFormat;
    


    //eIDAS specific
    $state['eidas:attr:names']     = $eidas->getAttributeNames(); //Gets a dict of friendlyNames - Names
    $state['eidas:raw:assertions'] =  $eidas->getRawAssertions();
    $state['eidas:raw:status']     =  $eidas->generateStatus($statusInfo);
    $state['eidas:status']         =  array(
        'MainStatusCode' => $statusInfo['MainStatusCode'],
        'SecondaryStatusCode' => $statusInfo['SecondaryStatusCode'],
        'StatusMessage' => $statusInfo['StatusMessage'],
    );
    
    
    //Pass the response state to the WebSSO SP
    $source->handleResponse($state, $remoteIdPMeta->getString('entityID', NULL), $attributes);
}





//Else, it was an Authentication Error


//Build the Response Status to be returned in the state (and in case of error)
if($statusInfo['MainStatusCode'] == sspmod_clave_SPlib::ATST_NOTAVAIL){
    //For some reason, Clave may not return a main status code. In that case, we set responder error // TODO: make this conditional to the dialect?
    $statusInfo['MainStatusCode'] = sspmod_clave_SPlib::ST_RESPONDER;
}



//Log for statistics: received failed Response from remote clave IdP
$statsData = array(
    'spEntityID' => $spMetadata->getString('entityid', NULL),
    'idpEntityID' => $eidas->getRespIssuer(),
    'protocol' => 'saml2-'.$SPdialect,
    'error' => array(
        'Code' => $statusInfo['MainStatusCode'],
        'SubCode' => $statusInfo['SecondaryStatusCode'],
        'Message' => $statusInfo['StatusMessage'],
    ),
);
if (isset($state['saml:AuthnRequestReceivedAt'])) {
    $statsData['logintime'] = microtime(TRUE) - $state['saml:AuthnRequestReceivedAt'];
}
SimpleSAML_Stats::log('clave:sp:Response:error', $statsData);




//Forward the Clave IdP error to our remote SP.
SimpleSAML_Auth_State::throwException($state,
                                      new sspmod_saml_Error($statusInfo['MainStatusCode'],
                                                            $statusInfo['SecondaryStatusCode'],
                                                            $statusInfo['StatusMessage']));


assert('FALSE');
