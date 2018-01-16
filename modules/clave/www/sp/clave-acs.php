<?php

/**
 * Assertion consumer service handler for clave authentication source SP
 *
 */

//Some Clave specific stuff
$expectedAdditionalPostParams = array('isLegalPerson', 'oid');


$returnedAttributes = array();


SimpleSAML_Logger::info('Call to Clave auth source acs');


// Get the Id of the authsource
$sourceId = substr($_SERVER['PATH_INFO'], 1);
$source = SimpleSAML_Auth_Source::getById($sourceId, 'sspmod_clave_Auth_Source_SP');

//Get the metadata for the soliciting SP
$spMetadata = $source->getMetadata();
SimpleSAML_Logger::debug('Metadata on acs:'.print_r($spMetadata,true));


//Hosted SP config
$hostedSP = $spMetadata->getString('hostedSP', NULL);
if($hostedSP == NULL)
    throw new SimpleSAML_Error_Exception("No clave hosted SP configuration defined in clave auth source configuration.");
$hostedSPmeta = sspmod_clave_Tools::getMetadataSet($hostedSP,"clave-sp-hosted");
SimpleSAML_Logger::debug('Clave SP hosted metadata: '.print_r($hostedSPmeta,true));

$spEntityId = $hostedSPmeta->getString('entityid', NULL);


if(!isset($_REQUEST['SAMLResponse']))
   	throw new SimpleSAML_Error_BadRequest('No SAMLResponse POST param received.');

$resp = base64_decode($_REQUEST['SAMLResponse']);
SimpleSAML_Logger::debug("Received response: ".$resp);


//TODO
//Get metadata for the hosted IdP, as it is needed to decrypt possible
//encrypted assertions in the response
$claveConfig = sspmod_clave_Tools::getMetadataSet("__DYNAMIC:1__","clave-idp-hosted");
SimpleSAML_Logger::debug('Clave Idp hosted metadata: '.print_r($claveConfig,true));

//Hosted SP config
/*
$hostedSP = $claveConfig->getString('hostedSP', NULL);
if($hostedSP == NULL)
    throw new SimpleSAML_Error_Exception("No clave hosted SP configuration defined in clave bridge configuration.");
$claveSP = sspmod_clave_Tools::getMetadataSet($hostedSP,"clave-sp-hosted");
SimpleSAML_Logger::debug('Clave SP hosted metadata: '.print_r($claveSP,true));
*/


//Add additional post params as attributes on the response (it is
//expected that these params will be promoted to attrs in the future)
foreach ($_POST as $name => $value){
    if(in_array($name,$expectedAdditionalPostParams))
        $returnedAttributes[$name] = $value;
}


$clave = new sspmod_clave_SPlib();


$id = $clave->getInResponseToFromReq($resp);


$state = SimpleSAML_Auth_State::loadState($id, 'clave:sp:req');
SimpleSAML_Logger::debug('State on acs:'.print_r($state,true));



$idpData = $source->getIdP();


// Warning! issuer is variale when authenticating on stork (they put
// the country code of origin of the citizen in there).
$expectedIssuers = NULL;


SimpleSAML_Logger::debug("Certificate in source: ".$idpData['cert']);
$clave->addTrustedCert($idpData['cert']);

$clave->setValidationContext($id,
                             $state['clave:sp:returnPage'],
                             $expectedIssuers,
                             $state['clave:sp:mandatoryAttrs']);

//Expect encrypted assertions and try to decrypt them with the SP
//private key, also, don't ignore any existing plain assertion (this
//may change in the future)
$spkeypem  = sspmod_clave_Tools::readCertKeyFile($hostedSPmeta->getString('privatekey', NULL));
$expectEncrypted = $hostedSPmeta->getBoolean('assertions.encrypted', true);
$onlyEncrypted   = $hostedSPmeta->getBoolean('assertions.encrypted.only', false);

$clave->setDecipherParams($spkeypem,$expectEncrypted,$onlyEncrypted);
// TODO




$clave->validateStorkResponse($resp);



//Authentication was successful
$errInfo = "";
if($clave->isSuccess($errInfo)){


    //If later these attributes are passed from the POST to the SAML
    //token, the values coming on the token will prevail
    $returnedAttributes = array_merge($returnedAttributes, $clave->getAttributes());

    
    //Log for statistics: received successful Response from remote clave IdP
    $statsData = array(
        'spEntityID' => $spEntityId,
        'idpEntityID' => $clave->getRespIssuer(),
        'protocol' => 'saml2-clave',
    );
    if (isset($state['saml:AuthnRequestReceivedAt'])) {
        $statsData['logintime'] = microtime(TRUE) - $state['saml:AuthnRequestReceivedAt'];
    }
    SimpleSAML_Stats::log('clave:sp:Response', $statsData);
    
    //Pass the response state to the WebSSO SP
    $source->handleResponse($state, $returnedAttributes);
}






//Handle auth error:


//Log for statistics: received failed Response from remote clave IdP
$status = array(
    'Code' => $errInfo['MainStatusCode'],
    'SubCode' => $errInfo['SecondaryStatusCode'],
    'Message' => $errInfo['StatusMessage'],
);

$statsData = array(
    'spEntityID' => $spEntityId,
    'idpEntityID' => $clave->getRespIssuer(),
    'protocol' => 'saml2-clave',
    'error' => $status,
);

if (isset($state['saml:AuthnRequestReceivedAt'])) {
    $statsData['logintime'] = microtime(TRUE) - $state['saml:AuthnRequestReceivedAt'];
}

SimpleSAML_Stats::log('clave:sp:Response:error', $statsData);


//For some reason, Clave may not return a main status code. In that case, we set responder error
if($errInfo['MainStatusCode'] == sspmod_clave_SPlib::ATST_NOTAVAIL){
  $errInfo['MainStatusCode'] = sspmod_clave_SPlib::ST_RESPONDER;
}
//Forward the Clave IdP error to our remote SP.
SimpleSAML_Auth_State::throwException($state,
                                      new sspmod_saml_Error($errInfo['MainStatusCode'],
                                                            $errInfo['SecondaryStatusCode'],
                                                            $errInfo['StatusMessage']));


assert('FALSE');
