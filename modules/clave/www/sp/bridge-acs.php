<?php

/**
 * Assertion consumer service handler for clave bridge SP
 *
 */




//Hosted IdP config
$claveConfig = sspmod_clave_Tools::getMetadataSet("__DYNAMIC:1__","clave-idp-hosted");
SimpleSAML_Logger::debug('Clave Idp hosted metadata: '.print_r($claveConfig,true));

//Hosted SP config
$hostedSP = $claveConfig->getString('hostedSP', NULL);
if($hostedSP == NULL)
    throw new SimpleSAML_Error_Exception("No clave hosted SP configuration defined in clave bridge configuration.");
$claveSP = sspmod_clave_Tools::getMetadataSet($hostedSP,"clave-sp-hosted");
SimpleSAML_Logger::debug('Clave SP hosted metadata: '.print_r($claveSP,true));


$expectedResponsePostParams = $claveConfig->getArray('sp.post.allowed', array());


//Which clave IdP to use
$idpEntityId = $claveConfig->getString('claveIdP', NULL);
if($idpEntityId == NULL)
    throw new SimpleSAML_Error_Exception("No clave IdP configuration defined in clave bridge configuration.");
$idpMetadata = sspmod_clave_Tools::getMetadataSet($idpEntityId,"clave-idp-remote");


$idpData['cert'] = $idpMetadata->getString('certData', NULL);

    
//Since issuer is dynamic when authenticated through stork (STORK-XX,
//XX being a country code) we simply ignore the issuer
$expectedIssuers = NULL;


$hiCertPath = $claveConfig->getString('certificate', NULL);
$hiKeyPath  = $claveConfig->getString('privatekey', NULL);

if($hiCertPath == NULL || $hiKeyPath == NULL)
    throw new SimpleSAML_Error_Exception("No clave SSO certificate or key defined for the IdP interface in clave bridge configuration.");


if(!isset($_REQUEST['SAMLResponse']))
   	throw new SimpleSAML_Error_BadRequest('No SAMLResponse POST param received.');

$resp = base64_decode($_REQUEST['SAMLResponse']);
SimpleSAML_Logger::debug("Received response: ".$resp);


//Get allowed post params to be forwarded to the SP
$forwardedParams = array();
foreach ($_POST as $name => $value){
    if(in_array($name,$expectedResponsePostParams))
        $forwardedParams[$name] = $value;
}





$clave = new sspmod_clave_SPlib();


$id = $clave->getInResponseToFromReq($resp);


$state = SimpleSAML_Auth_State::loadState($id, 'clave:bridge:req');
SimpleSAML_Logger::debug('State on acs:'.print_r($state,true));
$reqData = $state['sp:request'];


// TODO SEGUIR: Get Remote SP metadata
// $reqData['issuer']



SimpleSAML_Logger::debug("Certificate in source: ".$idpData['cert']);
$clave->addTrustedCert($idpData['cert']);


$clave->setValidationContext($id,
                             $state['bridge:returnPage'],
                             $expectedIssuers,
                             $state['bridge:mandatoryAttrs']);


//Expect encrypted assertions and try to decrypt them with the SP
//private key, also, don't ignore any existing plain assertion (this
//may change in the future)
$spkeypem  = sspmod_clave_Tools::readCertKeyFile($claveSP->getString('privatekey', NULL));
$expectEncrypted = $claveSP->getBoolean('assertions.encrypted', true);
$onlyEncrypted   = $claveSP->getBoolean('assertions.encrypted.only', false);

$clave->setDecipherParams($spkeypem,$expectEncrypted,$onlyEncrypted);
// TODO

$clave->validateStorkResponse($resp);




//We extract the status info
$statusInfo = "";
if($clave->isSuccess($statusInfo))
    SimpleSAML_Logger::info("Authentication Successful");
//For some reason, Clave may not return a main status code. In that case, we set responder error
if($statusInfo['MainStatusCode'] == sspmod_clave_SPlib::ATST_NOTAVAIL){
    $statusInfo['MainStatusCode'] = sspmod_clave_SPlib::ST_RESPONDER;
}


//We build a status response with the status codes returned by Clave
$status = $clave->generateStatus($statusInfo);

//We clone the assertions on the repsonse, as they are signed on source (signature kept for legal reasons).
$assertions = $clave->getRawAssertions();


//Generate response with attributes, show the response and send back with submit button
$acs  = $reqData['assertionConsumerService'];

$storkResp = new sspmod_clave_SPlib();


$hikeypem  = sspmod_clave_Tools::readCertKeyFile($hiKeyPath);
$hicertpem = sspmod_clave_Tools::readCertKeyFile($hiCertPath);


$storkResp->setSignatureKeyParams($hicertpem, $hikeypem, sspmod_clave_SPlib::RSA_SHA256);

$storkResp->setSignatureParams(sspmod_clave_SPlib::SHA256,sspmod_clave_SPlib::EXC_C14N);

// TODO get the cert, assertion.encrypot and keyAlgorithm

$encryptAssertions = $claveConfig->getBoolean('assertion.encryption', false);
$encryptAlgorithm  = $claveConfig->getString('assertion.encryption.keyAlgorith', sspmod_clave_SPlib::AES256_CBC);
// TODO read the overriding SP values
$storkResp->setCipherParams($reqData['spCert'],$encryptAssertions,$encryptAlgorithm);

$storkResp->setResponseParameters($storkResp::CNS_OBT,
                                  $acs,
                                  $reqData['id'],
                                  $claveConfig->getString('issuer', 'NOT_SET')
                                  );

$resp = $storkResp->generateStorkResponse($status,$assertions);

//Redirecting to Clave IdP (Only HTTP-POST binding supported)
$post = array(
    'SAMLResponse'  => base64_encode($resp),
) + $forwardedParams;
SimpleSAML_Utilities::postRedirect($acs, $post);
