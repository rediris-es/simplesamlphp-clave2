<?php

/**
 * Logout endpoint for clave bridge SP
 *
 */

//Hosted SP metadata
$claveConfig = sspmod_clave_Tools::getMetadataSet("__DYNAMIC:1__","clave-idp-hosted");
SimpleSAML_Logger::debug('Clave Idp hosted metadata: '.print_r($claveConfig,true));


//Remote IdP metadata (Which clave IdP to connect to)
$idpEntityId = $claveConfig->getString('claveIdP', NULL);
if($idpEntityId == NULL)
    throw new SimpleSAML_Error_Exception("No clave IdP configuration defined in clave bridge configuration.");
$idpMetadata = sspmod_clave_Tools::getMetadataSet($idpEntityId,"clave-idp-remote");


//Response validation parameters
$idpValidationCertPem = $idpMetadata->getString('certData', NULL);
$expectedIssuers = NULL;


//Certificate and key to sign the response directed to the remote SP.
$certPath = $claveConfig->getString('certificate', NULL);
$keyPath  = $claveConfig->getString('privatekey', NULL);
$spcertpem = sspmod_clave_Tools::readCertKeyFile($certPath);
$spkeypem  = sspmod_clave_Tools::readCertKeyFile($keyPath);
if($certPath == NULL || $keyPath == NULL)
    throw new SimpleSAML_Error_Exception("No clave SSO response signing certificate or key defined for the IdP interface in clave bridge configuration.");


//Response generation parameters
$issuer = $claveConfig->getString('issuer', 'NOT_SET');



// ****** Handle response from the IdP *******


//Get the response
if(!isset($_REQUEST['samlResponseLogout']))
   	throw new SimpleSAML_Error_BadRequest('No samlResponseLogout POST param received.');

$resp = base64_decode($_REQUEST['samlResponseLogout']);
SimpleSAML_Logger::debug("Received response: ".$resp);


//Validate response
$claveSP = new sspmod_clave_SPlib();


$id = $claveSP->getInResponseToFromReq($resp);


//Load state we stored for the request associated with this response
$state = SimpleSAML_Auth_State::loadState($id, 'clave:bridge:slo:req');
SimpleSAML_Logger::debug('State on slo-return:'.print_r($state,true));



//Adding IdP trusted certificate for validation
SimpleSAML_Logger::debug("Certificate in source: ".$idpValidationCertPem);
$claveSP->addTrustedCert($idpValidationCertPem);


$claveSP->setValidationContext($id,
                             $state['bridge:slo:returnPage'],
                             $expectedIssuers,
                             NULL);


if(!$claveSP->validateSLOResponse($resp)){
    SimpleSAML_Logger::warning('Unsuccessful logout. Status was: '.print_r($claveSP->getResponseStatus(),true));
}

$respStatus = $claveSP->getResponseStatus();


// ****** Build response for the SP *******



//Get the endpoint from the SP request, not from the metadata (stork
//always does this). Also, the endopint is in the issuer field.
$destination = $state['sp:slo:request']['issuer'];
$inResponseTo = $state['sp:slo:request']['id'];

$claveIdP = new sspmod_clave_SPlib();

$claveIdP->setSignatureKeyParams($spcertpem, $spkeypem, sspmod_clave_SPlib::RSA_SHA256);
$claveIdP->setSignatureParams(sspmod_clave_SPlib::SHA256,sspmod_clave_SPlib::EXC_C14N);

$spResponse = $claveIdP->generateSLOResponse($inResponseTo,$issuer,$respStatus,$destination);


//Redirecting to Clave IdP (Only HTTP-POST binding supported, also Stork-flavoured)
$post = array(
    'samlResponseLogout'  => base64_encode($spResponse),
);
SimpleSAML_Utilities::postRedirect($destination, $post);