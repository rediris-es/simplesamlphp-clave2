<?php

/**
 * Logout acs endpoint (response handler) for clave bridge SP
 *
 */

//Hosted SP metadata
$claveConfig = sspmod_clave_Tools::getMetadataSet("__DYNAMIC:1__","clave-idp-hosted");
SimpleSAML\Logger::debug('Clave Idp hosted metadata: '.print_r($claveConfig,true));


//Remote IdP metadata (Which clave IdP to connect to)
$idpEntityId = $claveConfig->getString('claveIdP', NULL);
if($idpEntityId == NULL)
    throw new SimpleSAML\Error\Exception("No clave IdP configuration defined in clave bridge configuration.");
$idpMetadata = sspmod_clave_Tools::getMetadataSet($idpEntityId,"clave-idp-remote");


//Hosted SP config
$hostedSP = $claveConfig->getString('hostedSP', NULL);
if($hostedSP == NULL)
    throw new SimpleSAML\Error\Exception("No clave hosted SP configuration defined in clave auth source configuration.");
$hostedSPmeta = sspmod_clave_Tools::getMetadataSet($hostedSP,"clave-sp-hosted");
SimpleSAML\Logger::debug('Clave SP hosted metadata: '.print_r($hostedSPmeta,true));

$spEntityId = $hostedSPmeta->getString('entityid', NULL);



//Response validation parameters
$expectedIssuers = NULL;


//Certificate and key to sign the response directed to the remote SP.
$certPath = $claveConfig->getString('certificate', NULL);
$keyPath  = $claveConfig->getString('privatekey', NULL);
$spcertpem = sspmod_clave_Tools::readCertKeyFile($certPath);
$spkeypem  = sspmod_clave_Tools::readCertKeyFile($keyPath);
if($certPath == NULL || $keyPath == NULL)
    throw new SimpleSAML\Error\Exception("No clave SSO response signing certificate or key defined for the IdP interface in clave bridge configuration.");


//Response generation parameters
$issuer = $claveConfig->getString('issuer', 'NOT_SET');



// ****** Handle response from the IdP *******


//Get the response
if(!isset($_REQUEST['samlResponseLogout']))
   	throw new SimpleSAML\Error\BadRequest('No samlResponseLogout POST param received.');

$resp = base64_decode($_REQUEST['samlResponseLogout']);
SimpleSAML\Logger::debug("Received response: ".$resp);


//Validate response
$claveSP = new sspmod_clave_SPlib();


$id = $claveSP->getInResponseToFromReq($resp);


//Load state we stored for the request associated with this response
$state = SimpleSAML\Auth\State::loadState($id, 'clave:bridge:slo:req');
SimpleSAML\Logger::debug('State on slo-return:'.print_r($state,true));



//Adding IdP trusted certificate for validation
$keys = $idpMetadata->getArray('keys',NULL);
if($keys !== NULL){
    foreach($keys as $key){
        //Here we should be selecting signature/encryption certs, but
        //as the library uses the same ones for both purposes, we just
        //ignore this check.
        if(!$key['X509Certificate'] || $key['X509Certificate'] == "")
            continue;
        
        $claveSP->addTrustedCert($key['X509Certificate']);
    }
}

$certData = $idpMetadata->getString('certData', NULL);
if($certData !== NULL){
    SimpleSAML\Logger::debug("Certificate in source (legacy parameter): ".$certData);
    $claveSP->addTrustedCert($certData);
}


$claveSP->setValidationContext($id,
                             $state['bridge:slo:returnPage'],
                             $expectedIssuers,
                             NULL);


if(!$claveSP->validateSLOResponse($resp)){
    SimpleSAML\Logger::warning('Unsuccessful logout. Status was: '.print_r($claveSP->getResponseStatus(),true));
}

$respStatus = $claveSP->getResponseStatus();


//Log for statistics: received LogoutResponse from remote clave IdP
$statsData = array(
    'spEntityID'  => $spEntityId,
    'idpEntityID' => $claveSP->getRespIssuer(),
);
$errInfo = "";
if (!$claveSP->isSuccess($errInfo))
    $statsData['error'] = $errInfo['MainStatusCode'];
SimpleSAML\Stats::log('saml:idp:LogoutResponse:recv', $statsData);



// ****** Build response for the SP *******



//Get the endpoint from the SP request, not from the metadata (stork
//always does this). Also, the endopint is in the issuer field.
$destination = $state['sp:slo:request']['issuer'];
$inResponseTo = $state['sp:slo:request']['id'];

$claveIdP = new sspmod_clave_SPlib();

$claveIdP->setSignatureKeyParams($spcertpem, $spkeypem, sspmod_clave_SPlib::RSA_SHA256);
$claveIdP->setSignatureParams(sspmod_clave_SPlib::SHA256,sspmod_clave_SPlib::EXC_C14N);

$spResponse = $claveIdP->generateSLOResponse($inResponseTo,$issuer,$respStatus,$destination);


//Log for statistics: sent LogoutResponse to the remote SP
SimpleSAML\Stats::log('saml:idp:LogoutResponse:sent', array(
    'spEntityID' => $destination,
    'idpEntityID' => $issuer,
    'partial' => TRUE
));
//Se refiere a si se han desconectado todos los SP o no. En este
//caso, como no clave no mantiene ningún listado de ello, ponemos que
//es parcial siempre


//Redirecting to Clave IdP (Only HTTP-POST binding supported, also Stork-flavoured)
$post = array(
    'samlResponseLogout'  => base64_encode($spResponse),
);
SimpleSAML_Utilities::postRedirect($destination, $post);
