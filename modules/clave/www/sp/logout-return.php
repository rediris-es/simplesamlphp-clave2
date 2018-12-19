<?php

/**
 * Logout acs endpoint (response handler) for clave authentication source SP
 *
 */

SimpleSAML_Logger::info('Call to Clave auth source logout-comeback');


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



if(!isset($_REQUEST['samlResponseLogout']))
   	throw new SimpleSAML_Error_BadRequest('No samlResponseLogout POST param received.');

$resp = base64_decode($_REQUEST['samlResponseLogout']);
SimpleSAML_Logger::debug("Received response: ".$resp);



$clave = new sspmod_clave_SPlib();


$id = $clave->getInResponseToFromReq($resp);


$state = SimpleSAML_Auth_State::loadState($id, 'clave:sp:slo:req');
SimpleSAML_Logger::debug('State on logout-return:'.print_r($state,true));



$remoteIdPMeta = $source->getIdPMetadata();

//Not properly set by Clave, so ignoring it.
$expectedIssuers = NULL;

SimpleSAML_Logger::debug("Certificate in source: ".$remoteIdPMeta->getString('certData', NULL));
$clave->addTrustedCert($remoteIdPMeta->getString('certData', NULL));




$clave->setValidationContext($id,
                             $state['clave:sp:slo:returnPage'],
                             $expectedIssuers,
                             NULL);

//If logout failed, we warn, but keep on with the response (as the
//status is transmitted back to the SP)
if(!$clave->validateSLOResponse($resp)){
    
    SimpleSAML_Logger::warning('Unsuccessful logout. Status was: '.print_r($clave->getResponseStatus(),true));

//$errInfo = $clave->getResponseStatus();
//new sspmod_saml_Error($errInfo['MainStatusCode'],
//                      $errInfo['SecondaryStatusCode'],
//                      $errInfo['StatusMessage'])
}


//Log for statistics: received LogoutResponse from remote clave IdP
$statsData = array(
    'spEntityID'  => $spEntityId,
    'idpEntityID' => $clave->getRespIssuer(),
);
$errInfo = "";
if (!$clave->isSuccess($errInfo))
    $statsData['error'] = $errInfo['MainStatusCode'];
SimpleSAML_Stats::log('saml:idp:LogoutResponse:recv', $statsData);




$state['saml:sp:LogoutStatus'] = $clave->getResponseStatus();
SimpleSAML_Auth_Source::completeLogout($state);



assert('FALSE');
