<?php

/**
 * Logout acs endpoint (response handler) for clave authentication source SP
 *
 */

namespace SimpleSAML\Module\clave;


use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Auth;
use SimpleSAML\Error;
use SimpleSAML\Module\clave\SPlib;
use SimpleSAML\Module\clave\Tools;
use SimpleSAML\Stats;


Logger::info('Call to Clave auth source logout-comeback');


// Get the Id of the authsource
$sourceId = substr($_SERVER['PATH_INFO'], 1);
$source = Auth\Source::getById($sourceId, 'SimpleSAML\Module\clave\Auth\Source\SP');

//Get the metadata for the soliciting SP
$spMetadata = $source->getMetadata();
Logger::debug('Metadata on acs:'.print_r($spMetadata,true));


//Hosted SP config
$hostedSP = Tools::getString($spMetadata,'hostedSP', NULL);
if($hostedSP == NULL)
    throw new Error\Exception("No clave hosted SP configuration defined in clave auth source configuration.");
$hostedSPmeta = Tools::getMetadataSet($hostedSP,"clave-sp-hosted");
Logger::debug('Clave SP hosted metadata: '.print_r($hostedSPmeta,true));

$spEntityId = Tools::getString($hostedSPmeta,'entityID', NULL);



if(!isset($_REQUEST['samlResponseLogout']))
   	throw new Error\BadRequest('No samlResponseLogout POST param received.');

$resp = base64_decode($_REQUEST['samlResponseLogout']);
Logger::debug("Received response: ".$resp);



$clave = new SPlib();


$id = $clave->getInResponseToFromReq($resp);


$state = Auth\State::loadState($id, 'clave:sp:slo:req');
Logger::debug('State on logout-return:'.print_r($state,true));



$remoteIdPMeta = $source->getIdPMetadata();

//Not properly set by Clave, so ignoring it.
$expectedIssuers = NULL;





$keys = Tools::getArray($remoteIdPMeta,'keys',NULL);
if($keys !== NULL){
    foreach($keys as $key){
        //Here we should be selecting signature/encryption certs, but
        //as the library uses the same ones for both purposes, we just
        //ignore this check.
        if(!$key['X509Certificate'] || $key['X509Certificate'] == "")
            continue;
        
        $clave->addTrustedCert($key['X509Certificate']);
    }
}

$certData = Tools::getString($remoteIdPMeta,'certData', NULL);
if($certData !== NULL){
    Logger::debug("Certificate in source (legacy parameter): ".$certData);
    $clave->addTrustedCert($certData);
}





$clave->setValidationContext($id,
                             $state['clave:sp:slo:returnPage'],
                             $expectedIssuers,
                             NULL);

//If logout failed, we warn, but keep on with the response (as the
//status is transmitted back to the SP)
if(!$clave->validateSLOResponse($resp)){
    
    Logger::warning('Unsuccessful logout. Status was: '.print_r($clave->getResponseStatus(),true));

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
Stats::log('saml:idp:LogoutResponse:recv', $statsData);




$state['saml:sp:LogoutStatus'] = $clave->getResponseStatus();
Auth\Source::completeLogout($state);



assert('FALSE');
