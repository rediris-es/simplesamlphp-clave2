<?php
/**
 * Clave IdP for simpleSAMLphp.
 *
 */

SimpleSAML_Logger::info('Call to Clave bridge IdP side');


//Hosted IdP config
$claveConfig = sspmod_clave_Tools::getMetadataSet("__DYNAMIC:1__","clave-idp-hosted");
SimpleSAML_Logger::debug('Clave Idp hosted metadata: '.print_r($claveConfig,true));

//Hosted SP config
$hostedSP = $claveConfig->getString('hostedSP', NULL);
if($hostedSP == NULL)
    throw new SimpleSAML_Error_Exception("No clave hosted SP configuration defined in clave bridge configuration.");
$claveSP = sspmod_clave_Tools::getMetadataSet($hostedSP,"clave-sp-hosted");
SimpleSAML_Logger::debug('Clave SP hosted metadata: '.print_r($claveSP,true));


//Which clave IdP to use
$idpEntityId = $claveConfig->getString('claveIdP', NULL);
if($idpEntityId == NULL)
    throw new SimpleSAML_Error_Exception("No clave IdP configuration defined in clave bridge configuration.");

$idpMeta = sspmod_clave_Tools::getMetadataSet($idpEntityId,"clave-idp-remote");
SimpleSAML_Logger::debug('Clave Idp remote metadata ('.$idpEntityId.'): '.print_r($idpMeta,true));


$providerName = $claveSP->getString('providerName', NULL);

//Authorised Signing Certificate to connect to Clave
$certPath = $claveSP->getString('certificate', NULL);
$keyPath  = $claveSP->getString('privatekey', NULL);

$endpoint = $idpMeta->getString('SingleSignOnService', NULL);

$expectedRequestPostParams = $claveConfig->getArray('idp.post.allowed', array());



if($endpoint == NULL)
    throw new SimpleSAML_Error_Exception("No clave SSO endpoint defined in clave bridge configuration.");
if($providerName == NULL)
    throw new SimpleSAML_Error_Exception("No provider Name defined in clave bridge configuration.");
if($certPath == NULL || $keyPath == NULL)
    throw new SimpleSAML_Error_Exception("No clave SSO certificate or key defined for the SP interface in clave bridge configuration.");



$spcertpem = sspmod_clave_Tools::readCertKeyFile($certPath);
$spkeypem  = sspmod_clave_Tools::readCertKeyFile($keyPath);



$claveIdP = new sspmod_clave_SPlib();

$claveIdP->setEidasMode();   // TODO

if(!isset($_REQUEST['SAMLRequest']))
   	throw new SimpleSAML_Error_BadRequest('No SAMLRequest POST param received.');

//Get allowed post params to be forwarded to Clave
$forwardedParams = array();
foreach ($_POST as $name => $value){
    if(in_array($name,$expectedRequestPostParams))
        $forwardedParams[$name] = $value;
}



$request = base64_decode($_REQUEST['SAMLRequest']);
SimpleSAML_Logger::debug("SP Request: ".$request);


$spEntityId = $claveIdP->getIssuer($request);
SimpleSAML_Logger::info("SP Issuer: ".$spEntityId);


$spMetadata = sspmod_clave_Tools::getSPMetadata($claveConfig,$spEntityId);
SimpleSAML_Logger::debug('Clave SP remote metadata ('.$spEntityId.'): '.print_r($spMetadata,true));

$cert = sspmod_clave_Tools::findX509SignCertOnMetadata($spMetadata);

$claveIdP->addTrustedRequestIssuer($spEntityId, $cert);


//Log for statistics: received AuthnRequest at the clave IdP
$aux = $claveIdP->getStorkRequestData($request);
SimpleSAML_Stats::log('clave:idp:AuthnRequest', array(
    'spEntityID' => $spEntityId,
    'idpEntityID' => $claveConfig->getString('issuer', ''),
    'forceAuthn' => $aux['forceAuthn'],
    'isPassive' => $aux['isPassive'],
    'protocol' => 'saml2-clave',
    'idpInit' => FALSE,
));


//Validate Clave AuthnRequest
$claveIdP->validateStorkRequest($request);

//Extract all relevant data for the retransmitted request (including stork extensions)
$reqData = $claveIdP->getStorkRequestData();

SimpleSAML_Logger::debug("SP Request data: ".print_r($reqData,true));



// ******************************* Building the new request ************


//These params will be taken from the request but can be overwritten if set on the hosted SP conf.
$bridgeData['spCountry']     = $claveSP->getString('spCountry', $reqData['spCountry']);
$bridgeData['spSector']      = $claveSP->getString('spSector', $reqData['spSector']);
$bridgeData['spInstitution'] = $claveSP->getString('spInstitution', $reqData['spInstitution']);
$bridgeData['spApplication'] = $claveSP->getString('spApplication', $reqData['spApplication']);
$bridgeData['spID']          = $claveSP->getString('spID', $reqData['spID']);
$bridgeData['citizenCountryCode'] =
    $claveSP->getString('citizenCountryCode', $reqData['citizenCountryCode']);
$bridgeData['eIDSectorShare'] =
    $claveSP->getBoolean('eIDSectorShare',
                             sspmod_clave_SPlib::stb($reqData['eIDSectorShare']));
$bridgeData['eIDCrossSectorShare'] =
    $claveSP->getBoolean('eIDCrossSectorShare',
                             sspmod_clave_SPlib::stb($reqData['eIDCrossSectorShare']));
$bridgeData['eIDCrossBorderShare'] =
    $claveSP->getBoolean('eIDCrossBorderShare',
    sspmod_clave_SPlib::stb($reqData['eIDCrossBorderShare']));


//The issuer is set to be the SP's entityId, if not fixed on the IdP configuration
$reqIssuer = $claveConfig->getString('issuer', $reqData['issuer']);




//Calculate return page for the new request
$returnPage = SimpleSAML_Module::getModuleURL('clave/sp/bridge-acs.php/');



//Calculate metadata URL // TODO eIDAS
$metadataURL = SimpleSAML_Module::getModuleURL('clave/sp/metadata.php/'.'bridge/'.$hostedSP.'/');
$reqIssuer = $metadataURL;  // TODO eIDAS




//Build the new authn request
$clave = new sspmod_clave_SPlib();



// TODO eIDAS
$clave->setEidasMode();   // TODO en el futuro, los parámetros de abajo tomarlos de la req entrante. De momento dejarlos fijos
$clave->setEidasRequestParams(sspmod_clave_SPlib::EIDAS_SPTYPE_PUBLIC,
                              sspmod_clave_SPlib::NAMEID_FORMAT_PERSISTENT,  
                              $ret['LoA']);


$clave->setSignatureKeyParams($spcertpem, $spkeypem, sspmod_clave_SPlib::RSA_SHA512);
$clave->setSignatureParams(sspmod_clave_SPlib::SHA512, sspmod_clave_SPlib::EXC_C14N);


$clave->setServiceProviderParams($providerName,
                                 $reqIssuer,
                                 $returnPage);


if($reqData['forceAuthn'])
    $clave->forceAuthn();

$clave->setSPLocationParams($bridgeData['spCountry'],$bridgeData['spSector'],
                            $bridgeData['spInstitution'],$bridgeData['spApplication']);  

$clave->setSPVidpParams($bridgeData['spID'],$bridgeData['citizenCountryCode']);
$clave->setSTORKParams ($endpoint, $reqData['QAA'],
                        $bridgeData['eIDSectorShare'],
                        $bridgeData['eIDCrossSectorShare'],
                        $bridgeData['eIDCrossBorderShare']);

$mandatory = array();
foreach($reqData['requestedAttributes'] as $attr){
    //$name = sspmod_clave_SPlib::getFriendlyName($attr['name']);  // TODO eIDAS. 
    //$clave->addRequestAttribute($name, $attr['isRequired']);
    $clave->addRequestAttribute($attr['friendlyName'], $attr['isRequired']);  // TODO eIDAS.

    
    //We store the list of mandatory attributes for response validation
    if(sspmod_clave_SPlib::stb($attr['isRequired']) === true){
        $mandatory []= $name;
    }
}



//Store state for the comeback
$state = array();
$state['sp:request']            = $reqData;
$state['bridge:returnPage']     = $returnPage;
$state['bridge:mandatoryAttrs'] = $mandatory;

$id = SimpleSAML_Auth_State::saveState($state, 'clave:bridge:req', true);
SimpleSAML_Logger::debug("Generated Req ID: ".$id);


//Set the id of the request, it must be the id of the saved state.
$clave->setRequestId($id);

//Generate the new request token
$req = base64_encode($clave->generateStorkAuthRequest());
SimpleSAML_Logger::debug("Generated AuthnReq: ".$req);


//Log for statistics: sent AuthnRequest to remote clave IdP
SimpleSAML_Stats::log('clave:sp:AuthnRequest', array(
    'spEntityID' =>  $claveSP->getString('entityid', NULL),
    'idpEntityID' => $endpoint,
    'forceAuthn' => $reqData['forceAuthn'],
    'isPassive' => FALSE,
    'protocol' => 'saml2-clave',
    'idpInit' => FALSE,
));



//Redirect (forwarded params are appended, priority to the ones set here)
$post = array(
    'SAMLRequest'  => $req,
    // 'country'  => 'ES', // TODO eIDAS forwarded, but if not present , show country selector
) + $forwardedParams;

SimpleSAML_Logger::debug("forwarded: ".print_r($forwardedParams, true));
SimpleSAML_Logger::debug("post: ".print_r($post, true));


//Redirecting to Clave IdP (Only HTTP-POST binding supported)
SimpleSAML_Utilities::postRedirect($endpoint, $post);


assert(false);


/*
$metadata = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler();
$spMetadata = $metadata->getMetaDataConfig($spEntityId, 'saml20-sp-remote');
*/