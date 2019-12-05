<?php
/**
 * Clave IdP Logout endopint for simpleSAMLphp.
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
$hostedSPmeta = sspmod_clave_Tools::getMetadataSet($hostedSP,"clave-sp-hosted");
SimpleSAML_Logger::debug('Clave SP hosted metadata: '.print_r($hostedSPmeta,true));


//Which clave IdP to use
$idpEntityId = $hostedSPmeta->getString('idpEntityID', NULL);
if($idpEntityId == NULL)
    throw new SimpleSAML_Error_Exception("No clave IdP configuration defined in clave bridge configuration.");

$idpMeta = sspmod_clave_Tools::getMetadataSet($idpEntityId,"clave-idp-remote");
SimpleSAML_Logger::debug('Clave Idp remote metadata ('.$idpEntityId.'): '.print_r($idpMeta,true));


$providerName = $hostedSPmeta->getString('providerName', NULL);

//Authorised Signing Certificate to connect to Clave
$certPath = $hostedSPmeta->getString('certificate', NULL);
$keyPath  = $hostedSPmeta->getString('privatekey', NULL);

$endpoint = $idpMeta->getString('SingleLogoutService', NULL);

//Calculate return page for the new request
$returnPage = SimpleSAML_Module::getModuleURL('clave/sp/bridge-logout.php/');


if($endpoint == NULL)
    throw new SimpleSAML_Error_Exception("No clave SLO endpoint defined in clave bridge configuration.");
if($providerName == NULL)
    throw new SimpleSAML_Error_Exception("No provider Name defined in clave bridge configuration.");
if($certPath == NULL || $keyPath == NULL)
    throw new SimpleSAML_Error_Exception("No clave certificate or key defined for the SP interface in clave bridge configuration.");




$spcertpem = sspmod_clave_Tools::readCertKeyFile($certPath);
$spkeypem  = sspmod_clave_Tools::readCertKeyFile($keyPath);







$claveIdP = new sspmod_clave_SPlib();


// TODO Don't know if we should use the standard POST params or
// completely match the Clave specs Standard: SAMLRequest
if(!isset($_REQUEST['samlRequestLogout']))
   	throw new SimpleSAML_Error_BadRequest('No samlRequestLogout POST param received.');

$request = base64_decode($_REQUEST['samlRequestLogout']);


//On SLO requests, the SP entity ID travels on the nameID field.
$spEntityId = $claveIdP->getSloNameId($request);
SimpleSAML_Logger::info("SLO request Issuer (SP): ".$spEntityId);


$spMetadata = sspmod_clave_Tools::getSPMetadata($claveConfig,$spEntityId);
SimpleSAML_Logger::debug('Clave SP remote metadata ('.$spEntityId.'): '.print_r($spMetadata,true));




//Get the mode of operation this IdP must expect (based on the remote
//SP specific or the hosted IdP default)
$IdPdialect    = $spMetadata->getString('dialect',
                                        $claveConfig->getString('dialect'));
$IdPsubdialect = $spMetadata->getString('subdialect',
                                        $claveConfig->getString('subdialect'));

SimpleSAML_Logger::debug('---------------------->dialect: '.$IdPdialect);
SimpleSAML_Logger::debug('---------------------->subdialect: '.$IdPsubdialect);

if ($IdPdialect === 'eidas')
    $eidas->setEidasMode();





$certs = sspmod_clave_Tools::findX509SignCertOnMetadata($spMetadata);

$claveIdP->addTrustedRequestIssuer($spEntityId, $certs);


//Log for statistics: received LogoutRequest at the clave IdP
SimpleSAML_Stats::log('saml:idp:LogoutRequest:recv', array(
    'spEntityID'  => $spEntityId,
    'idpEntityID' => $claveConfig->getString('issuer', ''),
));


//Validate Clave LogoutRequest
$claveIdP->validateLogoutRequest($request);

//Extract all relevant data for the retransmitted request (including stork extensions)
$reqData = $claveIdP->getSloRequestData();

SimpleSAML_Logger::debug("SP SLO Request data: ".print_r($reqData,true));



//**** Build request for clave *******


$claveSP = new sspmod_clave_SPlib();


$claveSP->setSignatureKeyParams($spcertpem, $spkeypem, sspmod_clave_SPlib::RSA_SHA256);
$claveSP->setSignatureParams(sspmod_clave_SPlib::SHA256,sspmod_clave_SPlib::EXC_C14N);


//Store state for the comeback
$state = array();
$state['sp:slo:request']            = $reqData;
$state['bridge:slo:returnPage']     = $returnPage;

$id = SimpleSAML_Auth_State::saveState($state, 'clave:bridge:slo:req', true);
SimpleSAML_Logger::debug("Generated Req ID: ".$id);




//Set the id of the request, it must be the id of the saved state.
$req = base64_encode($claveSP->generateSLORequest($providerName,$endpoint,$returnPage,$id));
SimpleSAML_Logger::debug("Generated LogoutReq: ".$req);


//Log for statistics: sent LogoutRequest to remote clave IdP
SimpleSAML_Stats::log('saml:idp:LogoutRequest:sent', array(
        'spEntityID' =>  $hostedSPmeta->getString('entityid'),
        'idpEntityID' => $idpMeta->getString('SingleSignOnService'),
));


//Redirect
$post = array(
    'samlRequestLogout'  => $req,
);

SimpleSAML_Logger::debug("post: ".print_r($post, true));


//Redirecting to Clave IdP (Only HTTP-POST binding supported)
SimpleSAML_Utilities::postRedirect($endpoint, $post);


assert(false);
