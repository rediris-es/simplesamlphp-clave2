<?php
/**
 * Clave IdP Logout endopint for simpleSAMLphp.
 *
 */

namespace SimpleSAML\Module\clave\Auth\Source;

use SimpleSAML\Logger;
use SimpleSAML\Error;
use SimpleSAML\Module;
use SimpleSAML\Stats;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\Auth\State;

use SimpleSAML\Module\clave\SPlib;
use SimpleSAML\Module\clave\Tools;

Logger::info('Call to Clave bridge IdP side');


//Hosted IdP config
$claveConfig = Tools::getMetadataSet("__DYNAMIC:1__","clave-idp-hosted");
Logger::debug('Clave Idp hosted metadata: '.print_r($claveConfig,true));

//Hosted SP config
$hostedSP = Tools::getString($claveConfig,'hostedSP', NULL);
if($hostedSP == NULL)
    throw new Error\Exception("No clave hosted SP configuration defined in clave bridge configuration.");
$hostedSPmeta = Tools::getMetadataSet($hostedSP,"clave-sp-hosted");
Logger::debug('Clave SP hosted metadata: '.print_r($hostedSPmeta,true));


//Which clave IdP to use
$idpEntityId = Tools::getString($hostedSPmeta,'idpEntityID', NULL);
if($idpEntityId == NULL)
    throw new Error\Exception("No clave IdP configuration defined in clave bridge configuration.");

$idpMeta = Tools::getMetadataSet($idpEntityId,"clave-idp-remote");
Logger::debug('Clave Idp remote metadata ('.$idpEntityId.'): '.print_r($idpMeta,true));


$providerName = Tools::getString($hostedSPmeta,'providerName', NULL);

//Authorised Signing Certificate to connect to Clave
$certPath = Tools::getString($hostedSPmeta,'certificate', NULL);
$keyPath  = Tools::getString($hostedSPmeta,'privatekey', NULL);

$endpoint = Tools::getString($idpMeta,'SingleLogoutService', NULL);

//Calculate return page for the new request
$returnPage = Module::getModuleURL('clave/sp/bridge-logout.php/');


if($providerName == NULL)
    throw new Error\Exception("No provider Name defined in clave bridge configuration.");
if($certPath == NULL || $keyPath == NULL)
    throw new Error\Exception("No clave certificate or key defined for the SP interface in clave bridge configuration.");




//Get the hosted SP cert and key
$spcertpem = Tools::readCertKeyFile($certPath);
$spkeypem  = Tools::readCertKeyFile($keyPath);







$claveIdP = new SPlib();


// TODO Don't know if we should use the standard POST params or
// completely match the Clave specs Standard: SAMLRequest
if(!isset($_REQUEST['samlRequestLogout']))
   	throw new Error\BadRequest('No samlRequestLogout POST param received.');

$request = base64_decode($_REQUEST['samlRequestLogout']);


//On SLO requests, the SP entity ID travels on the nameID field.
$spEntityId = $claveIdP->getSloNameId($request);
Logger::info("SLO request Issuer (SP): ".$spEntityId);


$spMetadata = Tools::getSPMetadata($claveConfig,$spEntityId);
Logger::debug('Clave SP remote metadata ('.$spEntityId.'): '.print_r($spMetadata,true));




//Get the mode of operation this IdP must expect (based on the remote
//SP specific or the hosted IdP default)
$IdPdialect    = Tools::getString($spMetadata,'dialect',
    Tools::getString($claveConfig,'dialect'));
$IdPsubdialect = Tools::getString($spMetadata,'subdialect',
    Tools::getString($claveConfig,'subdialect'));

Logger::debug('---------------------->dialect: '.$IdPdialect);
Logger::debug('---------------------->subdialect: '.$IdPsubdialect);

if ($IdPdialect === 'eidas')
    $claveIdP->setEidasMode();



//Another part of the dirty patch to go around Clave devlopers
//madness: If subdialect is clave 2, the return page for the SLO
//response must be the same as for the SSO acs, not the proper one, so
//smash it
if ($IdPdialect === 'eidas'){
    //Calculate return page for the new request in clave 2, which is SSO ACM
    $returnPage = Module::getModuleURL('clave/sp/clave-acs.php/'.Tools::getString($claveConfig,'auth','')); // TODO: works?

}


$certs = Tools::findX509SignCertOnMetadata($spMetadata);

$claveIdP->addTrustedRequestIssuer($spEntityId, $certs);


//Log for statistics: received LogoutRequest at the clave IdP
Stats::log('saml:idp:LogoutRequest:recv', array(
    'spEntityID'  => $spEntityId,
    'idpEntityID' => Tools::getString($claveConfig,'issuer', ''),
));


//Validate Clave LogoutRequest
$claveIdP->validateLogoutRequest($request);

//Extract all relevant data for the retransmitted request (including stork extensions)
$reqData = $claveIdP->getSloRequestData();

Logger::debug("SP SLO Request data: ".print_r($reqData,true));











//Now, if no SLO endpoint is defined,  we make it just go back silently to the SP
if($endpoint == NULL){
    //throw new Error\Exception("No clave SLO endpoint defined in clave bridge configuration.");


    // ****** Build response for the SP *******

    //Certificate and key to sign the response directed to the remote SP.
    $idpCertPath = Tools::getString($claveConfig,'certificate', NULL);
    $idpKeyPath  = Tools::getString($claveConfig,'privatekey', NULL);
    $idpcertpem = Tools::readCertKeyFile($idpCertPath);
    $idpkeypem  = Tools::readCertKeyFile($idpKeyPath);
    if($idpCertPath == NULL || $idpKeyPath == NULL)
        throw new Error\Exception("No clave SSO response signing certificate or key defined for the IdP interface in clave bridge configuration.");


    $issuer = Tools::getString($claveConfig,'issuer', 'NOT_SET');
    

    //Get the endpoint from the SP request, not from the metadata (stork
    //always does this). Also, the endopint is in the issuer field.
    $destination = $reqData['issuer'];
    $inResponseTo = $reqData['id'];

    $claveIdPresp = new SPlib();

    $claveIdPresp->setSignatureKeyParams($idpcertpem, $idpkeypem, SPlib::RSA_SHA256);
    $claveIdPresp->setSignatureParams(SPlib::SHA256,SPlib::EXC_C14N);
    
    
    $respStatus = array();
    $respStatus ["MainStatusCode"] = SPlib::ST_SUCCESS;
    $respStatus ["SecondaryStatusCode"] = NULL;
    
    
    $spResponse = $claveIdPresp->generateSLOResponse($inResponseTo,$issuer,$respStatus,$destination);


    //Log for statistics: sent LogoutResponse to the remote SP
    Stats::log('saml:idp:LogoutResponse:sent', array(
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
    (new HTTP)->submitPOSTData($destination, $post);
}















//**** Build request for clave *******


$claveSP = new SPlib();

if ($IdPdialect === 'eidas')
    $claveSP->setEidasMode();

$claveSP->setSignatureKeyParams($spcertpem, $spkeypem, SPlib::RSA_SHA256);
$claveSP->setSignatureParams(SPlib::SHA256,SPlib::EXC_C14N);


//Store state for the comeback
$state = array();
$state['sp:slo:request']            = $reqData;
$state['bridge:slo:returnPage']     = $returnPage;

$id = State::saveState($state, 'clave:bridge:slo:req', true);
Logger::debug("Generated Req ID: ".$id);




//Set the id of the request, it must be the id of the saved state.
$req = base64_encode($claveSP->generateSLORequest($providerName,$endpoint,$returnPage,$id));
Logger::debug("Generated LogoutReq: ".$req);


//Log for statistics: sent LogoutRequest to remote clave IdP
Stats::log('saml:idp:LogoutRequest:sent', array(
        'spEntityID' =>  Tools::getString($hostedSPmeta,'entityid'),
        'idpEntityID' => Tools::getString($idpMeta,'SingleSignOnService'),
));


//Redirect
$post = array(
    'samlRequestLogout'  => $req,  // TODO: probar a restaurar este si no va
    //'logoutRequest'  => $req,
    'country'   => 'ES',// TODO: añadido al comnparar con el kit. ver si se puede quitar
    'RelayState'   => 'dummystate',// TODO: añadido al comnparar con el kit. ver si se puede quitar. Si se ha de wquedar, intentar propagarlo como hago con el sso
    
);

Logger::debug("post: ".print_r($post, true));


//Redirecting to Clave IdP (Only HTTP-POST binding supported)
(new HTTP)->submitPOSTData($endpoint, $post);


assert(false);
