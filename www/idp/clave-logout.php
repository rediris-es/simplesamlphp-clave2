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


if($providerName == NULL)
    throw new SimpleSAML_Error_Exception("No provider Name defined in clave bridge configuration.");
if($certPath == NULL || $keyPath == NULL)
    throw new SimpleSAML_Error_Exception("No clave certificate or key defined for the SP interface in clave bridge configuration.");




//Get the hosted SP cert and key
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
    $claveIdP->setEidasMode();



//Another part of the dirty patch to go around Clave devlopers
//madness: If subdialect is clave 2, the return page for the SLO
//response must be the same as for the SSO acs, not the proper one, so
//smash it
if ($IdPdialect === 'eidas'){
    //Calculate return page for the new request in clave 2, which is SSO ACM
    $returnPage = SimpleSAML_Module::getModuleURL('clave/sp/clave-acs.php/'.$claveConfig->getString('auth','')); // TODO: works?

}


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











//Now, if no SLO endpoint is defined,  we make it just go back silently to the SP
if($endpoint == NULL){
    //throw new SimpleSAML_Error_Exception("No clave SLO endpoint defined in clave bridge configuration.");


    // ****** Build response for the SP *******

    //Certificate and key to sign the response directed to the remote SP.
    $idpCertPath = $claveConfig->getString('certificate', NULL);
    $idpKeyPath  = $claveConfig->getString('privatekey', NULL);
    $idpcertpem = sspmod_clave_Tools::readCertKeyFile($idpCertPath);
    $idpkeypem  = sspmod_clave_Tools::readCertKeyFile($idpKeyPath);
    if($idpCertPath == NULL || $idpKeyPath == NULL)
        throw new SimpleSAML_Error_Exception("No clave SSO response signing certificate or key defined for the IdP interface in clave bridge configuration.");


    $issuer = $claveConfig->getString('issuer', 'NOT_SET');
    

    //Get the endpoint from the SP request, not from the metadata (stork
    //always does this). Also, the endopint is in the issuer field.
    $destination = $reqData['issuer'];
    $inResponseTo = $reqData['id'];

    $claveIdPresp = new sspmod_clave_SPlib();

    $claveIdPresp->setSignatureKeyParams($idpcertpem, $idpkeypem, sspmod_clave_SPlib::RSA_SHA256);
    $claveIdPresp->setSignatureParams(sspmod_clave_SPlib::SHA256,sspmod_clave_SPlib::EXC_C14N);
    
    
    $respStatus = array();
    $respStatus ["MainStatusCode"] = sspmod_clave_SPlib::ST_SUCCESS;
    $respStatus ["SecondaryStatusCode"] = NULL;
    
    
    $spResponse = $claveIdPresp->generateSLOResponse($inResponseTo,$issuer,$respStatus,$destination);


    //Log for statistics: sent LogoutResponse to the remote SP
    SimpleSAML_Stats::log('saml:idp:LogoutResponse:sent', array(
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
}















//**** Build request for clave *******


$claveSP = new sspmod_clave_SPlib();

if ($IdPdialect === 'eidas')
    $claveSP->setEidasMode();

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
    'samlRequestLogout'  => $req,  // TODO: probar a restaurar este si no va
    //'logoutRequest'  => $req,
    'country'   => 'ES',// TODO: añadido al comnparar con el kit. ver si se puede quitar
    'RelayState'   => 'dummystate',// TODO: añadido al comnparar con el kit. ver si se puede quitar. Si se ha de wquedar, intentar propagarlo como hago con el sso
    
);

SimpleSAML_Logger::debug("post: ".print_r($post, true));


//Redirecting to Clave IdP (Only HTTP-POST binding supported)
SimpleSAML_Utilities::postRedirect($endpoint, $post);


assert(false);
