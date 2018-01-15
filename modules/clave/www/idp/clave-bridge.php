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



//Whether to show the country selctor
$showCountrySelector = $claveSP->getBoolean('showCountrySelector', false);




//Get the mode for the SP
$SPdialect    = $claveSP->getString('dialect');
$SPsubdialect = $claveSP->getString('subdialect');







if($endpoint == NULL)
    throw new SimpleSAML_Error_Exception("No clave SSO endpoint defined in clave bridge configuration.");
if($providerName == NULL)
    throw new SimpleSAML_Error_Exception("No provider Name defined in clave bridge configuration.");
if($certPath == NULL || $keyPath == NULL)
    throw new SimpleSAML_Error_Exception("No clave SSO certificate or key defined for the SP interface in clave bridge configuration.");



$spcertpem = sspmod_clave_Tools::readCertKeyFile($certPath);
$spkeypem  = sspmod_clave_Tools::readCertKeyFile($keyPath);




//Wrap the request parameters
$postParams   = $_POST;

//On the country selector comeback, is not defined
if(isset($_REQUEST['SAMLRequest']))
    $authnRequest = $_REQUEST['SAMLRequest'];





//Code to identify the second call, if we were redirected to the
//country selector
if(isset($_REQUEST['AuthID']) && $_REQUEST['AuthID'] !== ""){
    
    //Get the auth process state left when we jumped to the Country Selector
    $state = SimpleSAML_Auth_State::loadState($_REQUEST['AuthID'], 'clave:bridge:country');

    //Restore the original request parameters (and now, country will also be there)
    $authnRequest = $state['sp:authnRequest'];
    $postParams   = $state['sp:postParams'];
}
// TODO SEGUIR





// ************** IdP ***************


$claveIdP = new sspmod_clave_SPlib();


if(!isset($authnRequest))
   	throw new SimpleSAML_Error_BadRequest('No SAMLRequest POST param received.');

//Get allowed post params to be forwarded to Clave
$forwardedParams = array();
foreach ($postParams as $name => $value){
    if(in_array($name,$expectedRequestPostParams))
        $forwardedParams[$name] = $value;
}



$request = base64_decode($authnRequest);
SimpleSAML_Logger::debug("SP Request: ".$request);




//The entity ID of the requestor
$spEntityId = $claveIdP->getIssuer($request);
SimpleSAML_Logger::info("SP Issuer: ".$spEntityId);

//Remote SP config
$spMetadata = sspmod_clave_Tools::getSPMetadata($claveConfig,$spEntityId);
SimpleSAML_Logger::debug('Clave SP remote metadata ('.$spEntityId.'): '.print_r($spMetadata,true));



//Get the mode for the IdP (remote SP specific or hosted IdP default)   // TODO ******
$IdPdialect    = $spMetadata->getString('dialect',
                                        $claveConfig->getString('dialect'));
$IdPsubdialect = $spMetadata->getString('subdialect',
                                        $claveConfig->getString('subdialect'));


//Set the dialect of the received SAML2 AuthnRequest, based on the remote SP EntityId
if ($IdPdialect === 'eidas')
    $claveIdP->setEidasMode();   // TODO eIDAS *** OK si se hace aquí y no antes?


//Trust the alleged requester certificate we have in local metadata
$cert = sspmod_clave_Tools::findX509SignCertOnMetadata($spMetadata);
$claveIdP->addTrustedRequestIssuer($spEntityId, $cert);




//Validate Clave AuthnRequest
$claveIdP->validateStorkRequest($request);

//Extract all relevant data for the retransmitted request (including stork extensions)
$reqData = $claveIdP->getStorkRequestData();

SimpleSAML_Logger::debug("SP Request data: ".print_r($reqData,true));






//****** Show Country selector if required *****

$country = NULL;
if(isset($_REQUEST['country']))
    $country = $_REQUEST['country'];
else if($showCountrySelector){

    //Store state for the comeback
    $state = array();
    $state['sp:authnRequest'] = $authnRequest;
    $state['sp:postParams']   = $forwardedParams;

    $stateId = SimpleSAML_Auth_State::saveState($state, 'clave:bridge:country', true);
    SimpleSAML_Logger::debug("Generated Req ID: ".$stateId);


    //Redirect to the country selector
    $discoURL = SimpleSAML_Module::getModuleURL('clave/sp/countryselector.php');
    $returnTo = SimpleSAML_Module::getModuleURL('clave/idp/clave-bridge.php', array('AuthID' => $stateId));
		
    $params = array( // TODO ver si son necesarios y describirlos
        //'entityID' => $this->entityId,     //The clave hosted SP entityID
        'return' => $returnTo,             //The script to go on with the auth process (contains the authsource ID)
        //'returnIDParam' => 'country'       //The param name where the country ID will be searched
    );

    \SimpleSAML\Utils\HTTP::redirectTrustedURL($discoURL, $params);
}



//Log for statistics: received AuthnRequest at the clave IdP
$aux = $claveIdP->getStorkRequestData($request);
SimpleSAML_Stats::log('clave:idp:AuthnRequest', array(
    'spEntityID' => $spEntityId,
    'idpEntityID' => $claveConfig->getString('issuer', ''),
    'forceAuthn' => TRUE, //$aux['forceAuthn'],
    'isPassive' => $aux['isPassive'],
    'protocol' => 'saml2-'.$IdPdialect,
    'idpInit' => FALSE,
));









// ******************* SP *******************


//These params will be taken from the request but can be overwritten if set on the hosted SP conf.
$bridgeData['eIDSectorShare'] = "";
$bridgeData['eIDCrossSectorShare'] = "";
$bridgeData['eIDCrossBorderShare'] = "";
if ($SPdialect === 'stork'){
    
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

    //The issuer is set to be the SP's entityId, if not fixed on the
    //IdP configuration (on eidas, it is set later)
    $reqIssuer = $claveConfig->getString('issuer', $reqData['issuer']);
}

//eIDas request parameters. If set on the hostedSP, remote sp request values are overriden
if ($SPdialect === 'eidas'){

    if($reqData['IdFormat'] === NULL || $reqData['IdFormat'] === "")
        $reqData['IdFormat'] = sspmod_clave_SPlib::NAMEID_FORMAT_PERSISTENT;
        
    $bridgeData['SPType']       = $claveSP->getString('SPType', $reqData['SPType']);
    $bridgeData['NameIDFormat'] = $claveSP->getString('NameIDFormat', $reqData['IdFormat']);  // TODO SEGUIR: cuando el sp está en stork, $reqData['IdFormat'] es vacío, y falla luego. hay que poner otro default
    $bridgeData['LoA']          = $claveSP->getString('LoA', $reqData['LoA']);
}//TODO eIDAS





//Calculate return page for the new request
$returnPage = SimpleSAML_Module::getModuleURL('clave/sp/bridge-acs.php/');



//Calculate metadata URL
if ($SPdialect === 'eidas'){
    $metadataURL = SimpleSAML_Module::getModuleURL('clave/sp/metadata.php/'.'bridge/'.$hostedSP.'/');
    $reqIssuer = $metadataURL;
} // TODO eIDAS



//Build the new authn request
$clave = new sspmod_clave_SPlib();



if ($SPdialect === 'eidas'){
    $clave->setEidasMode();
    $clave->setEidasRequestParams($bridgeData['SPType'],
                                  $bridgeData['NameIDFormat'],
                                  $bridgeData['LoA']);
} // TODO eIDAS



$clave->setSignatureKeyParams($spcertpem, $spkeypem, sspmod_clave_SPlib::RSA_SHA512);
$clave->setSignatureParams(sspmod_clave_SPlib::SHA512, sspmod_clave_SPlib::EXC_C14N);


$clave->setServiceProviderParams($providerName,
                                 $reqIssuer,
                                 $returnPage);


//if($reqData['forceAuthn'])
$clave->forceAuthn();


if ($SPdialect === 'stork'){
    $clave->setSPLocationParams($bridgeData['spCountry'],$bridgeData['spSector'],
                                $bridgeData['spInstitution'],$bridgeData['spApplication']);  

    $clave->setSPVidpParams($bridgeData['spID'],$bridgeData['citizenCountryCode']);
}


$clave->setSTORKParams ($endpoint, $reqData['QAA'],
                        $bridgeData['eIDSectorShare'],
                        $bridgeData['eIDCrossSectorShare'],
                        $bridgeData['eIDCrossBorderShare']);

$mandatory = array();
foreach($reqData['requestedAttributes'] as $attr){

    if ($SPdialect === 'stork'){
        $name = sspmod_clave_SPlib::getFriendlyName($attr['name']);
        $clave->addRequestAttribute($name, $attr['isRequired']);
    }
    if ($SPdialect === 'eidas')
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
    'forceAuthn' => TRUE, //$reqData['forceAuthn'],
    'isPassive' => FALSE,
    'protocol' => 'saml2-'.$SPdialect,
    'idpInit' => FALSE,
));



//Redirect (forwarded params are appended, priority to the ones set here)
$post = array(
    'SAMLRequest'  => $req,
) + $forwardedParams;

// TODO eIDAS
//If SP sent it or the country selector was activated (otherwise, we
//rely on the eIDAS node country selector)
if ($country !== NULL and $country !== "")
    $post ['country'] = $country;


SimpleSAML_Logger::debug("forwarded: ".print_r($forwardedParams, true));
SimpleSAML_Logger::debug("post: ".print_r($post, true));


//Redirecting to Clave IdP (Only HTTP-POST binding supported)
SimpleSAML_Utilities::postRedirect($endpoint, $post);


assert(false);


/*
$metadata = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler();
$spMetadata = $metadata->getMetaDataConfig($spEntityId, 'saml20-sp-remote');
*/