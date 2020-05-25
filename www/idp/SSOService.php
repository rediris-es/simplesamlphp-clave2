<?php
/**
 * The SSOService is part of the SAML 2.0 - eIDAS IdP code, and it
 * receives incoming Authentication Requests from a SAML 2.0 SP,
 * parses, and process it, and then authenticates the user and sends
 * the user back to the SP with an Authentication Response.
 *
 * @author Francisco José Aragó Monzonís, RedIRIS <francisco.arago@externos.rediris.es>
 * @package Clave
 */


// TODO: This is a refactor of the clave-bridge script. Renamed to
// this for compatibility.When heavily tested, replace former with
// link to this one to give backwards compatibility

// TODO: Now, on SSP, metadata sources are parametrised in config
// (whether they come from a PHP file, an XML file, metadata query
// server, database). Integrate it or imitate its use for the
// eIDAS/Clave metadata sources, but for now, keep them simply as
// plain php files.

// TODO: when everything works, rename module and everything to eIDAS, remove clave references but for the specific clave impl.

// TODO: improve SSO and WAYF script to use SSPHP template 

//echo __FILE__;
//require_once('../../../../www/_include.php');  // TODO: this line maybe needed?

//print_r(get_included_files());

//assert(false);

// TODO: Implement the publication of IdP side metadata (for the remote SPs) (besides the actual SP side metadata published. Use the same? check if any differences)


SimpleSAML\Logger::info('eIDAS - IdP.SSOService: Accessing SAML 2.0 - eIDAS IdP endpoint SSOService');

//Hosted IdP config
$idpEntityId = "__DYNAMIC:1__";

$hostedIdpMeta = sspmod_clave_Tools::getMetadataSet($idpEntityId,"clave-idp-hosted");
SimpleSAML\Logger::debug('eIDAS IDP hosted metadata ('.$idpEntityId.'): '.print_r($hostedIdpMeta,true));


//Get the idp class
$idp = sspmod_clave_IdP::getById($idpEntityId);



//Filter the POST params to be forwarded to the remote IdP
//(based on the hosted IDP metadata)
$expectedRequestPostParams = $hostedIdpMeta->getArray('idp.post.allowed', array());

$forwardedParams = array();
foreach ($_POST as $name => $value){
    if(in_array($name,$expectedRequestPostParams))
        $forwardedParams[$name] = $value;
}


// TODO: support HTTP-REDIRECT binding (move the post-get part somewhere else? use the SAML2\Binding ?)

//Receive the AuthnRequest
if(!array_key_exists('SAMLRequest',$_POST))
   	throw new SimpleSAML\Error\BadRequest('SAMLRequest POST param not set.');
if($_POST['SAMLRequest'] == null || $_POST['SAMLRequest'] == "")
   	throw new SimpleSAML\Error\BadRequest('SAMLRequest POST param empty.');
$authnRequest = $_POST['SAMLRequest'];


//Is there a RelayState?
$relayState = '';
if (array_key_exists('RelayState', $_POST))
    $relayState = $_POST['RelayState'];



//Decode the request
$authnRequest = base64_decode($authnRequest);
SimpleSAML\Logger::debug("Received authnRequest from remote SP: ".$authnRequest);


//eIDAS protocol library object 
$eidas = new sspmod_clave_SPlib();


//Entity ID of the remote SP (requestor)
$spEntityId = $eidas->getIssuer($authnRequest);
SimpleSAML\Logger::info("Remote SP Issuer: ".$spEntityId);

//Load the remote SP metadata
$spMetadata = sspmod_clave_Tools::getSPMetadata($hostedIdpMeta,$spEntityId);
SimpleSAML\Logger::debug('Clave SP remote metadata ('.$spEntityId.'): '.print_r($spMetadata,true));



//Get the mode of operation this IdP must expect (based on the remote
//SP specific or the hosted IdP default)
$IdPdialect    = $spMetadata->getString('dialect',
                                        $hostedIdpMeta->getString('dialect'));
$IdPsubdialect = $spMetadata->getString('subdialect',
                                        $hostedIdpMeta->getString('subdialect'));
if ($IdPdialect === 'eidas')
    $eidas->setEidasMode();


//Trust the alleged requester certificate we have in local metadata
$certs = sspmod_clave_Tools::findX509SignCertOnMetadata($spMetadata);
$eidas->addTrustedRequestIssuer($spEntityId, $certs);



//Validate AuthnRequest
try{
    $eidas->validateStorkRequest($authnRequest);
} catch (Exception $e) {
    throw new SimpleSAML\Error\BadRequest($e->getMessage());
}



//Extract all relevant data for the retransmitted request (including stork extensions)
$reqData = $eidas->getStorkRequestData();

SimpleSAML\Logger::debug("SP Request data: ".print_r($reqData,true));


//Log for statistics: received AuthnRequest at the hosted IdP
//$aux = $eidas->getStorkRequestData($authnRequest);
SimpleSAML\Stats::log('clave:idp:AuthnRequest', array(
    'spEntityID' => $spEntityId,
    'idpEntityID' => $hostedIdpMeta->getString('issuer', ''),
    'forceAuthn' => TRUE,//$reqData['forceAuthn'],
    'isPassive' => $reqData['isPassive'],
    'protocol' => 'saml2-'.$IdPdialect,
    'idpInit' => FALSE,
));



$authnContext = null;
if(isset($reqData['LoA']))
    $authnContext = array(
        'AuthnContextClassRef' => array($reqData['LoA']),
        'Comparison'           => $reqData['Comparison'],
    );


$idFormat = sspmod_clave_SPlib::NAMEID_FORMAT_UNSPECIFIED;
if(isset($reqData['IdFormat']))
    $idFormat = $reqData['IdFormat'];

$idAllowCreate = FALSE;
if(isset($reqData['IdAllowCreate']))
    $idAllowCreate = $reqData['IdAllowCreate'];


//Set the state to be kept during the procedure    // TODO: if implementing multiple dialect classes, make the callback classnames depend on the dialect/subdialect
$state = array(

    //Standard by SSPHP    
    'Responder'                                   => array('sspmod_clave_IdP_eIDAS', 'sendResponse'), //The callback to send the response for this request
    SimpleSAML\Auth\State::EXCEPTION_HANDLER_FUNC => array('sspmod_clave_IdP_eIDAS', 'handleAuthError'),
    SimpleSAML\Auth\State::RESTART                => SimpleSAML\Utils\HTTP::getSelfURLNoQuery(),

    'SPMetadata'                  => $spMetadata->toArray(),
    'saml:RelayState'             => $relayState,
    'saml:RequestId'              => $reqData['id'],
    'saml:IDPList'                => $reqData['idplist'],
    'saml:ProxyCount'             => null,
    'saml:RequesterID'            => array(),
    'ForceAuthn'                  => TRUE,
    'isPassive'                   => $reqData['isPassive'],
    'saml:ConsumerURL'            => $reqData['assertionConsumerService'],
    'saml:Binding'                => SAML2\Constants::BINDING_HTTP_POST, // TODO: support HTTP_REDIRECT
    'saml:NameIDFormat'           => $idFormat,
    'saml:AllowCreate'            => $idAllowCreate,
    'saml:Extensions'             => $reqData,
    'saml:AuthnRequestReceivedAt' => microtime(true),
    'saml:RequestedAuthnContext'  => $authnContext,

    //My additions
    'sp:postParams'        =>   $forwardedParams,
    'idp:postParams:mode'  =>   'forward', //To mark the ACS whether to return the extra POST params as attributes or as POST params to be forwarded
    'eidas:request'        =>   $authnRequest,
    'eidas:requestData'    =>   $reqData,


    
);


SimpleSAML\Logger::debug('------------------STATE at SSOService: '.print_r($state,true));

// Invoke the IdP Class handler.
$idp->handleAuthenticationRequest($state);


assert('FALSE');




//************** Jump to the authSource (wrapped in Simple and defined in idp metadata): *****************
//Simple-> login (define  $state['ReturnCallback'] as PostAuth)
//authsource->initLogin ($state['ReturnCallback'] as PostAuth is passed and stored as $state['SimpleSAML\Auth\Source.Return'])
//authsource->authenticate : implemented by (instance)
//authsource(instance)-> startSSO
//%%%%%% jump to remote IDP
//%%%%%% back to the saml2-acs.php script
//authsource(instance)->handleResponse
//%%%%%% call Authsource level filters, given the idp and authsource-sp metadata
//authsource(instance)->onProcessingCompleted (autocallback)
//authsource->completeAuth
//authsource calls the callback defined in  $state['LoginCompletedHandler']: which is authsource->loginCompleted ; (defined in: authsource->initLogin).
//authsource->loginCompleted: calls the callback or redirect URL in SimpleSAML\Auth\Source.Return. (This callback was defined in initLogin, passed as param, and its value is PostAuth)

//******** Back to the IdP impl *********
//idp-->postAuth($state); executes filters and calls PostAuthProc.
//idp->PostAuthProc(); callback for after authfilters are done. Calls the callback stored in $state['Responder']
//idp-> callback $state['Responder']  (established as ('sspmod_saml_IdP_SAML2', 'sendResponse') before calling $idp->handleAuthenticationRequest($state);
//sspmod_saml_IdP_SAML2->sendResponse  (sspmod_saml_IdP_SAML2::sendResponse($state);)
//%%%%%%deliver response to the remote SP
