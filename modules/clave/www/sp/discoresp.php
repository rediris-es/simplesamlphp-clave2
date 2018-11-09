<?php

/**
 * Return page of the eIDAS country selector. Will go on with the authentication process
 *
 */


//GET parameter set at the AuthSource startDisco call
if (!array_key_exists('AuthID', $_REQUEST)) {
	throw new SimpleSAML_Error_BadRequest('Missing AuthID to country selector response handler');
}

//The parameter we obtained at the country selector
if (!array_key_exists('country', $_REQUEST)) {
	throw new SimpleSAML_Error_BadRequest('Missing country to country selector response handler');
}


//Get the auth process state left when we jumped to the Country Selector
$state = SimpleSAML_Auth_State::loadState($_REQUEST['AuthID'], 'clave:sp:sso');

// Find authentication source ID in state (set on the AuthSource 'authenticate' call)
assert('array_key_exists("clave:sp:AuthId", $state)');
$sourceId = $state['clave:sp:AuthId'];


// Find remote idp ID in state (set on the AuthSource 'authenticate' call)
assert('array_key_exists("clave:sp:idpEntityID", $state)');
$idpEntityId = $state['clave:sp:idpEntityID'];


//Instantiate the AuthSource
$source = SimpleSAML_Auth_Source::getById($sourceId);
if ($source === NULL) {
	throw new Exception('Could not find authentication source with id ' . $sourceId);
}
if (!($source instanceof sspmod_clave_Auth_Source_SP)) {
	throw new SimpleSAML_Error_Exception("Source -$sourceId- type (sspmod_clave_Auth_Source_SP) changed?");
}


//Save the country code
$state['country'] = $_REQUEST['country'];  // TODO SEGUIR usar este country en el startSSO, adaptar tb el discovery en el bridge.  // TODO: on startSSO, make sure this attr is not duplicated in the forwarded ones.



/*
//Get the destination remote IDP metadata
$idpMetadata = sspmod_clave_Tools::getMetadataSet($idpEntityId,"clave-idp-remote");

$idp = array('endpoint' => $idpMetadata->getString('SingleSignOnService', NULL),
             'cert'     => $idpMetadata->getString('certData', NULL),
             'country'  => $_REQUEST['country']);
*/ // TODO: REMOVE. now only this:
$idp = $idpEntityId;



//Return to the AuthSource and call the function that performs the request
$source->startSSO($idp, $state);
assert('FALSE');

