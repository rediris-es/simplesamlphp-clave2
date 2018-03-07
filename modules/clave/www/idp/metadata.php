<?php

/**
 * Metadata service for eIDAS IdP
 *
 */




//Read the Hosted IdP config
$claveConfig = sspmod_clave_Tools::getMetadataSet("__DYNAMIC:1__","clave-idp-hosted");
SimpleSAML_Logger::debug('Clave Idp hosted metadata: '.print_r($claveConfig,true));



//Obtain the full URL of this same page
$metadataUrl = SimpleSAML_Module::getModuleURL('clave/idp/metadata.php');

//Get the SSO url
$ssoserviceurl = SimpleSAML_Module::getModuleURL('clave/idp/clave-bridge.php');

//Get the signing certificate and key
$idpcertpem = sspmod_clave_Tools::readCertKeyFile($claveConfig->getString('certificate', NULL));
$idpkeypem  = sspmod_clave_Tools::readCertKeyFile($claveConfig->getString('privatekey', NULL));




$eidas = new sspmod_clave_SPlib();

$eidas->setEidasMode();


$eidas->setSignatureKeyParams($idpcertpem, $idpkeypem, sspmod_clave_SPlib::RSA_SHA512);
$eidas->setSignatureParams(sspmod_clave_SPlib::SHA512,sspmod_clave_SPlib::EXC_C14N);

$eidas->setServiceProviderParams("",$metadataUrl , "");


//Print the generated metadata
header('Content-type: application/xml');
echo $eidas->generateIdPMetadata($ssoserviceurl);
