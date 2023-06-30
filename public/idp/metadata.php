<?php

/**
 * Metadata service for eIDAS IdP
 *
 */




//Read the Hosted IdP config
use SimpleSAML\Module\clave\SPlib;
use SimpleSAML\Module\clave\Tools;

$claveConfig = Tools::getMetadataSet("__DYNAMIC:1__","clave-idp-hosted");
SimpleSAML\Logger::debug('Clave Idp hosted metadata: '.print_r($claveConfig,true));



//Obtain the full URL of this same page
$metadataUrl = SimpleSAML\Module::getModuleURL('clave/idp/metadata.php');

//Get the SSO url
$ssoserviceurl = SimpleSAML\Module::getModuleURL('clave/idp/clave-bridge.php');

//Get the signing certificate and key
$idpcertpem = Tools::readCertKeyFile(Tools::getString($claveConfig,'certificate', NULL));
$idpkeypem  = Tools::readCertKeyFile(Tools::getString($claveConfig,'privatekey', NULL));




$eidas = new SPlib();

$eidas->setEidasMode();


$eidas->setSignatureKeyParams($idpcertpem, $idpkeypem, SPlib::RSA_SHA512);
$eidas->setSignatureParams(SPlib::SHA512,SPlib::EXC_C14N);

$eidas->setServiceProviderParams("",$metadataUrl , "");


//Print the generated metadata
header('Content-type: application/xml');
echo $eidas->generateIdPMetadata($ssoserviceurl);
