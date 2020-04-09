<?php

/**
 * Metadata service for eIDAS SP
 *
 */

// Expects, at the end of the URL, a string: [acs-ID]/[clave-sp-hosted-ID]/[authsource-ID]


//Read the hosted-sp ID, to know which metadata to generate
// ...sp/metadata.php/bridge/hostedSpID/authSource
$pathInfoStr = str_replace(".","", substr($_SERVER['PATH_INFO'], 1)); // dots not allowed in this path
$pathInfo = explode("/", $pathInfoStr);

$acsID      = "";
$hostedSpId = "";
$authSource = "";
if (count($pathInfo) >= 1)
    $acsID      = $pathInfo[0];
if (count($pathInfo) >= 2)
    $hostedSpId = $pathInfo[1];
if (count($pathInfo) >= 3)
    $authSource = $pathInfo[2];

if ($acsID === NULL || $acsID === "")
    throw new SimpleSAML_Error_Exception("No eIDAS ACS ID provided on the url path info.");

//Read the hosted sp metadata
if($hostedSpId === NULL || $hostedSpId === "")
    throw new SimpleSAML_Error_Exception("No eIDAS hosted SP ID provided on the url path info.");
$hostedSPmeta = sspmod_clave_Tools::getMetadataSet($hostedSpId,"clave-sp-hosted");
SimpleSAML\Logger::debug('Clave SP hosted metadata: '.print_r($hostedSPmeta,true));



//Obtain the full URL of this same page
$metadataUrl = SimpleSAML_Module::getModuleURL('clave/sp/metadata.php/'.$pathInfoStr);

//Get the ACS url
$returnPage = SimpleSAML_Module::getModuleURL('clave/sp/'.$acsID.'-acs.php/'.$authSource);

//Get the signing certificate and key
$spcertpem = sspmod_clave_Tools::readCertKeyFile($hostedSPmeta->getString('certificate', NULL));
$spkeypem  = sspmod_clave_Tools::readCertKeyFile($hostedSPmeta->getString('privatekey', NULL));




$eidas = new sspmod_clave_SPlib();

$eidas->setEidasMode();


$eidas->setSignatureKeyParams($spcertpem, $spkeypem, sspmod_clave_SPlib::RSA_SHA512);
$eidas->setSignatureParams(sspmod_clave_SPlib::SHA512,sspmod_clave_SPlib::EXC_C14N);

$eidas->setServiceProviderParams("",$metadataUrl , $returnPage);


//Print the generated metadata
header('Content-type: application/xml');
echo $eidas->generateSPMetadata();

