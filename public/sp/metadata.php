<?php

/**
 * Metadata service for eIDAS SP
 *
 */

// Expects, at the end of the URL, a string: [acs-ID]/[clave-sp-hosted-ID]/[authsource-ID]


//Read the hosted-sp ID, to know which metadata to generate
// ...sp/metadata.php/bridge/hostedSpID/authSource
use SimpleSAML\Module\clave\SPlib;
use SimpleSAML\Module\clave\Tools;

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
    throw new SimpleSAML\Error\Exception("No eIDAS ACS ID provided on the url path info.");

//Read the hosted sp metadata
if($hostedSpId === NULL || $hostedSpId === "")
    throw new SimpleSAML\Error\Exception("No eIDAS hosted SP ID provided on the url path info.");
$hostedSPmeta = Tools::getMetadataSet($hostedSpId,"clave-sp-hosted");
SimpleSAML\Logger::debug('Clave SP hosted metadata: '.print_r($hostedSPmeta,true));



//Obtain the full URL of this same page
$metadataUrl = SimpleSAML\Module::getModuleURL('clave/sp/metadata.php/'.$pathInfoStr);

//Get the ACS url
$returnPage = SimpleSAML\Module::getModuleURL('clave/sp/'.$acsID.'-acs.php/'.$authSource);

//Get the signing certificate and key
$spcertpem = Tools::readCertKeyFile(Tools::getString($hostedSPmeta,'certificate', NULL));
$spkeypem  = Tools::readCertKeyFile(Tools::getString($hostedSPmeta,'privatekey', NULL));




$eidas = new SPlib();

$eidas->setEidasMode();


$eidas->setSignatureKeyParams($spcertpem, $spkeypem, SPlib::RSA_SHA512);
$eidas->setSignatureParams(SPlib::SHA512,SPlib::EXC_C14N);

$eidas->setServiceProviderParams("",$metadataUrl , $returnPage);


//Print the generated metadata
header('Content-type: application/xml');
echo $eidas->generateSPMetadata();

