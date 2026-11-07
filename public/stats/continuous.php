<?php

// Here we return the metrics which we
// don't have a history of values for, so the
// read value is always a live and absolute value.
//
// The SPs are read through SimpleSAMLphp's metadata API (the configured
// metadata directory/sources), not by parsing a fixed file path.

use SimpleSAML\Metadata\MetaDataStorageHandler;

// Output is buffered until the end of the request: SimpleSAMLphp may still
// need to send headers (session cookie for deferred log messages) after this
// script has written the CSV.
ob_start();

$SP_entityIDs = array_keys(MetaDataStorageHandler::getMetadataHandler()->getList('saml20-sp-remote'));

//We now try to extract domain names for the institutions from the entityIDs
$institutions = array();
foreach ($SP_entityIDs as $entityID){

    //Assuming it has the form of a url (or a domain + path), extract domain
    $domain = preg_replace('!(http(s)?://)?([^/:]+)(:[0-9]+)?(/)?.*$!',"\$3", $entityID);

    if($domain == null || $domain === "")
        continue;
    //Now we try to isolate only the name of the institutions (trying to remove subdomains)
    $institution = preg_replace('!^.*?([-a-zA-Z0-9]+\.[a-zA-Z]+)$!',"\$1", $domain);

    if($institution == null || $institution === "")
        continue;

    $institutions [] = $institution;
}
// We remove duplicates
$institutions = array_unique($institutions);



header("Content-type: text/csv");
header("Content-disposition: attachment; filename = stats_clave_SPs.csv");

// Number of SPs
$number_sp = sizeof($SP_entityIDs);
echo "number_sp, $number_sp\n";


// Number of unique institutions
$number_inst = sizeof($institutions);
echo "number_inst, $number_inst\n";
