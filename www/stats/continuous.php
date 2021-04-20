<?php

// Here we return the metrics which we
// don't have a history of values for, so the
// read value is always a live and absolute value.

//const SP_METADATA_FILENAME = "/root/config/clave2Bridge/metadata/saml20-sp-remote.php";
const SP_METADATA_FILENAME = "/var/www/clave2Bridge/metadata/saml20-sp-remote.php";

$sp_metadata = file_get_contents(SP_METADATA_FILENAME);


// Clean read file from block comments
$sp_metadata = preg_replace('!/\*.*?\*/!s', '', $sp_metadata);
// Clean read file from line comments
$sp_metadata = preg_replace('!(\r\n|\r|\n)\h*//[^\r\n]*(\r\n|\r|\n)!', "\$1", $sp_metadata);


//We now filter the entity IDs for the SPs
preg_match_all('/\$metadata\[["\']([^"\']*)["\']\]/', $sp_metadata, $matches);
//We get the number of inner matches, not the full matches
$SP_entityIDs = $matches[1];

//print_r($matches);

//We now try to extract domain names for the institutions from the entityIDs
$institutions = array();
foreach ($SP_entityIDs as $entityID){

    //echo "entityID: $entityID\n";

    //Assuming it has the form of a url (or a domain + path), extract domain
    //$domain = preg_replace('!(http(s)?://)?([^/]+)(/)?.*$!',"\$3", $entityID);
    $domain = preg_replace('!(http(s)?://)?([^/:]+)(:[0-9]+)?(/)?.*$!',"\$3", $entityID);

    //echo "domain: $domain\n";
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
//print_r($institutions);



header("Content-type: text/csv");
header("Content-disposition: attachment; filename = stats_clave_SPs.csv");

// Number of SPs
$number_sp = sizeof($SP_entityIDs);
echo "number_sp, $number_sp\n";


// Number of unique institutions
$number_inst = sizeof($institutions);
echo "number_inst, $number_inst\n";
