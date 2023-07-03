<?php

$config = array(
    
    // Base configuration of an eIDAS Auth Source (most of the metadata 
	// that is defined here in SAML:SP sources, we have moved it to a
	// hosted SP file)
    'clave' => array(
        'clave:SP',
        
        //[Mandatory] The url of the country selector (either absolute URL, or
        //relative URL starting from module.php)
        'discoURL' =>  'clave/sp/countryselector.php',
        
        //[Mandatory] Which local eIDAS hosted SP metadata entry will
        //we be used to connect to the eIDAS remote IdP (from
        //clave-sp-hosted.php)
        'hostedSP' => 'eidasSP',

        // [Optional] The unique ID of this SP --same value as in clave-sp-hosted.
        // Will work anyway, but add it if any filter expects the entityID of the
        // hosted SP (or if you want to remove the warning on the log entry in
        // ProcessingChain)
        'entityID' => 'https://eidas.sp/metadata.php',
        //'entityid' => 'https://eidas.sp/metadata.php', //SSP2.0.4 still expects lowercase

    ),

);
