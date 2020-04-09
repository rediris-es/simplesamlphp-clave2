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
    ),

);
