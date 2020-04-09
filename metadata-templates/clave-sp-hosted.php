<?php
/**
 * SAML 2.0 eIDAS SP configuration for simpleSAMLphp.
 *
 * All possible options included in this example in comments
 */



$claveMeta['eidasSP'] = array(
    
    // [Mandatory] The unique ID of this SP
    'entityid' => 'https://eidas.sp/metadata.php',
    
    
    // [Mandatory] In STORK, this identifier must match the
    // friendlyName of the request signing certificate authorised on
    // the IdP trust store.
	// TODO: despite not being used in eIDAS, still required here. Put anything
    'providerName' => 'eIDAS_SP',
    
    
    // [Optional] Default: TRUE. Determines if the bridge should
    // attache the providewrName of the remote SP to its own. It is an
    // obscure feature required by clave 2.0 platform in Spain
    //'providerName.forward' => true,
    
    
    // [Mandatory] Identifier of the remote IdP this SP will query,
    // from the list on clave-idp-remote.php
    'idpEntityID' => 'eIDASnode',
    
    
    // [Optional] The issuer field of the SP request to be sent. If
    // not set, the issuer field on the remoteSP metadata will be
    // used, and if neither set, the issuer field on tyhe original
    // request will be passed
	// TODO: At some point, this behaviour changed due to the Spanish 
	// eID and diverged from the practice of SSP of sending the metadata
    // URL if unset, and this is precisely the requirement of eIDAS. So, 
	// until I add anotgher flag to control this, metadata url should be set here.
    'issuer' => 'https://eidas.sp/metadata.php',
    
    
    // [Optional] List of the post parameters that will be
    // retransmitted along with the response (if not set, none will
    // be)
    //'sp.post.allowed' => array('isLegalPerson', 'oid'),
    
    
    // [Mandatory] Dialect to be used by the SP on the request
    //Possible values: 'stork','eidas'
    'dialect' => 'eidas',
    
    
    //[Mandatory] Details relative to the specific implementation of
    //the dialect
    //Possible values: 'stork','clave-1.0','eidas','clave-2.0'
    'subdialect' => 'eidas',
    
    
    // [Optional] STORK minimum accepted level of quality on the
    // authentication (1: username+pwd <-> 4:smartcard). Automatically
    // converted to eIDAS LoA values (<=2,3,>=4)
    'QAA' => 1,
    
    
    // [Mandatory] SP AuthnReq Signing Certificate and key (it must be
    // authorised at the Clave IdP)
    'certificate' => 'eidas_sp.pem',
    'privatekey'  => 'eidas_sp.key',
    
    
    //Expect encrypted assertions (and decrypt them with the
    //privatekey)
    //'assertions.encrypted' => true,
    
    
    //Expect encrypted assertions only (plain ones will be discarded)
    //'assertions.encrypted.only' => false,
    
    
    // [Optional] STORK parameters. If not set, request values will be
    // retransmitted (or defaulted if not present). Will be overriden
    // by the remote SP metadata values
    //'spCountry'     => 'ES',
    //'spSector'      => 'EDU',
    //'spInstitution' => 'RedIris',
    //'spApplication' => 'SIR2',
    //'spID'          => 'ES-EDU-RedIris-SIR2',
    
    //'citizenCountryCode' => 'ES',
    
    //'eIDSectorShare'      => true,
    //'eIDCrossSectorShare' => true,
    //'eIDCrossBorderShare' => true,
    
	
    // [Optional] eIDAS parameters. If not set, request values will be
    // used if any, else, default values (LoA default value will be
    // the QAA).
    'SPType'        => 'public',
    'NameIDFormat'  => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    'LoA'  =>  'http://eidas.europa.eu/LoA/low',
    
    
    //[Optional] If enabled, if the remote SP does not provide a
    //'country' code as a POST param, we will prompt with a country
    //selector
    'showCountrySelector' => false,
    
    
    //[Optional] The list of countries to be shown on the
    //country selector
    'countries' => array('ES' => 'España'), 
    
    
    
    // ---Clave 1.0 IdP selector configuration---
    
    //Possible values: 'Stork' 'aFirma' 'SS' 'AEAT'
    //(Values set on each remote SP metadata override these)

    
    //[Optional] List of IdPs that will be shown on the IdP selector
    //'idpList' => array('Stork', 'aFirma', 'AEAT'),
    
    //[Optional] List of IdPs that won't be shown on the IdP selector
    //'idpExcludedList' => array('SS'),
    
    //[Optional] Force a specific IdP [bypass selector]
    //'force' => 'aFirma',
    
    
    
    
    // [Optional] If set, will keep the RelayState in the state at the
    // bridge, and send a dummy compliant RelayState String to the (default
    // false) Affects all remote SPs and IdPs
    //'holdRelayState' => true,
);

