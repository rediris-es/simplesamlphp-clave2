<?php
/**
 * SAML 2.0 eIDAS remote SP metadata for simpleSAMLphp.
 *
 * Compatible with the saml20-sp-remote format.
 * saml20-sp-remote can be used as the combined source of remote
 * SP metadata for eIDAS through a config parameter 
 * in clave-idp-hosted
 * 
 * Also notice that this library was built first for STORK project,
 * the originator of eIDAS, and also supports Spanish government eID
 * systems Clave and Clave 2.0, based respectively on both 
 * specifications. So you will find some metadata fields
 * that are useless for eIDAS, or fit some obscure patching needs 
 * for the poor compliance of the specs the Spanish eID systems have
 */

$claveMeta['https://eidas.sp/metadata.php'] = array (
  'entityid' => 'https://eidas.sp/metadata.php',


  // [Optional] Added to do a dirty patch on the Clave 2 java kit. When
  // no issuer is sent, the audience field was empty. A custom value can
  // be added here instead of the entityID
  //'Audience' => "https://eidas.sp/acs.php",
  
  // -=== EIDAS SPECIFIC METADATA ===-

  // [Optional] If unset, the list of attributes on the SP request will 
  // be retransmitted. If set, list of attributes to be requested for 
  // this remote SP(and that will be returned), if NULL, minimum eIDAS
  // data set will be requested and all IdP returned attributes will be
  // delivered. Empty array won't allow anything back. 
  
  //'attributes' => array('PersonIdentifier', 'FirstName', 'FamilyName','DateOfBirth'),
  
  
  // [Optional] The issuer of the SP request our hosted SP will
  // perform. This value overrides the clave-sp-hosted value. If
  // neither are set, the requester's entityID will be used as issuer
  // of this one. Be aware that in eIDAS, issuer must be the metadata
  // URL of the SP
  
  //'issuer' => 'custom_entityID',
  
    
  // [Optional] Dialect of SAML 2.0 to be expected by the IdP on the
  // request, and used on the response. This will override the value
  // in hosted IdP metadata.
  // Possible values: 'stork','eidas'
  'dialect' => 'eidas',
  
  
  // [Optional] Details relative to the specific implementation of
  // the dialect
  // Possible values: 'stork','clave-1.0','eidas','clave-2.0'

  'subdialect' => 'eidas',
  
  
  // [Optional] Set, for this SP, if the IdP must encrypt the outbound
  // assertions using the SP's certificate, and the specific key
  // algorithm to use (default AES-256)
  // NOTICE that 'keyAlgorith' is only valid for eIDAS SPs, for websso
  // SPs, see
  // https://simplesamlphp.org/docs/stable/simplesamlphp-reference-sp-remote#section_2_1

  //'assertion.encryption' => true,
  //'assertion.encryption.keyAlgorith' => 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
  
  
  // [Optional] If set, will keep the RelayState in the state at the
  // bridge, and send a dummy compliant (<80 chars) RelayState String
  // to the (default false)

  //'holdRelayState' => true,
  
  
  // -=== STORK SPECIFIC METADATA ===-

  // [Optional] True if the response assertions must be parsed to add the STORK
  // extensions or false to keep the assertions as received (not
  // altering any possible existing signature)
  
  //'assertion.storkize' => true,
  
  
  
  // -=== CLAVE-1.0 SPECIFIC METADATA ===-
  
  //Possible values: 'Stork' 'aFirma' 'SS' 'AEAT'
  //(Values set here override values set at hosted SP metadata)
    
  //[Optional] List of IdPs that will be shown on the IdP selector
  //'idpList' => array('Stork', 'aFirma', 'AEAT'),
  
  //[Optional] List of IdPs that won't be shown on the IdP selector
  //'idpExcludedList' => array('SS'),
    
  //[Optional] Force a specific IdP [bypass selector]
  //'force' => 'aFirma',
  
  
  //[Optional] Default:false. Whether the user is authorised to
  //authenticate using a legal person certificate instead of a cotizen
  //certificate (not valid for all auth sources)
  //'allowLegalPerson' => true,
  
  
  // [Optional] STORK parameters. If not set, request values will be
  // retransmitted (or defaulted if not present). Will override
  // the hosted SP metadata values
  //'spCountry'     => 'ES',
  //'spSector'      => 'EDU',
  //'spInstitution' => 'RedIris',
  //'spApplication' => 'SIR2',
  //'spID'          => 'ES-EDU-RedIris-SIR2',
    
  //'citizenCountryCode' => 'ES',
    
  //'eIDSectorShare'      => true,
  //'eIDCrossSectorShare' => true,
  //'eIDCrossBorderShare' => true,


  // Standard remote SP metadata from here

  'AssertionConsumerService' => array (
    0 => array (
      'index' => 0,
      'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      'Location' => 'https://eidas.sp/acs.php',
    ),
  ),
	
  'keys' => array (
    0 => array (
      'encryption' => true,
      'signing' => true,
      'type' => 'X509Certificate',
      'X509Certificate' => 'MIICGzCCAYQCCQDoPIlU...K88NvjF6ogqIzi=',
    ),
  ),
);
