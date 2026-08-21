<?php
/**
 * SAML 2.0 remote SP metadata for SimpleSAMLphp.
 *
 * Includes additional metadata for SAML2 to eIDAS bridging
 */


/**
 * 
 * Incluir este bloque de código AL FINAL del fichero de metadatos, tras todos 
 * los SPs definidos, si quweremos imitar el comportamiento de que el 
 * bridge no tiene estado. Por defecto, el core de SAML2 no permite 
 * retransmitir SLO al IdP remoto si no hay sesión, y si hay sesión no 
 * puede ser stateless. El único apaño es que haya sesión pero que cada SP
 * virtualmente pida forceAuthn al bridge. Que ojo, es distinto a que el 
 * hosted SP de clave del bridge pida forceAuthn a Clave. Se podría 
 * pedir forceAuth al bridge, pero que este a Clave no le pidiera forceAuthn, 
 * habría que etudiar cómo implementarlo
 *
 * * 
 */
 
// TODO: ver si el hosted SP de clave mira el forceAuthn del SP 
//       remoto en ambos casos (SP saml y sp clave) o hay algún override a nivel de 
//       config de la authsource. Lo ideal sería que coja el del SP a menos que haya un override
 
// Cara SAML2 estándar: forzar re-autenticación aunque el SP remoto no mande
// ForceAuthn. El módulo saml lo fusiona con el del request, así que el bridge
// re-consulta a Cl@ve en cada AuthnRequest en vez de devolver atributos cacheados.
foreach ($metadata as $sir2_e => $sir2_c) {
    $metadata[$sir2_e]['ForceAuthn'] = true;
}
unset($sir2_e, $sir2_c);





/*
 * Example SimpleSAMLphp SAML 2.0 eIDAS SP
 */



$metadata['https://eidas.sp/metadata.php'] = array (
  'entityID' => 'https://eidas.sp/metadata.php',
  
  
  // [Optional] List of attributes to be requested to eIDAS. If not 
  // set, if a set is defined at the Hosted SP metadata, that 
  // attribute set will be requested, else, the minimum data set 
  // will be requested
  'attributes' => array('PersonIdentifier', 'FirstName', 'FamilyName','DateOfBirth'),
    
	
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
  //'dialect' => 'eidas',
  
  
  // [Optional] Details relative to the specific implementation of
  // the dialect
  // Possible values: 'stork','clave-1.0','eidas','clave-2.0'

  //'subdialect' => 'eidas',
  
  
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

	
  // Starting from here, minimum standard metadata to be functional
	
  'assertion.encryption' => false,
	
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
      'X509Certificate' => 'MIICGzCCAYQCCQDoPIlUtpzgHDANBgkqhkiG9w0BAQsF...jF6ogqIzi=',
    ),              
  ),
);
