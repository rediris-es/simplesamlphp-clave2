<?php


//require_once('xmlseclibs.php');

// TODO (IdP still stork-clave1). Make it dual mode, both at SP and IdP, just response generatin lacking

//STORK and eIDAS compliant SP


namespace SimpleSAML\Module\clave;

use DOMDocument;
use DOMElement;
use DOMNodeList;
use DOMXPath;
use Exception;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use SimpleXMLElement;


class SPlib {
  
  const VERSION = "2.0.3";
  
  /************ Usable constants and static vars *************/
  
  //Supported signature key modes
  const DSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1';
  const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
  const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  const RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
  const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
  
  //Supported encryption algorithms (for symmetric keys and assymmetric)
  const AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
  const AES192_CBC = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc';
  const AES256_CBC = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
  const AES128_GCM = 'http://www.w3.org/2009/xmlenc11#aes128-gcm';
  const AES192_GCM = 'http://www.w3.org/2009/xmlenc11#aes192-gcm';
  const AES256_GCM = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';
  
  const RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
  
  //Supported digest algorithms.
  const SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
  const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
  const SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
  const SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512';
  
  
  //Supported canonicalization methods.
  const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
  const C14N_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
  const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
  const EXC_C14N_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

  //Consent
  const CNS_OBT = "urn:oasis:names:tc:SAML:2.0:consent:obtained";
  const CNS_UNS = "urn:oasis:names:tc:SAML:2.0:consent:unspecified";
  const CNS_PRI = "urn:oasis:names:tc:SAML:2.0:consent:prior";
  const CNS_IMP = "urn:oasis:names:tc:SAML:2.0:consent:current-implicit";
  const CNS_EXP = "urn:oasis:names:tc:SAML:2.0:consent:current-explicit";
  const CNS_UNA = "urn:oasis:names:tc:SAML:2.0:consent:unavailable";
  const CNS_INA = "urn:oasis:names:tc:SAML:2.0:consent:inapplicable";
    
  //Namespaces.
  const NS_SAML2    = "urn:oasis:names:tc:SAML:2.0:assertion";
  const NS_SAML2P   = "urn:oasis:names:tc:SAML:2.0:protocol";
  const NS_XMLDSIG  = "http://www.w3.org/2000/09/xmldsig#";
  const NS_STORK    = "urn:eu:stork:names:tc:STORK:1.0:assertion";
  const NS_STORKP   = "urn:eu:stork:names:tc:STORK:1.0:protocol";
  const NS_XMLSCH   = "http://www.w3.org/2001/XMLSchema";
  const NS_XSI      = "http://www.w3.org/2001/XMLSchema-instance";
  const NS_EIDAS    = "http://eidas.europa.eu/saml-extensions";
  const NS_EIDASATT = "http://eidas.europa.eu/attributes/naturalperson";  // TODO este no sé muy bien qué pinta. Cuando reciba una req con datos lo sabré, y sabré si hay 2 o 4 y cambia y cómo se hace si hay varios (creo que habrá sólo 2 y serán alternativos, o igual uno de natural y otro de legal y puedan estar juntos). Se usa para el attribute value:transliyterated langInfo... y para la semánmtica de los attrs en el xs:type, pero este último ya queda fuera de scope.
  
  
  //SAML Main status codes
  const ST_SUCCESS   = "urn:oasis:names:tc:SAML:2.0:status:Success";
  const ST_REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester";
  const ST_RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder";

  //SAML Secondary status codes
  const ST_ERR_AUTH   = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
  const ST_ERR_ATTR   = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue";
  const ST_ERR_NIDPOL = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy";
  const ST_ERR_DENIED = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";

  //SAML Attribute status codes
  const ATST_AVAIL    =  "Available";
  const ATST_NOTAVAIL =  "NotAvailable";
  const ATST_WITHLD   =  "Withheld";

  //eIDAS Levels of Assurance
  const LOA_LOW = "http://eidas.europa.eu/LoA/low";
  const LOA_SUBST ="http://eidas.europa.eu/LoA/substantial";
  const LOA_HIGH = "http://eidas.europa.eu/LoA/high";

  //eIDAS SP types
  const EIDAS_SPTYPE_PUBLIC  = "public";
  const EIDAS_SPTYPE_PRIVATE = "private";
  
  
  const NAMEID_FORMAT_PERSISTENT  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
  const NAMEID_FORMAT_TRANSIENT   = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
  const NAMEID_FORMAT_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
      
  
  // List of accepted attributes (friendly names)
  // Edit as you need it.
  private static array $ATTRIBUTES = array(
          // STORK 1 Personal Attributes
          "givenName"                 => "http://www.stork.gov.eu/1.0/givenName", 
          "surname"                   => "http://www.stork.gov.eu/1.0/surname",
          "eIdentifier"               => "http://www.stork.gov.eu/1.0/eIdentifier",
          "countryCodeOfBirth"        => "http://www.stork.gov.eu/1.0/countryCodeOfBirth",
          "canonicalResidenceAddress" => "http://www.stork.gov.eu/1.0/canonicalResidenceAddress",
          "dateOfBirth"               => "http://www.stork.gov.eu/1.0/dateOfBirth",
          "textResidenceAddress"      => "http://www.stork.gov.eu/1.0/textResidenceAddress",
          "maritalStatus"             => "http://www.stork.gov.eu/1.0/maritalStatus",
          "pseudonym"                 => "http://www.stork.gov.eu/1.0/pseudonym",
          "citizenQAAlevel"           => "http://www.stork.gov.eu/1.0/citizenQAAlevel",
          "adoptedFamilyName"         => "http://www.stork.gov.eu/1.0/adoptedFamilyName",
          "title"                     => "http://www.stork.gov.eu/1.0/title",
          "residencePermit"           => "http://www.stork.gov.eu/1.0/residencePermit",
          "nationalityCode"           => "http://www.stork.gov.eu/1.0/nationalityCode",
          "gender"                    => "http://www.stork.gov.eu/1.0/gender",
          "fiscalNumber"              => "http://www.stork.gov.eu/1.0/fiscalNumber",
          "inheritedFamilyName"       => "http://www.stork.gov.eu/1.0/inheritedFamilyName",
          "age"                       => "http://www.stork.gov.eu/1.0/age",
          "eMail"                     => "http://www.stork.gov.eu/1.0/eMail",
          "signedDoc"                 => "http://www.stork.gov.eu/1.0/signedDoc",
          "isAgeOver"                 => "http://www.stork.gov.eu/1.0/isAgeOver",
          // New Personal Attributes
          "placeOfBirth"			  => "http://www.stork.gov.eu/1.0/placeOfBirth",
          // Academia Attributes
          "diplomaSupplement"         => "http://www.stork.gov.eu/1.0/diplomaSupplement",
          "currentStudiesSupplement"  => "http://www.stork.gov.eu/1.0/currentStudiesSupplement",
          "isStudent"                 => "http://www.stork.gov.eu/1.0/isStudent",
          "isAcademicStaff"		      => "http://www.stork.gov.eu/1.0/isAcademicStaff",
          "isTeacherOf"			      => "http://www.stork.gov.eu/1.0/isTeacherOf",
          "isCourseCoordinator"	      => "http://www.stork.gov.eu/1.0/isCourseCoordinator",
          "isAdminStaff"			  => "http://www.stork.gov.eu/1.0/isAdminStaff",
          "habilitation"			  => "http://www.stork.gov.eu/1.0/habilitation",
          "languageQualification"     => "http://www.stork.gov.eu/1.0/languageQualification",
          "academicRecommendation"    => "http://www.stork.gov.eu/1.0/academicRecommendation",
          "hasDegree"		          => "http://www.stork.gov.eu/1.0/hasDegree",
          
          //Clave Attributes
          "afirmaResponse"	          => "http://www.stork.gov.eu/1.0/afirmaResponse",
          "isdnie"			          => "http://www.stork.gov.eu/1.0/isdnie",
          "registerType"			  => "http://www.stork.gov.eu/1.0/registerType",
          "citizenQAALevel"           => "http://www.stork.gov.eu/1.0/citizenQAALevel",
          
          
          //Defined for the websso interface
          "usedIdP"                   => "http://www.stork.gov.eu/1.0/usedIdP",
  );


  //eIDAS attributes (FriendlyName -> Name)
  const EIDAS_ATTR_PREFIX = "http://eidas.europa.eu/attributes/";
  //PHP5.4 does not accept concatenations in declaration
  //      "PersonIdentifier"     => self::EIDAS_ATTR_PREFIX."naturalperson/PersonIdentifier",
  private static array $eIdasAttributes = array(
      "PersonIdentifier"     => "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier",
      "FirstName"            => "http://eidas.europa.eu/attributes/naturalperson/CurrentGivenName",
      "FamilyName"           => "http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName",
      "DateOfBirth"          => "http://eidas.europa.eu/attributes/naturalperson/DateOfBirth",
      "AdditionalAttribute"  => "http://eidas.europa.eu/attributes/naturalperson/AdditionalAttribute",
      "BirthName"            => "http://eidas.europa.eu/attributes/naturalperson/BirthName",
      "CurrentAddress"       => "http://eidas.europa.eu/attributes/naturalperson/CurrentAddress",
      "Gender"               => "http://eidas.europa.eu/attributes/naturalperson/Gender",
      "PlaceOfBirth"         => "http://eidas.europa.eu/attributes/naturalperson/PlaceOfBirth",

      "D-2012-17-EUIdentifier"    => "http://eidas.europa.eu/attributes/legalperson/D-2012-17-EUIdentifier",
      "EORI"                      => "http://eidas.europa.eu/attributes/legalperson/EORI",
      "LEI"                       => "http://eidas.europa.eu/attributes/legalperson/LEI",
      "LegalAdditionalAttribute"  => "http://eidas.europa.eu/attributes/legalperson/LegalAdditionalAttribute",
      "LegalAddress"              => "http://eidas.europa.eu/attributes/legalperson/LegalAddress",
      "LegalName"                 => "http://eidas.europa.eu/attributes/legalperson/LegalName",
      "LegalPersonIdentifier"     => "http://eidas.europa.eu/attributes/legalperson/LegalPersonIdentifier",
      "SEED"                      => "http://eidas.europa.eu/attributes/legalperson/SEED",
      "SIC"                       => "http://eidas.europa.eu/attributes/legalperson/SIC",
      "TaxReference"              => "http://eidas.europa.eu/attributes/legalperson/TaxReference",
      "VATRegistration"           => "http://eidas.europa.eu/attributes/legalperson/VATRegistration",

      "RepresentativeD-2012-17-EUIdentifier"  => "http://eidas.europa.eu/attributes/legalperson/representative/D-2012-17-EUIdentifier",
      "RepresentativeEORI"                    => "http://eidas.europa.eu/attributes/legalperson/representative/EORI",
      "RepresentativeLEI"                     => "http://eidas.europa.eu/attributes/legalperson/representative/LEI",
      "RepresentativeLegalAddress"            => "http://eidas.europa.eu/attributes/legalperson/representative/LegalAddress",
      "RepresentativeLegalName"               => "http://eidas.europa.eu/attributes/legalperson/representative/LegalName",
      "RepresentativeLegalPersonIdentifier"   => "http://eidas.europa.eu/attributes/legalperson/representative/LegalPersonIdentifier",
      "RepresentativeSEED"                    => "http://eidas.europa.eu/attributes/legalperson/representative/SEED",
      "RepresentativeSIC"                     => "http://eidas.europa.eu/attributes/legalperson/representative/SIC",
      "RepresentativeTaxReference"            => "http://eidas.europa.eu/attributes/legalperson/representative/TaxReference",
      "RepresentativeVATRegistration"         => "http://eidas.europa.eu/attributes/legalperson/representative/VATRegistration",

      "RepresentativeBirthName"         => "http://eidas.europa.eu/attributes/naturalperson/representative/BirthName",
      "RepresentativeCurrentAddress"    => "http://eidas.europa.eu/attributes/naturalperson/representative/CurrentAddress",
      "RepresentativeFamilyName"        => "http://eidas.europa.eu/attributes/naturalperson/representative/CurrentFamilyName",
      "RepresentativeFirstName"         => "http://eidas.europa.eu/attributes/naturalperson/representative/CurrentGivenName",
      "RepresentativeDateOfBirth"       => "http://eidas.europa.eu/attributes/naturalperson/representative/DateOfBirth",
      "RepresentativeGender"            => "http://eidas.europa.eu/attributes/naturalperson/representative/Gender",
      "RepresentativePersonIdentifier"  => "http://eidas.europa.eu/attributes/naturalperson/representative/PersonIdentifier",
      "RepresentativePlaceOfBirth"      => "http://eidas.europa.eu/attributes/naturalperson/representative/PlaceOfBirth",
      
      
      //Clave 2 Attributes
      "AFirmaIdP"                 => "http://es.minhafp.clave/AFirmaIdP",
      "GISSIdP"                   => "http://es.minhafp.clave/GISSIdP",
      "AEATIdP"                   => "http://es.minhafp.clave/AEATIdP",
      "EIDASIdP"                  => "http://es.minhafp.clave/EIDASIdP",
      "PartialAfirma"             => "http://es.minhafp.clave/PartialAfirma",
      "RelayState"                => "http://es.minhafp.clave/RelayState",

      "RegisterType"			  => "http://es.minhafp.clave/RegisterType",

      //Defined for the websso interface
      "usedIdP"                   => "http://es.minhafp.clave/usedIdP",
  );


  //Get the friendly name for a eIDAS attribute name
  public static function getEidasFriendlyName ($attributeName): string
  {
      
      if($attributeName === NULL || $attributeName === "") {
          # TODO: turn again to self::fail when fal is made static (as it should be)
          self::critical("[Code ".self::ERR_GENERIC."] ".__FUNCTION__."::"."Empty or null attribute name.");
          throw new Exception(__FUNCTION__."::"."Empty or null attribute name",self::ERR_GENERIC);
      }
      
      foreach(self::$eIdasAttributes as $friendlyName => $name){
          if($name === $attributeName)
              return $friendlyName;
      }
      
      return "";
  }
  
  
  /************ Internal config vars *************/


  //The attribute names being used for signed node referencing 
  //[Notice that XPath expressions are case-sensitive]
  private static array $referenceIds = array('ID','Id','id');
  
  //The prefix to form the full name of the attributes and the name format declaration.
  private static string $AttrNamePrefix = "http://www.stork.gov.eu/1.0/";
  private static string $AttrNF         = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
  

  //Protocol to be used (0:Stork, 1:eIDAS)
  private $mode;

   
  /*********** Request attributes **************/
  
  //SamlResquestTokenID and generation timestamp
  private $ID;
  private $TSTAMP;
  
  //Signature parameters
  private $signCert;
  private $signKey;
  private $signKeyType;
  
  private $c14nMethod;
  private $digestMethod;
  
  //SP
  private $ServiceProviderName;    // SP readable name
  private $Issuer;                 // SP Issuer identifier (usually a URL)
  private $ReturnAddr;             // Address where SamlResponse must be returned
  
  private $SPEPS;                  // S-PEPS url, the destination of the request.
  private $QAALevel;               // Minimum authentication quality needed.

  private $forceAuth;
  
  private $sectorShare;            // Can eID be shared on the SP sector?
  private $crossSectorShare;       // Can eID be shared outside the SP sector?
  private $crossBorderShare;       // Can eID be shared outside the SP country?  
  
  //For eId derivation
  private $ServiceProviderCountry;     // S-PEPS country code
  private $ServiceProviderSector;      // SP group of institutions ID
  private $ServiceProviderInstitution; // SP institution ID
  private $ServiceProviderApplication; // SP exact app ID
  
  //V-IDP
  private $ServiceProviderID;      // SPID unique identifier string
  private $CitizenCountry;         // Citizen country code
  
  // The list of attributes to be requested.
  private $AttrList;
  
  // The generated SamlAuthReq token.
  private $samlAuthReq;
  

  //Parameters for Assertion encryption-decryption
  private $encryptCert;
  private $doCipher;
  private $keyAlgorithm;
  
  private $decryptPrivateKey;
  private $doDecipher;
  private $onlyEncrypted;

  private $idplist;
  
  /*********** Response attributes **************/
  
  
  //All the certificates added to this array will be used to check the
  //signature. If any of them succeeds, the response will be
  //validated. Trust on this certs must have been previously inferred
  //(no certification chain validation is performed)
  private $trustedCerts;
  
  // The received SamlResponse token (xml string)
  private $SAMLResponseToken;
  
  // Response attributes
  private $signingCert;        // The signing certificat embedded on the response.
  private $responseAssertions; // The assertions that the response contained with all relevant info.

  private $inResponseTo;        // The id of the request associated to this response
  private $responseIssuer;      // The issuer ID of the S-PEPS (who produced the response)
  private $responseNameId;
  private $responseNameIdFrm;
  private $AuthnInstant;
  private $AuthnContextClassRef;
  private $responseDestination; // The URL where this resp is addressed.
  
  private $responseSuccess;    // Whether if the request was successful or not.
  private $responseStatus;     // Status info for the response: array with these fields:
                               //      MainStatusCode
                               //      SecondaryStatusCode
                               //      StatusMessage

  private $consent;            //Whether consent has been given
  
  
  // Request attributes to be compared
  private $requestId;             // The id of the related request
  private $assertionConsumerUrl;  // The URL that expected the response
  private $expectedIssuers;        // The List of allowed identifiers of the S-PEPS
  private $mandatoryAttrList;     // List of requested attribute friendly 
                                  //  names that were mandatory
  

  
  /*********** Request attributes **************/

  // All the SPs authorised to send requests. key is the issuer and
  //value is the array of certificates that can use to sign the request
  private $trustedIssuers;

  // The received SamlAuthnReq token (xml string)
  private $SAMLAuthnReqToken;


  // The received LogoutRequest token (xml string)
  private $SLOReqToken;



  /************ eIDAS ***************/
  
  //Type of SP (private sector, public sector)
  private $spType;
  private $nameIdFormat;
  
  
  
  /*************************  Error treatment, log and debug  *************************/
  const LOG_TRACE    = 0;
  const LOG_DEBUG    = 1;
  const LOG_INFO     = 2;
  const LOG_WARN     = 3;
  const LOG_ERROR    = 4;
  const LOG_CRITICAL = 5;

  private static $logLevels = array(
        self::LOG_TRACE    => 'TRACE',
        self::LOG_DEBUG    => 'DEBUG',
        self::LOG_INFO     => 'INFO',
        self::LOG_WARN     => 'WARN',
        self::LOG_ERROR    => 'ERROR',
        self::LOG_CRITICAL => 'CRITICAL'
                                    );
  
  
  private static $logLevel    = self::LOG_TRACE;
  private static $logFile     = '/tmp/storkLog';
  private static $logToFile   = false;
  private static $logToStdout = false;
  
  
  private static function log($content,$level){
    
    if($level < self::$logLevel)
      return;
    
    $prefix = "[".date('c',time())."][".self::$logLevels[$level]."]: ";

    if(is_object($content) || is_array($content))
      $message=print_r($content,TRUE);
    else
      $message=$content;
    
    if(self::$logToStdout)
      echo $prefix.$message."\n";
    
    if(self::$logToFile)
      file_put_contents(self::$logFile, $prefix.$message."\n",FILE_APPEND); 
  }
  
  private static function trace($message){
    self::log($message,self::LOG_TRACE);
  }
  private static function debug($message){
    self::log($message,self::LOG_DEBUG);
  }
  private static function info($message){
    self::log($message,self::LOG_INFO);
  }
  private static function warn($message){
    self::log($message,self::LOG_WARN);
  }
  private static function error($message){
    self::log($message,self::LOG_ERROR);
  }
  private static function critical($message){
    self::log($message,self::LOG_CRITICAL);
  }
  
  
  //Default language for error messages.
  private $defaultLang = 'EN';
  private $msgLang;
  
  //Set the language in which the erorr codes will be shown
  public function setErrorMessageLanguage($langcode){
    $this->msgLang = strtoupper($langcode);
  }

  //Add message translation.
  public function addErrorMessageTranslation($langcode,$messages){
    $this->ERR_MESSAGES[strtoupper($langcode)] = $messages;
  }

  private function fail($func,$code,$additionalInfo=""){
    $extra="";
    if($additionalInfo != "")
      $extra=":\n".$additionalInfo;
    
    $lang = $this->defaultLang;
    if($this->msgLang != NULL && isset($this->ERR_MESSAGES[$this->msgLang]))
      $lang = $this->msgLang;

    self::critical("[Code $code] ".$func."::".$this->ERR_MESSAGES[$lang]["$code"].$extra);
    throw new Exception($func."::".$this->ERR_MESSAGES[$lang]["$code"].$extra,$code);   
  }

  const ERR_RSA_KEY_READ            =  1;
  const ERR_X509_CERT_READ          =  2;
  const ERR_RESP_NO_MAND_ATTR       =  3;
  const ERR_BAD_XML_SYNTAX          =  4;
  const ERR_NONEXIST_STORK_ATTR     =  5;
  const ERR_NEEDED_SPEPS            =  6;
  const ERR_NEEDED_RADDR            =  7;   
  const ERR_NEEDED_SPROVN           =  8; 
  const ERR_BAD_ASSERT_SUBJ         =  9;
  const ERR_DUP_ASSERT_ID           = 10;
  const ERR_ASSERT_NO_ATTRS         = 11;
  const ERR_NO_COUNTRYCODE          = 12;
  const ERR_EMPTY_CERT              = 13;
  const ERR_EMPTY_KEY               = 14;
  const ERR_SAMLRESP_BADXML         = 15;
  const ERR_SAMLRESP_EMPTY          = 16;
  const ERR_SAMLRESP_STILLNOTVALID  = 17;
  const ERR_SAMLRESP_EXPIRED        = 18;
  const ERR_SAMLRESP_NOSTATUS       = 19;
  const ERR_BAD_ASSERTION           = 20;
  const ERR_NO_ASSERT_ID            = 21;
  const ERR_NO_ASSERT_ISSUER        = 22;
  const ERR_NO_ASSERT_SUBJECT       = 23;
  const ERR_SIG_VERIF_FAIL          = 24;
  const ERR_RESP_SUCC_NO_ASSERTIONS = 25;
  const ERR_NO_SIGNATURE            = 26;
  const ERR_RESP_NO_DESTINATION     = 27;
  const ERR_RESP_NO_REQ_ID          = 28;
  const ERR_UNEXP_DEST              = 29;
  const ERR_MISSING_SIG_INFO        = 30;
  const ERR_REF_VALIDATION          = 31;
  const ERR_BAD_PUBKEY_CERT         = 32;
  const ERR_NO_INT_EXT_CERT         = 33;
  const ERR_BAD_PARAMETER           = 34;
  const ERR_UNEXP_ROOT_NODE         = 35;
  const ERR_UNEXP_REQ_ID            = 36;
  const ERR_RESP_NO_ISSUER          = 37;
  const ERR_UNEXP_ISSUER            = 38;
  const ERR_NONAUTH_ISSUER          = 39;
  const ERR_SLOREQ_EMPTY            = 40;
  const ERR_GENERIC                 = 99;


  private $ERR_MESSAGES = array(
    'EN' => array(
    0  => "OK.",
				1  => "Key param not a valid PEM RSA private key.",
				2  => "Cert param not a valid PEM X509 certificate.",
				3  => "Missing mandatory attributes on response.",
				4  => "Bad XML syntax on entry data.",
				5  => "This STORK Attribute doesn't exist.",
				6  => "Peps URL parameter must be provided.",
				7  => "Return Address parameter must be provided.",
				8  => "Service Provider readable name parameter must be provided.",
				9  => "Error parsing assertion subject.",
				10 => "Duplicate Assertion ID.",
				11 => "Assertion without Attribute Statement on response",
				12 => "Destination 2 letter country code must be provided.",
				13 => "No cert provided",
				14 => "No key provided",
				15 => "SAML Response XML badly formed",
				16 => "SAML Response empty",
				17 => "SAML Response still not valid",
				18 => "SAML Response validity has expired",
				19 => "SAML Response has no status",
				20 => "Error parsing assertion.",
				21 => "Assertion without ID on response.",
				22 => "Assertion without Issuer on response.",
				23 => "Assertion without Subject on response.",
				24 => "Signature verification failed",
				25 => "No plain assertions on a successful response.",
				26 => "No signature node found",
				27 => "No Destination attribute found on response.",
				28 => "No InResponseTo attribute found on response.",
    29 => "The Destination of the response  doesn't match the expected one.",
    30 => "No signature method information found",
				31 => "Error validating references.",
				32 => "Error parsing public key or certificate",
				33 => "No keyinfo found, no external pubkey/cert provided.",
				34 => "Bad parameter or parameter type.",
    35 => "Unexpected document root node.",
    36 => "The ID of the request at which this response addresses doesnt' match the expected one.",
    37 => "No Issuer node found on response.",
    38 => "The Issuer of the response  doesn't match the expected one.",
    39 => "The Issuer of the request is not authorised.",
    40 => "The SLO request is empty.",
    99 => "Error."
    )
			);
  
  
  
  
  public function __construct (){
    
    self::trace(__CLASS__.".".__FUNCTION__."()");
    
    // Defaults
    $this->mode = 0; //Default mode is Stork, the legacy one
    
    $this->digestMethod = self::SHA512;
    $this->c14nMethod   = self::EXC_C14N;
    
    $this->trustedCerts = array();

    $this->forceAuth = false;
    
    $this ->encryptCert = NULL;
    $this ->doCipher = false;
    $this ->keyAlgorithm = self::AES256_CBC;
    
    $this->decryptPrivateKey  = NULL;
    $this->doDecipher         = false;
    $this->onlyEncrypted      = false;
    
    $this->spType = NULL;
    $this->nameIdFormat = self::NAMEID_FORMAT_PERSISTENT;

    $this->responseSuccess = false;

    $this->idplist = NULL;
    
    //request ID is randomly generated
    $this->ID = self::generateID();
  }
  
  
  
  // Returns the list of supported STORK attribute friendly names
  public function listSupportedAttributes(){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    return array_keys(self::$ATTRIBUTES);
  }


  // Returns the list of supported eIDAS attribute friendly names
  public function listEidasSupportedAttributes(){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    return array_keys(self::$eIdasAttributes);
  }
  
  
  
  //Add an attribute to be requested.
  // $friendlyName: the name of the attribute, from the supported list.
  // $required:     true if mandatory, false if optional.
  // $values:       [optional] some attributes accept sending attribute values as parameters. array of value strings.
  // $escape:       [optional] false if value must be set unescaped (to allow embedded xml, like SamlEngine does)
  //                           Notice that this could provoke validation issues.
  public function addRequestAttribute ($friendlyName, $required=false, $values=NULL, $escape=true){
    
    self::debug("Adding attribute ".$friendlyName." required(".self::bts($required).")");

    $prefix = '';
    if($this->mode === 0)
        $prefix = "stork";
    if($this->mode === 1)
        $prefix = "eidas";
    
    // We check if it is a supported attribute (always allow if mandatory)
    if($this->mode === 0)
        if(!$required){
            self::$ATTRIBUTES[$friendlyName] or $this->fail(__FUNCTION__, self::ERR_NONEXIST_STORK_ATTR, $friendlyName);
        }

    // On eIDAS, allow always?
    //if($this->mode === 1)
    //    self::$eIdasAttributes[$friendlyName] or $this->fail(__FUNCTION__, self::ERR_NONEXIST_STORK_ATTR, $friendlyName);

    
    
    if($values)
      if(!is_array($values))
        if(is_object($values))
          $this->fail(__FUNCTION__, self::ERR_BAD_PARAMETER, 'values: '.$values);
        else
          $values=array($values);
    

    
    
    if($values == NULL || count($values)<=0){
      $values = array();
      $tagClose = "/>";
      $closeTag = "";
    }
    else{
      $tagClose = ">";
      $closeTag = "</".$prefix.":RequestedAttribute>";
    }
    $valueAddition = "";
    foreach($values as $value){
      
      $transformedValue = $value;
      if($escape)
        $transformedValue = htmlspecialchars($value);



      $valueType = 'xs:string';

      //TODO: Workaround for terrible clave-2.0 design. still not definitive
      //Seems it is not necessary. Will leave it commented just in case.
      //if($friendlyName === 'RelayState' )
      //    $valueType = 'eidas-natural:PersonIdentifierType';
      
          
      
      $valueAddition .= '<'.$prefix.':AttributeValue '
        .'xmlns:xs="'.self::NS_XMLSCH.'" '
        .'xmlns:xsi="'.self::NS_XSI.'" '
        .'xsi:type="'.$valueType.'">'
        .$transformedValue.'</'.$prefix.':AttributeValue>';
    }


    $attrLine = '';
    if($this->mode === 0){
        
        $attrName = $friendlyName;
        if (array_key_exists($friendlyName,self::$ATTRIBUTES))
            $attrName = self::$ATTRIBUTES[$friendlyName];
        
        $attrLine = '<stork:RequestedAttribute'
            .' Name="'.$attrName.'"'
            .' NameFormat="'.self::$AttrNF.'"'
            .' isRequired="'.self::bts($required).'"'
            .$tagClose
            .$valueAddition
            .$closeTag;
    }
    
    if($this->mode === 1){    
        //If we can't translate the friendlyname to a name, use it as is
        $name = $friendlyName;
        if (array_key_exists($friendlyName,self::$eIdasAttributes))
            $name = self::$eIdasAttributes[$friendlyName];
    
        $attrLine = '<'.$prefix.':RequestedAttribute'
            .' FriendlyName="'.$friendlyName.'"'
            .' Name="'.$name.'"'
            .' NameFormat="'.self::$AttrNF.'"'
            .' isRequired="'.self::bts($required).'"'
            .$tagClose
            .$valueAddition
            .$closeTag;
    }
    
    
    //We add the attribute to the requested attributes array
    // [Notice that an attribute can be requested multiple times]
    if($attrLine != "")
      $this->AttrList []= $attrLine;    
  }
  
  
  
  // Set the key that will be used to sign requests.
  // $cert:    x509 certificate associated with the key, to be included on the keyinfo
  // $key:     private key, of a supported public key cryptosystem.
  // $keytype: Kind of key [See constants]
  public function setSignatureKeyParams ($cert, $key, 
                                         $keytype=self::RSA_SHA512){
      
      self::debug(__CLASS__.".".__FUNCTION__."()");
      
      $this->signKey     = $this->checkKey($key);
      $this->signCert    = $this->checkCert($cert);    
      $this->signKeyType = $keytype;    
  }
  
  
  
  // Set the digest and canonicalization methods to be used for
  // request signature. See constants for allowed values.
  public function setSignatureParams($digestMethod,$c14nMethod){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    $this->digestMethod = $digestMethod;
    $this->c14nMethod   = $c14nMethod;
  }
  
  
  
  // $name        -> String. Readable name of the SP.
  // $issuer      -> String  SP identifier towards S-PEPS (usually a URL)
  // $returnAddr  -> String. URL where the SamlResponse will be delivered.
  // $spid        -> String. (Optional) IDentifier for this SP, assigned by some entity (MS? S-PEPS?)
  // $countryCode -> String. (Optional) Country code for the SP country 
  public function setServiceProviderParams ($name, $issuer, $returnAddr) {
    
    self::debug(__CLASS__.".".__FUNCTION__."()");

    $this->ServiceProviderName    = $name;
    $this->Issuer                 = $issuer;
    $this->ReturnAddr             = $returnAddr;
  }
  

  //Enables the force authentication flag on the request (default false)
  public function forceAuthn(){
      $this->forceAuth = true;
  }
  
  
  //Params with more specific and leveled SP ID information. Mandatory if the request
  //is addressed to a country which performs eID derivation.
  // $countryCode -> The country code of the SP
  // $sector      -> The sector (like a group of institutions) ID (must be settled by someone)
  // $institution -> The institution ID of the SP (must be settled by someone)
  // $application -> The SP most specific ID, per application (must be settled by someone).
  public function setSPLocationParams ($countryCode, $sector, $institution, $application) {
    
    self::debug(__CLASS__.".".__FUNCTION__."()");

    $this->ServiceProviderCountry     = $countryCode;
    $this->ServiceProviderSector      = $sector;
    $this->ServiceProviderInstitution = $institution;
    $this->ServiceProviderApplication = $application;
  }
  
  
  
  //Params needed when the request is addressed to a country that uses V-IDP
  // $spId               -> Unique SP identifier, usually spcountry-sp-sector-spinst-spapp
  // $citizenCountryCode -> The country code of the citizen
  public function setSPVidpParams ($spId, $citizenCountryCode){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");

    $this->ServiceProviderID      = $spId;
    $this->CitizenCountry         = $citizenCountryCode;
  }
  
  
  
  // $EntryURL:          String. S-PEPS URL.
  // $QAALevel:          Int.  Min Quality Authentication Assurance Level 
  //                           requested (1-3)? default 1 (soft auth, pwd),
  //                           2: cert, 3:smartcard
  // $sectorShare:       Can eID be shared on the SP sector?
  // $crossSectorShare:  Can eID be shared outside the SP sector?
  // $crossBorderShare:  Can eID be shared outside the SP country?
  public function setSTORKParams ($EntryURL, 
                                  $QAALevel=1,
                                  $sectorShare=true,
                                  $crossSectorShare=true,
                                  $crossBorderShare=true) {
    
    self::debug(__CLASS__.".".__FUNCTION__."()");

    $this->SPEPS            = $EntryURL;
    $this->QAALevel         = $QAALevel;
    $this->sectorShare      = $sectorShare;     
    $this->crossSectorShare = $crossSectorShare;
    $this->crossBorderShare = $crossBorderShare;
  }

  //If the request needs to have a scoping of the allowed idps when proxying this request
  public function setIdpList ($IdpList){
    $this->idplist  = $IdpList;
  }


  //Establishes an equivalence between Stork QAA levels and eIDAS LoA
  //levels
  public static function qaaToLoA($QAA) {
      
      if($QAA === NULL || $QAA === "")
          return "";
      
      if( is_string($QAA) === true )
          $QAA = (int)$QAA;
            
      if($QAA <= 2)
          return self::LOA_LOW;
      if($QAA == 3)
          return self::LOA_SUBST;
      if($QAA >= 4)
          return self::LOA_HIGH;
      
      return "";
  }



  public static function loaToQaa($LoA) {
      
      if($LoA === NULL || $LoA === "")
          return "";
      
      if( is_string($LoA) === false )
          return "";
      
      if($LoA == self::LOA_LOW)
          return 2;
      if($LoA == self::LOA_SUBST)
          return 3;
      if($LoA >= self::LOA_HIGH)
          return 4;
      
      return 1;
  }
    
  
  
  // $signed:  Wether if the generated request has to be digitally signed or not.
  //Return: String The STORK SAML Auth request token.
  public function generateStorkAuthRequest ($signed=true){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    //ISO Timestamp
    $this->TSTAMP = self::generateTimestamp();

    self::info("Generating request at: ".$this->TSTAMP);


    if($this->SPEPS == NULL || $this->SPEPS == "")
      $this->fail(__FUNCTION__, self::ERR_NEEDED_SPEPS);
    
    if($this->mode === 0)
        if($this->ReturnAddr == NULL || $this->ReturnAddr == "")
            $this->fail(__FUNCTION__, self::ERR_NEEDED_RADDR);   
    
    if($this->ServiceProviderName == NULL || $this->ServiceProviderName == "")
      $this->fail(__FUNCTION__, self::ERR_NEEDED_SPROVN);
 
    if($this->signCert == NULL || $this->signCert == "" 
       || $this->signKey == NULL || $this->signKey == ""
       || $this->signKeyType == NULL || $this->signKeyType == "")
      $this->fail(__FUNCTION__, self::ERR_EMPTY_KEY);

    
    $specificNamespaces = 'xmlns:stork="'.self::NS_STORK.'" '.'xmlns:storkp="'.self::NS_STORKP.'" ';
    if($this->mode === 1)
        $specificNamespaces = 'xmlns:eidas="'.self::NS_EIDAS.'" '.'xmlns:eidas-natural="http://eidas.europa.eu/attributes/naturalperson" ';
    
    $assertionConsumerServiceURL = 'AssertionConsumerServiceURL="'.htmlspecialchars($this->ReturnAddr).'" ';
//    if($this->mode === 1)  //On eIDAS, this SHOULD NOT be sent. // TODO: but on Clave-2.0, it must. eIDAS supports sending it just as the address stated in the metadata. We'll do so.
//        $assertionConsumerServiceURL = "";
    
    $protocolBinding = 'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" ';
    if($this->mode === 1)  //On eIDAS, this SHOULD NOT be sent.
        $protocolBinding = "";
    
    
    $nsPrefix1="stork";
    $nsPrefix2="storkp";
    if($this->mode === 1){
        $nsPrefix1 = "eidas";
        $nsPrefix2 = "eidas";
    }
    
    self::debug("Setting request header.");
    //Header of the SAML Auth Request 
    $RootTagOpen = '<?xml version="1.0" encoding="UTF-8"?>'
        .'<saml2p:AuthnRequest '
        .'xmlns:saml2p="'.self::NS_SAML2P.'" '
        .'xmlns:ds="'.self::NS_XMLDSIG.'" '
        .'xmlns:saml2="'.self::NS_SAML2.'" '
        .$specificNamespaces
        .$assertionConsumerServiceURL
        .'Consent="'.self::CNS_UNS.'" '
        .'Destination="'.htmlspecialchars($this->SPEPS).'" '
        .'ForceAuthn="'.self::bts($this->forceAuth).'" '
        .'ID="'.$this->ID.'" '
        .'IsPassive="false" '
        .'IssueInstant="'.$this->TSTAMP.'" '
        .$protocolBinding
        .'ProviderName="'.htmlspecialchars($this->ServiceProviderName).'" '
        .'Version="2.0">';
    
    self::debug("Setting request issuer.");
    //Issuer
    $Issuer='<saml2:Issuer '
      .'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">'
      .htmlspecialchars($this->Issuer)
      .'</saml2:Issuer>';
    
    
    //Stork profile extensions: requested attributes
    self::debug("Setting request attributes.");
    $RequestedAttributes = '';
    
    if(count($this->AttrList)>0){
      $RequestedAttributes = '<'.$nsPrefix2.':RequestedAttributes>';
      foreach ($this->AttrList as $attr){
        $RequestedAttributes .= $attr;
      }
      $RequestedAttributes .= '</'.$nsPrefix2.':RequestedAttributes>';
    }
    
    
    if($this->mode === 0){  //Stork only

        //Stork profile extensions: authentication additional attributes (optional)
        $StorkExtAuthAttrs = "";
        if($this->ServiceProviderID != NULL && $this->ServiceProviderID != ""
        && $this->CitizenCountry != NULL && $this->CitizenCountry != ""
        ){      
            self::debug("Setting profile extensions: authentication additional attributes (optional).");
      
            $StorkExtAuthAttrs = '<storkp:AuthenticationAttributes>'
                .'<storkp:VIDPAuthenticationAttributes>';
      
            if($this->CitizenCountry != NULL && $this->CitizenCountry != ""){
                $StorkExtAuthAttrs .= '<storkp:CitizenCountryCode>'
                    .htmlspecialchars($this->CitizenCountry)
                    .'</storkp:CitizenCountryCode>';
            }
      
            $StorkExtAuthAttrs .= '<storkp:SPInformation>'
                .'<storkp:SPID>'
                .htmlspecialchars($this->ServiceProviderID)
                .'</storkp:SPID>'
                .'</storkp:SPInformation>'
                .'</storkp:VIDPAuthenticationAttributes>'
                .'</storkp:AuthenticationAttributes>';
        }

    
        self::debug("Setting request QAA.");
        //Stork profile extensions: QAA
        $QAA = '<stork:QualityAuthenticationAssuranceLevel>'
            .htmlspecialchars($this->QAALevel)
            .'</stork:QualityAuthenticationAssuranceLevel>';
    
    
        //Stork profile extensions: SP info (optional)
        if($this->ServiceProviderCountry != NULL && $this->ServiceProviderCountry != ""
        && $this->ServiceProviderSector != NULL && $this->ServiceProviderSector != ""
        && $this->ServiceProviderInstitution != NULL && $this->ServiceProviderInstitution != ""
        && $this->ServiceProviderApplication != NULL && $this->ServiceProviderApplication != ""
        ){
            self::debug("Setting request SP info (optional).");

            $SPinfo = '<stork:spSector>'.htmlspecialchars($this->ServiceProviderSector).'</stork:spSector>'
                .'<stork:spInstitution>'.htmlspecialchars($this->ServiceProviderInstitution).'</stork:spInstitution>'
                .'<stork:spApplication>'.htmlspecialchars($this->ServiceProviderApplication).'</stork:spApplication>'
                .'<stork:spCountry>'.htmlspecialchars($this->ServiceProviderCountry).'</stork:spCountry>';
        }
    
        self::debug("Setting request eID sharing permissions.");
        //Stork profile extensions: eId sharing permissions.
        $eIdShareInfo = '<storkp:eIDSectorShare>'.htmlspecialchars(self::bts($this->sectorShare)).'</storkp:eIDSectorShare>'
            .'<storkp:eIDCrossSectorShare>'.htmlspecialchars(self::bts($this->crossSectorShare)).'</storkp:eIDCrossSectorShare>'
            .'<storkp:eIDCrossBorderShare>'.htmlspecialchars(self::bts($this->crossBorderShare)).'</storkp:eIDCrossBorderShare>';
    }
    

    $SPtype = '';
    if($this->mode === 1){  //eIDAS only
        //Sending is optional, but in that case, it must be set at the eIDAS node metadata
        if ($this->spType !== NULL && $this->spType !== ""){
            $SPtype = '<eidas:SPType>'.$this->spType.'</eidas:SPType>';
        }
        $QAA="";
        $SPinfo="";
        $eIdShareInfo="";
        $StorkExtAuthAttrs="";
    }
    

    $Extensions = '<saml2p:Extensions>'
      .$SPtype  //eIDAS
      .$QAA  //Stork
      .$SPinfo  //Stork
      .$eIdShareInfo  //Stork
      .$RequestedAttributes
      .$StorkExtAuthAttrs  //Stork
      .'</saml2p:Extensions>';
    
    $NameIDPolicy = '';
    $AuthnContext = "";
    if($this->mode === 1){  //eIDAS only
        
        //Set the format of the identifier of the principal (persistent, transient, unspecified)
        $NameIDPolicy = '<saml2p:NameIDPolicy'
            .' AllowCreate="true"'
            .' Format="'.$this->nameIdFormat.'"'
            .' />';

        //Set the required Level of Assurance for authentication
        //(comparison is always minimum-required-value)
        $LoA = $this->QAALevel;
        if(is_int($this->QAALevel))
            $LoA = self::qaaToLoA($this->QAALevel);
        if($LoA != ""){
            $AuthnContext = '<saml2p:RequestedAuthnContext'
                .' Comparison="minimum">'
                .'<saml2:AuthnContextClassRef>'.htmlspecialchars($LoA).'</saml2:AuthnContextClassRef>'
                .'</saml2p:RequestedAuthnContext>';
        }
    }

    $Scoping = "";
    if($this->idplist != null){
        $idpList = "";
        foreach ($this->idplist as $idp)
            $idpList .= '<samlp:IDPEntry ProviderID="'.$idp.'" />';

        if($idpList != ""){
            $Scoping = '<samlp:Scoping>'
            .'  <samlp:IDPList>'
            .$idpList
            .'  </samlp:IDPList>'
            .'</samlp:Scoping>';
        }

    }


    
    //Compose the AuthnRequest
    $this->samlAuthReq = $RootTagOpen
      .$Issuer
      .$Extensions
      .$NameIDPolicy
      .$AuthnContext
      .$Scoping
      .'</saml2p:AuthnRequest>';
    
    
    if($signed){
      self::debug("Proceeding to sign the request.");
      $this->samlAuthReq = $this->calculateXMLDsig($this->samlAuthReq);
      self::debug("Request signed.");
    }
    
    self::info("Generated SamlAuth request.");
    self::trace($this->samlAuthReq);
    
    return $this->samlAuthReq;
  }
  
  public function getRequestId(){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");

    return $this->ID;
  }


  public function setRequestId($id){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    //Will overwrite ID generated on construction
    $this->ID = $id;
  }


  
  public function getRequestTimestamp(){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");

    return $this->TSTAMP;
  }
  
  
  
  // Returns the generated SAMLAuthRequest
  public function getSamlAuthReqToken(){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");

    
    if($this->samlAuthReq != NULL){
      return $this->samlAuthReq;
    }
    
    return "";
  }
  
  
  
  
  // Builds a POST request body (for user convenience)
  // $DestCountryCode -> The C-PEPS country code.
  public function buildPOSTBody($DestCountryCode){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");

    
    if($DestCountryCode == "")
      $this->fail(__FUNCTION__, self::ERR_NO_COUNTRYCODE);
    
    return "country=".$DestCountryCode."&SAMLRequest=".urlencode(base64_encode($this->samlAuthReq));
  }
  
  
  
  
  
  
  //Bool to string
  public static function bts($boolVar){
    
    self::trace(__CLASS__.".".__FUNCTION__."()");

    if($boolVar === true){
      return 'true';
    }else{
      return 'false';
    }
  }
  
  //String to Bool
  public static function stb($stringVar){
    
    self::trace(__CLASS__.".".__FUNCTION__."()");
    
    if(strtolower($stringVar) === 'true'){
      return true;
    }else{
      return false;
    }
  }

    /**
     * Returns the xml document signed in enveloped mode
     *
     * @throws Exception
     */
  private function calculateXMLDsig($xml, $insertAhead=false){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    $doc = new DOMDocument(); 
    $doc->formatOutput = false; 
    $doc->preserveWhiteSpace = false;
    $doc->loadXML($xml);
    
    self::debug("Parsed document to be signed.");
    
    $objDSig = new XMLSecurityDSig(); 
    $objDSig->setCanonicalMethod($this->c14nMethod);
    
    self::debug("Adding reference to root node.");
    // force_uri to force the URI="" attribute on signedinfo (required due to java sec bug)
    // overwrite to false avoid the ID overwrite.
    // $doc->documentElement instead of $doc to target the root element, not the document
    // id_name to set the name of the ID field of the signed node (default 'Id', we need 'ID').
    $objDSig->addReference($doc->documentElement, $this->digestMethod,
                           array('http://www.w3.org/2000/09/xmldsig#enveloped-signature', $this->c14nMethod),
                           array('force_uri'=>TRUE,'overwrite'=>FALSE,'id_name'=>"ID")); 
    
    self::debug("Loading signature key.");   
    $objKey = new XMLSecurityKey($this->signKeyType, array('type'=>'private'));
    $objKey->loadKey($this->signKey, FALSE);
  
    self::debug("Signing root node.");
    $objDSig->sign($objKey, $doc->documentElement);
  
    self::debug("Appending signature certificate.");
    $objDSig->add509Cert($this->signCert);
    
    if ($insertAhead ===true)
        $objDSig->appendSignature($doc->documentElement, true); //Inserts the signature ahead
    else{
        //On SAMLResponses, Signature above Status
        $statusnode = $doc->getElementsByTagName('Status')->item(0);
        
        //On SAMLAuthnReqs, Signature above Extensions
        $extensions = $doc->getElementsByTagName('Extensions')->item(0);
        
        $nextnode = $statusnode; //Inserts signature before the Status
        if ($nextnode === NULL) // If there is no status, then it is an AuthnReq
            $nextnode = $extensions;  //Inserts signature before the Extensions  // SEGUIR
        
        $objDSig->insertSignature($doc->documentElement, $nextnode);
    }
    
    self::debug("Marshalling signed document.");
    return $doc->saveXML();
  }



    /*******************  SAML RESPONSE PARSING AND VALIDATION  *******************/

    /**
     * Checks if a private key is valid and adds PEM headers if necessary
     *
     * @throws Exception
     */
  public function checkKey($key){
    
    if($key == null || $key == "")
        $this->fail(__FUNCTION__, self::ERR_EMPTY_KEY);
    
    $keyPem = $key;
    
    // We check it is a valid X509 private key
    try{
        @openssl_pkey_get_private($keyPem) or $this->fail(__FUNCTION__, self::ERR_RSA_KEY_READ);    
    }
    catch(Exception $e){
      $keyPem = str_replace("\n","",$keyPem);
      $keyPem =
        "-----BEGIN PRIVATE KEY-----\n"
        . chunk_split($keyPem,64,"\n")
        . "-----END PRIVATE KEY-----\n";
    }
    @openssl_pkey_get_private($keyPem) or $this->fail(__FUNCTION__, self::ERR_RSA_KEY_READ);    
    
    return $keyPem;
  }
  
  
  //Checks if cert is valid and adds PEM headers if necessary
  public function checkCert($cert){
      
      if($cert == null || $cert == "")
        $this->fail(__FUNCTION__, self::ERR_EMPTY_CERT);
    
    $certPem = $cert;
    //    SimpleSAML\Logger::debug("********** cert  at the beginning: ".$certPem);
    // We check it is a valid X509 certificate
//    try{
//      @openssl_x509_read($certPem) or $this->fail(__FUNCTION__, self::ERR_X509_CERT_READ);
//    }
//    catch(Exception $e){
      if (!@openssl_x509_read($certPem)){
        
          $certPem = str_replace("\n","",$certPem);
          $certPem =
              "-----BEGIN CERTIFICATE-----\n"
              . chunk_split($certPem,64,"\n")
              . "-----END CERTIFICATE-----\n";
          //SimpleSAML\Logger::debug("********** cert with headers?: ".$certPem);
      }
      //SimpleSAML\Logger::debug("********** cert at the end: ".$certPem);
      @openssl_x509_read($certPem) or $this->fail(__FUNCTION__, self::ERR_X509_CERT_READ);
      
      return $certPem;
  }
  
  
  //Turns a PEM certificate into a one-line b64 string (removing
  //headers, if any, and chunk splitting)
  public static function implodeCert($cert) {
      
      $certLine = str_replace("\n","",$cert);
      $certLine = str_replace("-----BEGIN CERTIFICATE-----","",$certLine);
      $certLine = str_replace("-----END CERTIFICATE-----","",$certLine);
      
      return $certLine;
  }
  
  
  
  // Adds a certificate to the trusted certificate list
  public function addTrustedCert ($cert){
        
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    if($cert == null || $cert == "")
      $this->fail(__FUNCTION__, self::ERR_EMPTY_CERT);
    
    $this->trustedCerts [] = $this->checkCert($cert);
  }
  
  
  //Set all values that may be compared

  // $mandatoryAttrs: List of attribute friendly names thar were mandatory on the request.
  public function setValidationContext($requestId,
                                       $assertionConsumerUrl=NULL,
                                       $expectedIssuers=NULL,
                                       $mandatoryAttrList=NULL){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    $this->requestId            = $requestId;
    $this->assertionConsumerUrl = $assertionConsumerUrl;
    $this->expectedIssuers       = $expectedIssuers;
    $this->mandatoryAttrList    = $mandatoryAttrList;
  }
  
  
  
  //Validates the received SamlResponse by comparing it to the request  // TODO adapt for eIDAs: review
  public function validateStorkResponse($storkSamlResponseToken, $checkDates=True, $checkSignature=True){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    self::trace("Received SamlResponse token:\n".$storkSamlResponseToken);
    
    if($storkSamlResponseToken == null || $storkSamlResponseToken == "")
      $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
    
    self::debug("Parsing response.");
    //Checks if it is a valid XML string.
    $samlResponse = $this->parseXML($storkSamlResponseToken);
    
    
    //Validates the signature
    if($checkSignature){
      self::debug("Checking response signature.");
      $this->validateXMLDSignature($storkSamlResponseToken);
    }   
    
    self::debug("Checking response validity.");
    //Root node must be 'Response'
    if(strtolower($samlResponse->getName()) != 'response')
      $this->fail(__FUNCTION__, self::ERR_UNEXP_ROOT_NODE);
    
        
    $this->inResponseTo         = "".$samlResponse["InResponseTo"];
    $this->responseDestination  = "".$samlResponse["Destination"];
    $this->responseIssuer       = "".$samlResponse->children(self::NS_SAML2,false)->Issuer;

    self::trace("inResponseTo:         ".$this->inResponseTo);
    self::trace("responseDestination:  ".$this->responseDestination);
    self::trace("responseIssuer:       ".$this->responseIssuer);
    

    //Check existance of mandatory elements/attributes
    if(!$this->inResponseTo || $this->inResponseTo == ""){
      $this->fail(__FUNCTION__, self::ERR_RESP_NO_REQ_ID);
    }
    if(!$this->responseDestination || $this->responseDestination == ""){
      $this->fail(__FUNCTION__, self::ERR_RESP_NO_DESTINATION);
    }
    if(!$this->responseIssuer || $this->responseIssuer == ""){
      $this->fail(__FUNCTION__, self::ERR_RESP_NO_ISSUER);
    }
    
    self::debug("Comparing with context values if set.");
    // Compare with context values, if set
    if($this->requestId){
      self::debug("Comparing with requestID.");
      if(trim($this->requestId) != trim($this->inResponseTo))
        $this->fail(__FUNCTION__, self::ERR_UNEXP_REQ_ID,$this->requestId." != ".$this->inResponseTo);
    }
    if($this->assertionConsumerUrl){
      self::debug("Comparing with assertionConsumerURL.");
      if(trim($this->assertionConsumerUrl) != trim($this->responseDestination))
        $this->fail(__FUNCTION__, self::ERR_UNEXP_DEST,$this->assertionConsumerUrl." != ".$this->responseDestination);
    }
    if($this->expectedIssuers){
      foreach($this->expectedIssuers as $expectedIssuer){
        self::debug("Comparing with expected Issuer: $expectedIssuer");
        if(trim($expectedIssuer) == trim($this->responseIssuer))
          $found = true;
      }
      if(!$found)
        $this->fail(__FUNCTION__, self::ERR_UNEXP_ISSUER,"response issuer: ".$this->responseIssuer);
    }
    
    self::debug("Parsing response status.");
    //Get status info
    self::parseStatus($samlResponse);
    
    // If successful, must have at least one assertion.
    if(self::isSuccess($aux)){
        
        self::debug("Response Successful.");
        
        //Search for encrypted assertions and try to decrypt them beforehand
        if ($this->doDecipher == TRUE){
            self::debug("Searching for encrypted assertions...");
            $samlResponse = $this->decryptAssertions($storkSamlResponseToken);
        }
        
        self::debug("Searching for assertions.");
        $assertions = $samlResponse->children(self::NS_SAML2,false)->Assertion;
      
        self::trace("Assertions SimpleXML node: \n".print_r($assertions,true));
        if(!$assertions || count($assertions)<=0)
            $this->fail(__FUNCTION__, self::ERR_RESP_SUCC_NO_ASSERTIONS);
      
        self::debug("Parsing response assertions.");
        //Get attribute info
        self::parseAssertions($assertions);          
      
        self::debug("Checking validity dates for each assertion.");
        $now = time();
        foreach($assertions as $assertion){
        
            //Validate validity dates for each assertion
            if($checkDates){
                $NotBefore    = "".$assertion->Conditions->attributes()->NotBefore;
                $NotOnOrAfter = "".$assertion->Conditions->attributes()->NotOnOrAfter;
          
                self::checkDates($now,$NotBefore,$NotOnOrAfter);
            }
        
        }
        
        
        //Get data from the first assertion
        if($samlResponse->children(self::NS_SAML2,false)->Assertion[0]->Subject){
            $this->responseNameId       = "".$samlResponse->children(self::NS_SAML2,false)->Assertion[0]->Subject->NameID;
            $this->responseNameIdFrm    = "".$samlResponse->children(self::NS_SAML2,false)->Assertion[0]->Subject->NameID->attributes()->Format;
        }
        $this->AuthnInstant         = "".$samlResponse->children(self::NS_SAML2,false)->Assertion[0]->AuthnStatement->attributes()->AuthnInstant;
        $this->AuthnContextClassRef = "".$samlResponse->children(self::NS_SAML2,false)->Assertion[0]->AuthnStatement->AuthnContext->AuthnContextClassRef;
        
        self::trace("responseNameId:       ".$this->responseNameId);
        self::trace("responseNameIdFrm:    ".$this->responseNameIdFrm);
        self::trace("AuthnInstant:         ".$this->AuthnInstant);
        self::trace("AuthnContextClassRef: ".$this->AuthnContextClassRef);
    }
    

    // Once all assertions are parsed check if all mandatory attributes have been served.
    if($this->mandatoryAttrList){
        self::debug("Checking that mandatory attributes were served.");      
        foreach($this->mandatoryAttrList as $mAttr){
            self::trace("Searching attribute: $mAttr");
            $found = false;
            foreach($this->responseAssertions as $assertion){
                foreach($assertion['Attributes'] as $attr){          
                    if(trim($attr['friendlyName']) == trim($mAttr)
                    && $attr['AttributeStatus'] == self::ATST_AVAIL){
                        self::trace("$mAttr found.");
                        $found = true;
                        break 2;
                    }
                }
            }
            if(!$found){
                $this->fail(__FUNCTION__, self::ERR_RESP_NO_MAND_ATTR);
            }
        }
    }
    
    $this->SAMLResponseToken = $storkSamlResponseToken;
  }
  
  
  
  //Returns whether the request was in success status.
  // $statusInfo: Status primary and secondary (if exists) codes will be returned here.
  public function isSuccess(&$statusInfo){
        
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    $statusInfo = $this->responseStatus;
    
    return $this->responseSuccess;
  }


  //Returns the status array
  public function getResponseStatus(){
      self::debug(__CLASS__.".".__FUNCTION__."()");
      
      return $this->responseStatus;
  }
  
  
  // Returns the signing certificate for the response that came
  // embedded on the keyinfo node, so the user can compare it.
  // Returns the certificate in PEM format or NULL.
  // Won't be set if signature validation is skipped.
  public function getEmbeddedSigningCert(){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    return $this->signingCert;
  }
  
  // Returns the issuer ID of the S-PEPS.
  public function getRespIssuer(){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    if($this->SAMLResponseToken == null)
      $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
    
    return $this->responseIssuer;
  }


  public function getRespNameID(){
      
      self::debug(__CLASS__.".".__FUNCTION__."()");
      
      if($this->SAMLResponseToken == null)
          $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
      
      return $this->responseNameId;
  }


  public function getRespNameIDFormat(){
      
      self::debug(__CLASS__.".".__FUNCTION__."()");
      
      if($this->SAMLResponseToken == null)
          $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
      
      return $this->responseNameIdFrm;
  }
  

  public function getAuthnInstant(){
      
      self::debug(__CLASS__.".".__FUNCTION__."()");
      
      if($this->SAMLResponseToken == null)
          $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
      
      return $this->AuthnInstant;
  }


  public function getAuthnContextClassRef(){
      
      self::debug(__CLASS__.".".__FUNCTION__."()");
      
      if($this->SAMLResponseToken == null)
          $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
      
      return $this->AuthnContextClassRef;
  }
  
  
  
  // Returns the ID of the request this response is addressed to.
  public function  getInResponseTo (){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    if($this->SAMLResponseToken == null)
      $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
    
    return $this->inResponseTo;
  }

  // Returns the URL at which this response was addressed to.
  public function  getResponseDestination (){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    if($this->SAMLResponseToken == null)
      $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
    
    return $this->responseDestination;
  }


  
  // Returns an array of assertions with all relevant information:
  // subject, issuer, attributes
  public function getAssertions(){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    if($this->SAMLResponseToken == null || $this->responseAssertions == NULL)
      $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
    
    return $this->responseAssertions;
  }
  
  
  
  // Returns a list containing all the attributes stated on all the
  // assertions merged, for each attribute, a list of values is provided
  public function getAttributes(){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    if($this->SAMLResponseToken == null || $this->responseAssertions == NULL)
      $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
    
    $attributes = array();
    foreach($this->responseAssertions as $assertion){
      foreach($assertion['Attributes'] as $attr){
        
        $attributeName = $attr['friendlyName'];
        
        //If we haven't found an attribute with the same name, we create the value array
        if(!isset($attributes[$attributeName]))
          $attributes[$attributeName] = array();
        
        if($attr['values'])
          foreach($attr['values'] as $value){
            // We added a functionality to get the metadata of the attr value,
            // but here we don't want it // TODO: works?
            if(is_array($value))
                $value = $value['value'];
            $attributes[$attributeName][] = $value;
          }
      }
    }
    
    return $attributes;
  }



  // Returns a list containing the pairing between attribute names and
  // friendly anmes, if available
  public function getAttributeNames(){
      
      self::debug(__CLASS__.".".__FUNCTION__."()");
      
      if($this->SAMLResponseToken == null || $this->responseAssertions == NULL)
          $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
      
      $pairings = array();
      foreach($this->responseAssertions as $assertion){
          foreach($assertion['Attributes'] as $attr){
              if(isset($attr['friendlyName'])
              && isset($attr['Name'])){
                  $pairings[$attr['friendlyName']] = $attr['Name'];
              }
          }
      }
      
      return $pairings;
  }
  
  
  
  private function checkDates($now,$NotBefore,$NotOnOrAfter){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    self::trace("Now:          ".date('c',$now));
    self::trace("notBefore:    ".$NotBefore);
    self::trace("notOnOrAfter: ".$NotOnOrAfter);
    
    if($NotBefore != NULL && $NotBefore != "")
      if( $now < strtotime($NotBefore) )
        $this->fail(__FUNCTION__, self::ERR_SAMLRESP_STILLNOTVALID, "Now: ".date('c',$now).". Not until: $NotBefore.");
    
    if($NotOnOrAfter != NULL && $NotOnOrAfter != "")
      if( $now >= strtotime($NotOnOrAfter) )
        $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EXPIRED, "Now: ".date('c',$now).". Not on or after: $NotOnOrAfter.");

  }

  //Parse the status node on the SamlResponse
  private function parseStatus($samlResponse){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    $status = $samlResponse->children(self::NS_SAML2P,false)->Status;
    
    if(!$status)
      $this->fail(__FUNCTION__, self::ERR_SAMLRESP_NOSTATUS);
    
    
    $statusInfo = array();
    $statusInfo ["MainStatusCode"]      = "".$status->StatusCode->attributes()->Value;
    $statusInfo ["SecondaryStatusCode"] = NULL;
    
    
    if($status->StatusMessage)
      $statusInfo ["StatusMessage"] = "".$status->StatusMessage;
    
    if ($statusInfo ["MainStatusCode"] == self::ST_SUCCESS){
      $this->responseSuccess = true;
    }
    else{
      $this->responseSuccess = false;
      
      if($status->StatusCode->StatusCode)
        $statusInfo ["SecondaryStatusCode"] = "".$status->StatusCode->StatusCode->attributes()->Value;
    }
    
    $this->responseStatus = $statusInfo;
  }
  
  
  //Parse and extract information from the assertion subject
  // $subject:  SimpleXML object representing the Subject  // TODO see if namequalifier being absent is a problem
  private function parseAssertionSubject($subject){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    if(!$subject){
        //$this->fail(__FUNCTION__, self::ERR_NO_ASSERT_SUBJECT);
        return NULL;
    }

    try{
      $subjectInfo = array(
        "NameID"        => "".$subject->NameID, //In eIDAS, it will be the same as the PersonIdentifier attribute
        "NameFormat"    => "".$subject->NameID->attributes()->Format,
        "NameQualifier" => "".$subject->NameID->attributes()->NameQualifier,
        "Method"        => "".$subject->SubjectConfirmation->attributes()->Method,
        "Address"       => "".$subject->SubjectConfirmation->SubjectConfirmationData->attributes()->Address,
        "InResponseTo"  => "".$subject->SubjectConfirmation->SubjectConfirmationData->attributes()->InResponseTo,
        "NotOnOrAfter"  => "".$subject->SubjectConfirmation->SubjectConfirmationData->attributes()->NotOnOrAfter,
        "NotBefore"     => "".$subject->SubjectConfirmation->SubjectConfirmationData->attributes()->NotBefore,
        "Recipient"     => "".$subject->SubjectConfirmation->SubjectConfirmationData->attributes()->Recipient
      );
      if($subject->NameID->attributes()->NameQualifier) //In Stork, should be the DomainName of the C-PEPS
          $subjectInfo["NameQualifier"] = "".$subject->NameID->attributes()->NameQualifier;
      
    } catch(Exception $e){
      $this->fail(__FUNCTION__, self::ERR_BAD_ASSERT_SUBJ,$e);
    }
    
    return $subjectInfo;
  }
  
  
  //Parse and extract information from the assertions
  // $assertions: SimpleXML object representing the SamlResponse Assertion nodes
  private function parseAssertions($assertions){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    self::info("Number of assertions in response: ".count($assertions));
    
    $this->responseAssertions = array();
    
    try{
      foreach($assertions as $assertion){
        
        //AssertionID
        $assertionID = "".$assertion->attributes()->ID;
        if($assertionID == "")
          $this->fail(__FUNCTION__, self::ERR_NO_ASSERT_ID);
        
        self::debug("Assertion ID: ".$assertionID);

        if(isset($this->responseAssertions[$assertionID]))
          $this->fail(__FUNCTION__, self::ERR_DUP_ASSERT_ID);
        $assertionInfo = array();
        
        //Basic assertion info
        $assertionInfo['ID'] = $assertionID;
        $assertionInfo['IssueInstant'] = "".$assertion->attributes()->IssueInstant;
        $assertionInfo['Issuer'] = "".$assertion->Issuer;

        self::debug("Parsing issuer.");        
        //Must have an Issuer
        if($assertionInfo['Issuer'] == "")
          $this->fail(__FUNCTION__, self::ERR_NO_ASSERT_ISSUER);

        self::debug("Parsing subject.");
        //Subject
        $assertionInfo['Subject'] = self::parseAssertionSubject($assertion->Subject);
 
        self::debug("Parsing conditions.");       
        //Conditions
        $assertionInfo['Conditions'] = array(
            'NotBefore'    => "".$assertion->Conditions->attributes()->NotBefore,
            'NotOnOrAfter' => "".$assertion->Conditions->attributes()->NotOnOrAfter,
            'OneTimeUse'   => "".($assertion->Conditions->OneTimeUse ? True : False),
            'Audience'     => array()
                                             );  
        foreach($assertion->Conditions->AudienceRestriction->Audience as $audience)
          $assertionInfo['Conditions']['Audience'][] = "".$audience;

        self::debug("Parsing Authentication Statement.");
        //Authentication Statement
        $assertionInfo['AuthnStatement'] = array(
            'AuthnInstant' => "".$assertion->AuthnStatement->attributes()->AuthnInstant,
            'SessionIndex' => "".$assertion->AuthnStatement->attributes()->SessionIndex
                                                 );
        if($assertion->AuthnStatement->SubjectLocality){
          $assertionInfo['AuthnStatement']['LocalityAddress'] = "".$assertion->AuthnStatement->SubjectLocality->attributes()->Address;
          $assertionInfo['AuthnStatement']['LocalityDNSName'] = "".$assertion->AuthnStatement->SubjectLocality->attributes()->DNSName;
        }
        
        //On eIDAS, this is the QAA of the authentication
        if($assertion->AuthnStatement->AuthnContext){
          if($assertion->AuthnStatement->AuthnContext->AuthnContextClassRef){
              $assertionInfo['AuthnStatement']['AuthnContext'] = "".$assertion->AuthnStatement->AuthnContext->AuthnContextClassRef;
          }
        }
        
        self::debug("Parsing Attributes.");        
        //Get Attributes
        $assertionInfo['Attributes'] =  $this->parseAssertionAttributes($assertion->AttributeStatement, true);  // TODO SEGUIR he quitado el self porque no es static!
        
        self::trace("Assertion SimpleXMLNode:\n".print_r($assertion,true));
        self::trace("Assertion storkAuth inner Struct:\n".print_r($assertionInfo,true));
        
        $this->responseAssertions[$assertionID] = $assertionInfo;
        
      }//foreach
      
    }catch(Exception $e){
      $this->fail(__FUNCTION__, self::ERR_BAD_ASSERTION,$e);
    }
    
  }//function
  
  
  //Parses the attribute statement of an assertion.
  // $attributes: SimpleXML object representing the attribute statement
  // $returnValueMeta: eIDAS has some xml attributes indicating the type/language, etc. of each value. If true, values will be arrays and not strings, containing the value and its metadata
  //Will return an array with the assertion data. 0n eIDAS, attribute
  //values have one more level of depth: access as ['value']['value]
  private function parseAssertionAttributes($attributeStatement, $returnValueMeta=false){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    if(!$attributeStatement)
      $this->fail(__FUNCTION__, self::ERR_ASSERT_NO_ATTRS);
    
    $attrInfo = array();
    foreach ($attributeStatement->Attribute as $attr){
      
      if($this->mode === 0){ //Stork
          $attrname = preg_replace("|.+/(.+?)$|i", "\\1", $attr->attributes()->Name);
          $attrstatus = "".$attr->attributes(self::NS_STORK,false)->AttributeStatus;
      }
      if($this->mode === 1){ //eIDAS
          $attrname = "".$attr->attributes()->FriendlyName;
          $attrstatus = NULL;
      }
      
      //Status is optional. default value is available
      if(!$attrstatus)
        $attrstatus = self::ATST_AVAIL;

      self::debug("********MODE: ".$this->mode);
      self::debug("Parsing Attribute: ".$attr->attributes()->Name." ($attrname)");
      
      $attribute = array(
         'friendlyName'    => $attrname,
         'Name'            => "".$attr->attributes()->Name,
         'NameFormat'      => "".$attr->attributes()->NameFormat,
         'AttributeStatus' => $attrstatus
                         );
      
      //If status is available, we search for attributeValue
      if($attrstatus == self::ATST_AVAIL){
        self::debug("Attribute $attrname available.");
        
        $attribute['values'] = array();
        foreach ($attr->AttributeValue as $attrval){

          
          //$attribute['values'][] = $attrval->asXML();
          
          if($this->mode === 0){ //Stork

                //Looks for XML nodes in the STORK namespace inside attribute value
                if(count($attrval->children(self::NS_STORK)) <= 0){
                    self::trace("Attribute $attrname is simple.");
                    $attribute['values'][] = "".$attrval;
                }else{
                    self::trace("Attribute $attrname is complex.");
                    $complexAttr = $attrval->xpath("*");
                    //We cat the XML for all children to return it
                    if($complexAttr && count($complexAttr)>0){
                        /*  $complexVal = "";
                            foreach($complexAttr as $subattr)
                            $complexVal .= $subattr->asXML();
                            $attribute['values'][] = $complexVal;*/
              
                        //// !!!! -*-*
              
                        $attrNode = new SimpleXMLElement('<stork:'.$attrname
                        .' xmlns:stork="'.self::NS_STORK.'"></stork:'.$attrname.'>');//,NULL,false,'stork',true);
              
                        //echo "\n***********".$attrNode->asXML()."\n";

                        //Declaring stork assertion namespace [xmlns:xmlns: is a common workaround to allow the ns declaration]
                        //$attrNode->addAttribute('xmlns:xmlns:stork','urn:eu:stork:names:tc:STORK:1.0:assertion');
                        foreach($complexAttr as $subattr)
                            $attrNode->addChild($subattr->getName(),"".$subattr);
              
                        //              echo "\n***********".$attrNode->xpath("//*")[0]->asXML()."\n";
                        $attribute['values'][] = $attrNode->asXML();

                    }
                }
          }

          //No complex attributes. Complex ones are in b64 (won't
          //decode, this is SP's task, and dependent on the attribute
          //semantics, defined by the type, defined on a profile).
          //Also, now values is an array pof arrays, and not of
          //strings
          if($this->mode === 1){ //eIDAS

              if ($returnValueMeta == true){
                  $valueNode = array(   // TODO  ojo: revisar cuando pueda hacer pruebas reales. el prefijo podría cambiar si hay varios namespaces  y requeriría buscarlos todos o pasar el namespace tal cual.
                      'value' => "".$attrval,
                      'type'  => "".$attrval->attributes("xsi",TRUE)->type,
                      'LatinScript' => "".$attrval->attributes("eidas-natural",TRUE)->LatinScript,
              );
              
              
                  if($attrval->attributes()->languageID)
                      $valueNode['languageID'] = "".$attrval->attributes()->languageID;
              
                  if($attrval->attributes(self::NS_EIDASATT)->Transliterated)
                      $valueNode['Transliterated'] = "".$attrval->attributes(self::NS_EIDASATT)->Transliterated;
              }
              else{
                  $valueNode = "".$attrval;
              }
              
              $attribute['values'][] = $valueNode;
          }
          
        }
      }
      else // Not available or withheld
        $attribute['values'] = NULL;
      
      $attrInfo []= $attribute;
    }
    self::trace("Attributes processed:".print_r($attrInfo,true));
    return $attrInfo;
  }
  
  
  
  //Verifies the enveloped signature on an XML document, with the embedded 
  //certificate or optionally an externally provided certificate.
  private function verifySignature($data,$externalKey="") {
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    self::debug("Parsing signed document.");
    $doc = new DOMDocument();   
    if (!$doc->loadXML($data)){
      $this->fail(__FUNCTION__, self::ERR_BAD_XML_SYNTAX);
    }

    self::debug("Instantiating xmlseclibs object.");    
    $objXMLSecDSig = new XMLSecurityDSig();

    self::debug("Searching Signature node.");
    //Shouldn't use this one because it locates all Signature nodes
    //and will keep the first one regardles of which it is, and we
    //need to ignore the Assertion signatures.
    //$objDSig = $objXMLSecDSig->locateSignature($doc);
    $objDSig =  null;
    if ($doc != NULL &&  ($doc instanceof DOMDocument)) {
      $xpath = new DOMXPath($doc);
      $xpath->registerNamespace('ds', self::NS_XMLDSIG);
      //This query allows to get only the first level Signature
      //node, not the ones inside the Assertions.
      $query = "/*/ds:Signature";
      $nodeset = $xpath->query($query, $doc);
      $objDSig = $nodeset->item(0);
      if($objDSig)
        self::trace("Signature node found:".$doc->saveXML($objDSig));
      //We must reference the signature node on the class
      $objXMLSecDSig->sigNode = $objDSig;
    }
    
    if (!$objDSig) {
      $this->fail(__FUNCTION__, self::ERR_NO_SIGNATURE);
    }
    
    self::debug("Canonicalizing signedinfo.");
    $objXMLSecDSig->canonicalizeSignedInfo();
    
    $objXMLSecDSig->idKeys = self::$referenceIds;
    //To declare Namespaces and prefixes for the XPath queries 
    //$objXMLSecDSig->idNS = array('ds'=>'http://www.w3.org/2000/09/xmldsig#',
    //                             'saml2p'=>'urn:oasis:names:tc:SAML:2.0:protocol');	
    try{
      self::debug("Validating root node reference.");
      $retVal = $objXMLSecDSig->validateReference();
      if (!$retVal) {
        $this->fail(__FUNCTION__, self::ERR_REF_VALIDATION);
      }
    }catch(Exception $e){
      $this->fail(__FUNCTION__, self::ERR_REF_VALIDATION,$e);
    }

    
    self::debug("Searching Keyinfo.");
    //Locates the key info on the signature node and sets the
    //sig-method and the key type (public)
    $objKey = $objXMLSecDSig->locateKey();
    if (!$objKey ) {
      $this->fail(__FUNCTION__, self::ERR_MISSING_SIG_INFO);
    }

    self::debug("Loading embedded verification public key.");
    //Getting the keyinfo node (which will contain the signing certificate/key)
    $objKeyInfo = NULL;
    try{
      $objKeyInfo = XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);
    }catch(Exception $e){
      self::warn("No embedded key found. No keyinfo node.");
    }
    
    
    //Check if signing algorithm is supported (DUE TO A BUG DETECTED
    //BY SSPHP, ONLY THESE ARE DEEMED SAFE)
    $algorithm = $objKey->getAlgorith();   
    if (!in_array($algorithm, array(
        XMLSecurityKey::RSA_1_5,
        XMLSecurityKey::RSA_SHA1,
        XMLSecurityKey::RSA_SHA256,
        XMLSecurityKey::RSA_SHA384,
        XMLSecurityKey::RSA_SHA512
    ))) {
        $this->fail(__FUNCTION__, self::ERR_GENERIC,"Unsupported signing algorithm.");               
    }
    
    //Build the key object for the external validation key
    $extKey = new XMLSecurityKey($algorithm, array('type'=>'public'));
    
    if($externalKey === NULL || $externalKey === ""){
        $this->fail(__FUNCTION__, self::ERR_GENERIC,"Missing external validation key.");
    }
    
    //Load the validation key
    self::debug("Loading external verification public key material.");
    self::trace("KEY: \n".$externalKey);    
    $extKey->loadKey($externalKey);
    
    
    //We store the certificate that came with the request, for
    //debugging purposes
    self::trace("Storing embedded key.");
    $this->signingCert = $objKeyInfo->getX509Certificate();
    self::trace("KEY: \n".$this->signingCert);
    
    
    //Try to validate with the external key
    if ($extKey->key === NULL){
        $this->fail(__FUNCTION__, self::ERR_BAD_PUBKEY_CERT);
        return false;
    }
    
    self::debug("Verifying signature with external key.");
    $verified = false;
    if($objXMLSecDSig->verify($extKey) === 1){
        self::debug("Success.");
        $verified = true;
    }
    else{
        self::debug("Failure.");
    }
    
    return $verified;
  }
  
  
  
  //Validate SamlResponseToken against all trusted issuer certificates.
  private function validateXMLDSignature($xml){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    if($xml == null)
      $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
    
    //Test self validation.
    /*
    if(count($this->trustedCerts) <=0){
      self::debug("self validation.");
      if(!$this->verifySignature($xml)){
        self::debug("Self validation failure.");
        $this->fail(__FUNCTION__, self::ERR_SIG_VERIF_FAIL,$this->signingCert);
      }
      self::debug("Self validation success.");
      return True;
    }
    */
    
    //Check all trusted issuer certificates.
    //If response has embedded key, always does a signature
    //verification and if failure, its result has priority over
    //external verification
    self::debug("Starting external validation [].");
    $validated = false;
    foreach($this->trustedCerts as $cert){
      self::debug("Validating with external cert:\n".$cert);
      if($this->verifySignature($xml,$cert)){
        self::debug("Validated.");
        $validated = true;
        break;
      }
    }
    
    if(!$validated){
      self::trace("External validation failure.");
      $this->fail(__FUNCTION__, self::ERR_SIG_VERIF_FAIL);
    }
    
    return True;
  }
  
  
  
  private function parseXML($xmlStr){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    if($xmlStr == null || $xmlStr == "")
        $this->fail(__FUNCTION__, self::ERR_SAMLRESP_BADXML,"empty string");    
    
    try{
      @$xmlObj = new SimpleXMLElement($xmlStr);
      
      if ($xmlObj == null){
        $this->fail(__FUNCTION__, self::ERR_SAMLRESP_BADXML,"object is null");
      }      
      //echo "Declared namespaces: \n";print_r($xmlObj->getDocNamespaces(true));echo "----\n";print_r($xmlObj);
      
    }catch(Exception $e){
      $this->fail(__FUNCTION__, self::ERR_SAMLRESP_BADXML, $e);
    }
    
    return $xmlObj;
  }



  private function parseScoping($samlReq){
    self::debug(__CLASS__.".".__FUNCTION__."()");

    if($samlReq == null)
      $this->fail(__FUNCTION__, self::ERR_BAD_PARAMETER,"samlReq object is null");

    $idpList = [];
    $idpEntries = $samlReq->children(self::NS_SAML2P,false)->Scoping->IDPList->IDPEntry ?? NULL;
    if($idpEntries != null)
        foreach($idpEntries as $idpEntry){
            $idpList []= "".$idpEntry->attributes()->ProviderID;
        }
    return $idpList;
  }





    public function getInResponseToFromReq($storkSamlResponseToken){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    self::trace("SamlResponse token:\n".$storkSamlResponseToken);
    
    if($storkSamlResponseToken == null || $storkSamlResponseToken == "")
      $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
    
    self::debug("Parsing response.");
    //Checks if it is a valid XML string.
    $samlResponse = $this->parseXML($storkSamlResponseToken);
    
    return "".$samlResponse["InResponseTo"];
  }




  /*******************  SAML AUTHN REQUEST PARSING AND VALIDATION  *********************/


  // Adds a trusted request issuer to the list. Must 
  public function addTrustedRequestIssuer($issuer, $certs){
        
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    if($issuer == null || $issuer == "")
      $this->fail(__FUNCTION__, self::ERR_GENERIC,"Missing or empty issuer entityId.");

    if($certs == null || $certs == array())
      $this->fail(__FUNCTION__, self::ERR_EMPTY_CERT);

    $this->trustedIssuers[$issuer] = array();
    foreach($certs as $cert)
        $this->trustedIssuers[$issuer] []= $this->checkCert($cert); 
  }
  
  
  //Validates the received SamlAuthnReq towards the list of authorised issuers.
  public function validateStorkRequest($storkSamlRequestToken){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    self::trace("Received SamlRequest token:\n".$storkSamlRequestToken);
    
    if($storkSamlRequestToken == null || $storkSamlRequestToken == "")
      $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
    
    
    self::debug("Parsing request.");
    //Checks if it is a valid XML string.
    $samlReq = $this->parseXML($storkSamlRequestToken);

    self::debug("Checking request validity.");
    //Root node must be 'AuthnRequest'
    if(strtolower($samlReq->getName()) != 'authnrequest')
      $this->fail(__FUNCTION__, self::ERR_UNEXP_ROOT_NODE);
    
    //We get the issuer
    $issuer = "".$samlReq->children(self::NS_SAML2,false)->Issuer;
    if($issuer == "")
        $issuer = "".$samlReq["ProviderName"]; // Dirty workaround for Clave 2.0 java SPs not using issuers TODO: verify.

    //Validates the signature
    self::debug("Checking request signature. Issuer: ".$issuer);


    $verified = false;
    foreach($this->trustedIssuers[$issuer] as $cert){
        
        if($cert == NULL || $cert == "")
            $this->fail(__FUNCTION__, self::ERR_NONAUTH_ISSUER);
        
        if($this->verifySignature($storkSamlRequestToken,$cert))
            $verified = true;
    } 
    if(!$verified){
        self::trace("Cert validation failure.");
        $this->fail(__FUNCTION__, self::ERR_SIG_VERIF_FAIL);
    }
        
    $this->SAMLAuthnReqToken = $storkSamlRequestToken;
  }

  //Returns an array with the important parameters of the received request
  // If a Request is passed on the parameter, then the return is related
  // to it and not to the request in the object state       // TODO test eIDAS support 
  public function getStorkRequestData($SAMLAuthnReqToken=NULL){
      
      self::debug(__CLASS__.".".__FUNCTION__."()");
      
      $ret = array();
      
      $request = $this->SAMLAuthnReqToken;
      if($SAMLAuthnReqToken !== NULL){
          self::debug("Notice that you are parsing an external token and not the internal state one");
          $request = $SAMLAuthnReqToken;
      }
      
      $samlReq = $this->parseXML($request);
      
      $ret['id']                   = "".$samlReq["ID"];
      $ret['destination']          = "".$samlReq["Destination"];
      $ret['protocolBinding']      = "".$samlReq["ProtocolBinding"];
      $ret['ProviderName']         = "".$samlReq["ProviderName"];
      $ret['forceAuthn']           = self::stb("".$samlReq["ForceAuthn"]);
      $ret['isPassive']            = self::stb("".$samlReq["IsPassive"]);
      
      if(isset($samlReq["AssertionConsumerServiceURL"]))
          $ret['assertionConsumerService'] = "".$samlReq["AssertionConsumerServiceURL"];
      
      $ret['issuer'] = "".$samlReq->children(self::NS_SAML2,false)->Issuer;      
      
      $ext = $samlReq->children(self::NS_SAML2P,false)->Extensions;

      //Check for scoping (list of allowed remote IDPs in a proxying request)
      $ret['idplist'] =  $this->parseScoping($samlReq);
      // TODO: SEGUIR: funciona?


      if($this->mode === 0){ //Stork
          self::debug("Mode 0");
          
          $authAttrs = $ext->children(self::NS_STORKP,false)->AuthenticationAttributes->VIDPAuthenticationAttributes;
          $reqAttrs  =  $ext->children(self::NS_STORKP,false)->RequestedAttributes->children(self::NS_STORK,false);
          
          $ret['QAA'] = "".$ext->children(self::NS_STORK,false)->QualityAuthenticationAssuranceLevel;
          $ret['spSector'] = "".$ext->children(self::NS_STORK,false)->spSector;
          $ret['spInstitution'] = "".$ext->children(self::NS_STORK,false)->spInstitution;
          $ret['spApplication'] = "".$ext->children(self::NS_STORK,false)->spApplication;
          $ret['spCountry'] = "".$ext->children(self::NS_STORK,false)->spCountry;
          $ret['eIDSectorShare'] = "".$ext->children(self::NS_STORKP,false)->eIDSectorShare;
          $ret['eIDCrossSectorShare'] = "".$ext->children(self::NS_STORKP,false)->eIDCrossSectorShare;
          $ret['eIDCrossBorderShare'] = "".$ext->children(self::NS_STORKP,false)->eIDCrossBorderShare;
          $ret['citizenCountryCode'] = "".$authAttrs->CitizenCountryCode;
          $ret['spID'] = "".$authAttrs->SPInformation->SPID;
          
          
          $ret['requestedAttributes'] = array();  // TODO: SEGUIR soportar aquí que se lean y retransmitan los values de los attr solicitados
          foreach($reqAttrs as $reqAttr){
              
              $values = array();
              foreach ($reqAttr->AttributeValue as $val){
                  $values []= "".$val;
              }
              
              $ret['requestedAttributes'] []= array(
                  'name'         => "".$reqAttr->attributes()->Name,
                  //'friendlyName' => "".$reqAttr->attributes()->Name,
                  //Also empty string will be evaluated to false
                  'isRequired'   => strtolower("".$reqAttr->attributes()->isRequired) === 'true'? true : false,
                  'values'       => $values
              ); 
          }
      }
      
      if($this->mode === 1){ //eIDAS
          self::debug("Mode 1");
          
          $authContext  = $samlReq->children(self::NS_SAML2P,false)->RequestedAuthnContext;
          $nameIDPolicy = $samlReq->children(self::NS_SAML2P,false)->NameIDPolicy;
          $reqAttrs     =  $ext->children(self::NS_EIDAS,false)->RequestedAttributes->children(self::NS_EIDAS,false);

          $ret['spSector'] = "";
          $ret['spInstitution'] = "";
          $ret['spApplication'] = "";
          $ret['spCountry'] = "";
          $ret['eIDSectorShare'] = "";
          $ret['eIDCrossSectorShare'] = "";
          $ret['eIDCrossBorderShare'] = "";
          $ret['citizenCountryCode'] = "";
          $ret['spID'] = "";
          
          $ret['Comparison']    = "".$authContext->attributes()->Comparison; 
          $ret['LoA']           = "".$authContext->children(self::NS_SAML2,false)->AuthnContextClassRef;//*****
          $ret['SPType']        = "".$ext->children(self::NS_EIDAS,false)->SPType;

          $ret['QAA']           = self::loaToQaa($ret['LoA']);    //Derived from LoA

          $ret['IdAllowCreate'] = "".$nameIDPolicy->attributes()->AllowCreate;
          $ret['IdFormat']      = "".$nameIDPolicy->attributes()->Format;

          $ret['requestedAttributes'] = array();
          foreach($reqAttrs as $reqAttr){
              
              $values = array();
              foreach ($reqAttr->AttributeValue as $val){
                  $values []= "".$val;
              }
              
              $ret['requestedAttributes'] []= array(
                  'friendlyName' => "".$reqAttr->attributes()->FriendlyName,
                  'name'         => "".$reqAttr->attributes()->Name,
                  //Also empty string will be evaluated to false
                  'isRequired'   => strtolower("".$reqAttr->attributes()->isRequired) === 'true'? true : false,
                  'values'       => $values
              ); 
          }
          
      }
      
      
      //Include the embedded certificate in the returned data
      $ret['spCert'] = "".$samlReq->children(self::NS_XMLDSIG,false)->Signature->KeyInfo->X509Data->X509Certificate;
      
      return $ret;
  }
  
  
  
  /*******************  SAML RESPONSE GENERATION  *********************/
  
  
  //Returns an array with the assertions from the response in the shape of xml strings
  public function getRawAssertions (){
      self::debug(__CLASS__.".".__FUNCTION__."()");
      
      //If there are encrypted assertions, try to decrypt them beforehand
      if ($this->doDecipher === TRUE){
          self::debug("Decrypt assertions before returning them...");
          $samlResponse = $this->decryptAssertions($this->SAMLResponseToken);
      }else{
          $samlResponse = $this->parseXML($this->SAMLResponseToken);
      }
      
      $assertions = $samlResponse->children(self::NS_SAML2,false)->Assertion;
      
      if(!$assertions || count($assertions)<=0)
          $this->fail(__FUNCTION__, self::ERR_RESP_SUCC_NO_ASSERTIONS);
      
      $ret = array();
      foreach($assertions as $assertion){
          $ret []= $assertion->asXML();
      }
      return $ret;
  }
  
  public function getRawStatus (){
      
      $samlResponse = $this->parseXML($this->SAMLResponseToken);
      
      $status = $samlResponse->children(self::NS_SAML2,false)->Status;
      
      if(!$status || count($status)<=0)
          $this->fail(__FUNCTION__, self::ERR_SAMLRESP_NOSTATUS);
      
      return $status;
  }

  public static function generateID(){
      //randomly generated 128 bits request ID
      return "_".md5(uniqid(mt_rand(), true));
  }
  

  public static function generateTimestamp($time=NULL){
      
      //Not compatible with SimpleSamlPHP IdP. In fact, standard SAML
      //requires ZULU dates, not with a timezone
      //return date('c',time());
      
      if($time === NULL)
          $time = time();
      
      return gmdate('Y-m-d\TH:i:s\Z',$time);
  }

  public function setResponseParameters($consent,$destination,$inResponseTo,$issuer){

      if($consent == NULL || $consent == "")
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"Missing or empty consent on response building.");
      if($destination == NULL || $destination == "")
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"Missing or empty destination on response building.");
      if($inResponseTo == NULL || $inResponseTo == "")
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"Missing or empty inResponseTo on response building.");
      if($issuer == NULL || $issuer == "")
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"Missing or empty issuer on response building.");
      
      $this->consent              = $consent;
      $this->responseDestination  = $destination;
      $this->inResponseTo         = $inResponseTo;
      $this->responseIssuer       = $issuer;
  }


  public function generateStatus($status, $isRaw=false){
      
      //If raw, it is a string, return and we're done.
      if($isRaw){
          if(!is_string($status) || $status == "")
              $this->fail(__FUNCTION__, self::ERR_GENERIC,"Status should be a string.");
          else
              return $status;
      }
      
      $statusInfo = $status;
      
      $statusTagEnd = '/>';
      $statusCodeCloseTag = '';
      $secondaryStatus = '';
      if(isset($statusInfo ["SecondaryStatusCode"]) && $statusInfo ["SecondaryStatusCode"] != NULL){
          $statusTagEnd = '>';
          $statusCodeCloseTag = '</saml2p:StatusCode>';
          $secondaryStatus = '<saml2p:StatusCode Value="'.htmlspecialchars($statusInfo["SecondaryStatusCode"]).'" />';
      }
      
      $statusMessage = '';
      if(isset($statusInfo ["StatusMessage"]) && $statusInfo ["StatusMessage"] != NULL)
          $statusMessage = '<saml2p:StatusMessage>'.htmlspecialchars($statusInfo ["StatusMessage"]).'</saml2p:StatusMessage>';
      
      $statusNode =
          '<saml2p:Status>'
          .'<saml2p:StatusCode Value="'.htmlspecialchars($statusInfo ["MainStatusCode"]).'" '.$statusTagEnd
          .$secondaryStatus
          .$statusCodeCloseTag
          .$statusMessage
          .'</saml2p:Status>';
      
      return $statusNode;
  }

  

  public function generateAssertion($assertionData,$isRaw=false, $storkize=true){
      
      $assertion = NULL;
      $now = time();
      
      //If raw, it is a string, return as is or add the namespaces if needed.
      if($isRaw){
          if(!is_string($assertionData) || $assertionData == "")
              $this->fail(__FUNCTION__, self::ERR_GENERIC,"Assertion should be a string.");
          
          $assertion = $assertionData;
          if($storkize === true){
              //Wrap the object around a root with the used namespaces
              $xml = '<root '
                  .'xmlns:saml2p="'.self::NS_SAML2P.'" '
                  .'xmlns:ds="'.self::NS_XMLDSIG.'" '
                  .'xmlns:saml2="'.self::NS_SAML2.'" '
                  .'xmlns:stork="'.self::NS_STORK.'" '
                  .'xmlns:storkp="'.self::NS_STORKP.'" '
                  .'xmlns:xsi="'.self::NS_XSI.'" '
                  .'xmlns:eidas="'.self::NS_EIDASATT.'" '
                  .'xmlns:eidas-natural="'.self::NS_EIDASATT.'" '
                  .'xmlns:xs="'.self::NS_XMLSCH.'">'
                  .$assertionData
                  .'</root>';              
              $rootObj = $this->parseXML($xml);
              
              //Add AttributeStatus to each assertion attribute
              $assertionObj = $rootObj->children(self::NS_SAML2,false)->Assertion;
              foreach ($assertionObj->AttributeStatement->Attribute as $attribute){
                  $attribute->addAttribute('stork:AttributeStatus','Available',self::NS_STORK);
              }
              $assertion = $assertionObj->saveXML();
          }
          
      }

      else{
          //Default values for optional inputs
          $NameID              = '';
          $nameQualifier       = '';
          $clientAddress       = '';
          $inResponseTo        = '';
          $recipient           = '';
          $audienceRestriction = '';
          
          //Default values for other inputs
          $id           = self::generateID();
          $IssueInstant = self::generateTimestamp($now);
          $NotBefore    = $IssueInstant;
          $NotOnOrAfter = self::generateTimestamp($now+300);
          $AuthnInstant = $IssueInstant;
          
          $AuthnContextClassRef = self::LOA_LOW;
          $NameIDFormat = self::NAMEID_FORMAT_UNSPECIFIED;
          
          
          
          //Check mandatory inputs
          if(!isset($assertionData['Issuer']))
              $this->fail(__FUNCTION__, self::ERR_GENERIC,"Issuer not defined on assertion input.");
          $Issuer = $assertionData['Issuer'];
          
          
          
          //Override defaults with the received values if any
          if(isset($assertionData['ID']))
              $id = $assertionData['ID'];
          
          if(isset($assertionData['IssueInstant']))
              $IssueInstant = $assertionData['IssueInstant'];
          
          if(isset($assertionData['NotBefore']))
              $NotBefore = $assertionData['NotBefore'];
          
          if(isset($assertionData['NotOnOrAfter']))
              $NotOnOrAfter = $assertionData['NotOnOrAfter'];
          
          if(isset($assertionData['AuthnInstant']))
              $AuthnInstant = $assertionData['AuthnInstant'];
          
          if(isset($assertionData['AuthnContextClassRef']))
              $AuthnContextClassRef = $assertionData['AuthnContextClassRef'];
          
          if(isset($assertionData['NameIDFormat']))
              $NameIDFormat = $assertionData['NameIDFormat'];

          
          
          //Build the optional parts of the assertion, if inputs are available
          if(isset($assertionData['NameID']))
              $NameID = $assertionData['NameID'];
          if(isset($assertionData['NameQualifier']))
              $nameQualifier = 'NameQualifier="'.htmlspecialchars($assertionData['NameQualifier']).'" ';
          if(isset($assertionData['Address']))
              $clientAddress = 'Address="'.htmlspecialchars($assertionData['Address']).'" ';
          if(isset($assertionData['InResponseTo']))
              $inResponseTo  = 'InResponseTo="'.htmlspecialchars($assertionData['InResponseTo']).'" ';
          if(isset($assertionData['Recipient']))
              $recipient     = 'Recipient="'.htmlspecialchars($assertionData['Recipient']).'" ';
          
          if(isset($assertionData['Audience']))                                
              $audienceRestriction = '<saml2:AudienceRestriction>'
                  .'            <saml2:Audience>'.htmlspecialchars($assertionData['Audience']).'</saml2:Audience>' //EntityID of the AuthnReq issuer
                  .'        </saml2:AudienceRestriction>';
          

          $subject = '';
          if($NameID !== ''){
              $subject = '<saml2:Subject>'
                  .'        <saml2:NameID Format="'.htmlspecialchars($NameIDFormat).'" ' //persistent, transient, unspecified
                  .'               '.$nameQualifier.'>'.htmlspecialchars($NameID).'</saml2:NameID>' //namequalifier: the domain of the idp, nameid: the value of the personIdentifier attribute
                  .'        <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
                  .'           <saml2:SubjectConfirmationData '
                  .'               '.$clientAddress
                  .'               '.$inResponseTo        //tokenID of the AuthnReq that we are responding to       
                  .'               NotOnOrAfter="'.htmlspecialchars($NotOnOrAfter).'" '  //now+5min
                  .'               '.$recipient.'/>'      //EntityID of the AuthnReq issuer
                  .'        </saml2:SubjectConfirmation>'
                  .'    </saml2:Subject>';
          }



          
          
          //Now we build the attribute statement based on the received attribute list for this assertion
          $attribs = '';
          foreach($assertionData['attributes'] as $attr){
              
              $values = '';
              foreach($attr['values'] as $val){

                  // Legacy is: each value as a string. We only apply the new logic if the value is an array
                  // TODO: check thoroughly that works! first as legacy, then as new behaviour!!!
                  $valueType = "";
                  $latinScript = "";
                  if(is_array($val)){
                      if($val['type'] != "")
                          $valueType = ' xsi:type="'.htmlspecialchars($val['type']).'"'; //eidas-natural:PersonIdentifierType
                      if($val['LatinScript'] != "")
                          $latinScript = ' eidas-natural:LatinScript="'.htmlspecialchars($val['LatinScript']).'"';
                      $val = $val['value'];
                  }

                  $values .= '    <saml2:AttributeValue '
                      // TODO: for the moment we don't set the data
                      // type (as eIDAs implementations seem to ignore
                      // it and SAML2 deems it as optional). Pass it
                      // on $attr['valueType'] if any (if there is
                      // more than one value, SAML2 says all must have
                      // the same type, so do it on the attribute
                      // section, not per value).
                      .$valueType
                      .$latinScript
                      .'>'
                      .htmlspecialchars($val)
                      .'</saml2:AttributeValue>';
              }
              
              $attribs .= '<saml2:Attribute '
                  .'    FriendlyName="'.$attr['friendlyName'].'" '
                  .'    Name="'.$attr['name'].'" '
                  .'    NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">'
                  .'    '.$values
                  .'</saml2:Attribute>';
              
          }
          
          $attributeStatement = '';
          if($attribs !== '')
              $attributeStatement = '<saml2:AttributeStatement>'
                  .$attribs
                  .'</saml2:AttributeStatement>';
          
          
          
          
          //Finally, assemble the assertion
          $assertion = '<saml2:Assertion '
              .'ID="'.htmlspecialchars($id).'" ' //Random UUID for the assertion
              .'IssueInstant="'.htmlspecialchars($IssueInstant).'" ' //now
              .'Version="2.0">'
              .'    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">'.htmlspecialchars($Issuer).'</saml2:Issuer>' //Entity ID of IDP
              .'    '.$subject
              .'    <saml2:Conditions '
              .'        NotBefore="'.htmlspecialchars($NotBefore).'" '  //now
              .'        NotOnOrAfter="'.htmlspecialchars($NotOnOrAfter).'">' //now+5min
              .'        '.$audienceRestriction
              .'    </saml2:Conditions>'
              .'    <saml2:AuthnStatement AuthnInstant="'.htmlspecialchars($AuthnInstant).'">' //now
              .'        <saml2:AuthnContext>'
              .'            <saml2:AuthnContextClassRef>'.htmlspecialchars($AuthnContextClassRef).'</saml2:AuthnContextClassRef>' //LoA
              .'            <saml2:AuthnContextDecl/>'
              .'        </saml2:AuthnContext>'
              .'    </saml2:AuthnStatement>'
              .'    '.$attributeStatement
              .'</saml2:Assertion>';
          
      }

      return $assertion;
  }
  
  
  // Status: status of the response, either raw (XML
  // string) or to be built (array in the shape of what we return when
  // parsing a response)
  // 
  // Assertions: array of assertions for the response, either raw (XML
  // string) or to be built (array in the shape of what we return when
  // parsing a response)
  // 
  // rawStatus: true if status parameter
  // contains an xml string or false if it contains an array
  // 
  // rawAssertions: true if assertions array
  // contains xml strings or false if it contains arrays
  //
  // storkize: true if the assertion must be altered (thus breaking
  // the possibly existing signature) to include the stork extension
  // for available attributes
  public function generateStorkResponse($status, $assertions, $rawStatus=true, $rawAssertions=true, $storkize=true){  // TODO probar


      $consent      = $this->consent;
      $destination  = $this->responseDestination;
      $inResponseTo = $this->inResponseTo;
      
      $issuer  = $this->responseIssuer;
            
      
      //TODO For each assertion (if not repacked): Esperar array como el que genero yo en el parsing de la response. Así menos quebraderos. Si he de tocar algo, se toca sobre el array
      // issuer
      // subject: (pasar en un array tal cual lo genero al parsear)
      // Conditions:
      // authnStatemet:
      // attributes:


      //Build the response with the params
      $storkNamespaces = '';
      if($this->mode === 0 || $storkize === true){ //eIDAS  // TODO check
          $storkNamespaces =
               'xmlns:stork="'.self::NS_STORK.'" '
              .'xmlns:storkp="'.self::NS_STORKP.'" ';
          
      }
      $eIDASNamespaces = '';
      if($this->mode === 1){ //eIDAS  // TODO check
          $eIDASNamespaces =
                           'xmlns:eidas="'.self::NS_EIDASATT.'" '
                          .'xmlns:eidas-natural="'.self::NS_EIDASATT.'" ';
      }
      
      
      //Header of the SAML Response 
      $RootTagOpen = '<?xml version="1.0" encoding="UTF-8"?>'
          .'<saml2p:Response '
          .'xmlns:saml2p="'.self::NS_SAML2P.'" '
          .'xmlns:ds="'.self::NS_XMLDSIG.'" '
          .'xmlns:saml2="'.self::NS_SAML2.'" '
          .$storkNamespaces
          .'xmlns:xsi="'.self::NS_XSI.'" '
          .$eIDASNamespaces
          .'xmlns:xs="'.self::NS_XMLSCH.'" '
          .'Consent="'.htmlspecialchars($consent).'" '
          .'Destination="'.htmlspecialchars($destination).'" '
          .'ID="'.self::generateID().'" '
          .'InResponseTo="'.htmlspecialchars($inResponseTo).'" '
          .'IssueInstant="'.self::generateTimestamp().'" '
          .'Version="2.0">';
      

      //Issuer
      self::debug("Setting response issuer.");
      $Issuer='<saml2:Issuer '
          .'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">'
          .htmlspecialchars($issuer)
          .'</saml2:Issuer>';
      
      $assertionList = "";
      foreach($assertions as $assertion){
          $assertionList .= $this->generateAssertion($assertion,$rawAssertions,$storkize);  // TODO verify that storkize works
      }
      
      
      $samlResponse = $RootTagOpen
          .$Issuer
          .$this->generateStatus($status,$rawStatus)
          .$assertionList
          .'</saml2p:Response>';
      
      
      //If enabled, cipher the assertions with the recipient key
      if($this->doCipher === TRUE){
          self::info("Ciphering the response assertions...");
          $samlResponse = $this->encryptAssertions($samlResponse);
      }
      
      //Sign the response
      $samlResponse = $this->calculateXMLDsig($samlResponse);
      
      
      return $samlResponse;
  }

  // Gets the issuer entityId from a Saml token
  // $samlToken: string xml saml token string
  public function getIssuer($samlToken){
      
      if($samlToken == null || $samlToken == "")
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"Empty saml token.");
      
      //Checks if it is a valid XML string.
      $samlTok = $this->parseXML($samlToken);
      
      //We get the issuer
      return "".$samlTok->children(self::NS_SAML2,false)->Issuer;
  }

  // Gets the providerName from a Saml token
  // $samlToken: string xml saml token string
  public function getProviderName($samlToken){

      if($samlToken == null || $samlToken == "")
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"Empty saml token.");

      //Checks if it is a valid XML string.
      $samlTok = $this->parseXML($samlToken);

      //We get the providerName
      return "".$samlTok["ProviderName"];
  }

  public static function getFriendlyName($attributeName, $mode=0){

      if($mode === 0){ //Stork
          $prefixLen = strlen(self::$AttrNamePrefix);      
          if (substr($attributeName, 0, $prefixLen) == self::$AttrNamePrefix){
              return substr($attributeName, $prefixLen);
          }
          return $attributeName;
      }

// Deleted: eIDAS full names suffixes don't always match the friendly names
//      if($mode === 1){ //eIDAS
//          $attrname = preg_replace("|.+/(.+?)$|i", "\\1", $attributeName);
//          return $attrname;
//      }
      return NULL;
  }
  





  // *************** Stork Single Logout *******************  // TODO once eIDAS-clave3.0 is deployed, see if there's SSO and adapt
  
  // Stork single logout has some differences with the standard saml logout:

  //Only HTTP-POST binding, and always signed
  
  // As no NameID is used to keep session info, nameid type is
  // unspecified and content is the ProviderName of the logout
  // requesting SP (the value that is used on the authnReq to match
  // the cert on their trust store)

  // POST param is not the standard "SAMLRequest". Instead you MUST
  // use "samlRequestLogout"
  
  //In a similar fashion, the repsonse must not be expected at
  //"SAMLResponse" but at "samlResponseLogout"

  //The content of the issuer field must not be the EntityID of the
  //issuer. Instead, as STORK does not use Metadata transfer from SP
  //to IdP, here the SingleLogout endpoint URL of the SP must be
  //specified.

  // $spID: the stork id of the SP
  // $destination: endopint of the SLO service on the IdP
  // $returnTo: endpoint at the SP where the SLO response is expected.
  // $id: the id of the token (as it is usually used as a session token). If null will be auto-generated.
  public function generateSLORequest($spID,$destination,$returnTo,$id=NULL){
      self::debug(__CLASS__.".".__FUNCTION__."()");
      
      
      if($id != NULL){
          self::debug("ID provided. Overriding".$this->ID." with ".$id);
          $this->ID = $id;
      }      
      self::debug("ID being actually used: ".$this->ID);
      
      $issuer = '<saml:Issuer>'
          .htmlspecialchars($returnTo)
          .'</saml:Issuer>';
      
      $nameId = '<saml:NameID>'.htmlspecialchars($spID).'</saml:NameID>';
      if($this->mode === 1){
          $nameId = '<saml:NameID'
                  .' Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"'
                  .' SPNameQualifier="'.htmlspecialchars($returnTo).'"'
                  .'>'.htmlspecialchars($spID).'</saml:NameID>';
      }
      
      
      $sloReq = '<?xml version="1.0" encoding="UTF-8"?>'
          .'<samlp:LogoutRequest'
          .' xmlns:samlp="'.self::NS_SAML2P.'"'
          .' xmlns:saml="'.self::NS_SAML2.'"'
          .' ID="'.htmlspecialchars($this->ID).'"'
          .' Version="2.0"'
          .' IssueInstant="'.self::generateTimestamp().'"'
          .' Destination="'.htmlspecialchars($destination).'"'
          .'>'
          .$issuer
          .$nameId
          .'</samlp:LogoutRequest>';
      
      //Sign the request
      $sloReq = $this->calculateXMLDsig($sloReq);

      return $sloReq; 
  }

  public function validateSLOResponse($samlToken){     
      self::debug(__CLASS__.".".__FUNCTION__."()");
    
      self::trace("Received LogoutResponse token:\n".$samlToken);
    
      if($samlToken == null || $samlToken == "")
          $this->fail(__FUNCTION__, self::ERR_SAMLRESP_EMPTY);
      
      self::debug("Parsing SLOresponse.");
      //Checks if it is a valid XML string.
      $samlResponse = $this->parseXML($samlToken);
    
    
      //Validates the signature
      self::debug("Checking SLOresponse signature.");
      $this->validateXMLDSignature($samlToken);
    
      self::debug("Checking SLOresponse validity.");
      //Root node must be 'LogoutResponse'
      if(strtolower($samlResponse->getName()) != 'logoutresponse')
          $this->fail(__FUNCTION__, self::ERR_UNEXP_ROOT_NODE);
            
    $this->inResponseTo        = "".$samlResponse["InResponseTo"];
    $this->responseDestination = "".$samlResponse["Destination"];
    $this->responseIssuer      = "".$samlResponse->children(self::NS_SAML2,false)->Issuer;
    $this->responseNameId      = "".$samlResponse->children(self::NS_SAML2,false)->Assertion[0]->Subject->NameID;

    self::trace("inResponseTo:        ".$this->inResponseTo);
    self::trace("responseDestination: ".$this->responseDestination);
    self::trace("responseIssuer:      ".$this->responseIssuer);

    //Check existance of mandatory elements/attributes
    if(!$this->inResponseTo || $this->inResponseTo == ""){
      $this->fail(__FUNCTION__, self::ERR_RESP_NO_REQ_ID);
    }
    if(!$this->responseDestination || $this->responseDestination == ""){
      $this->fail(__FUNCTION__, self::ERR_RESP_NO_DESTINATION);
    }
    if(!$this->responseIssuer || $this->responseIssuer == ""){
      $this->fail(__FUNCTION__, self::ERR_RESP_NO_ISSUER);
    }
    
    self::debug("Comparing with context values if set.");
    // Compare with context values, if set
    if($this->requestId){
      self::debug("Comparing with requestID.");
      if(trim($this->requestId) != trim($this->inResponseTo))
        $this->fail(__FUNCTION__, self::ERR_UNEXP_REQ_ID,$this->requestId." != ".$this->inResponseTo);
    }
    if($this->assertionConsumerUrl){
      self::debug("Comparing with assertionConsumerURL.");
      if(trim($this->assertionConsumerUrl) != trim($this->responseDestination))
        $this->fail(__FUNCTION__, self::ERR_UNEXP_DEST,$this->assertionConsumerUrl." != ".$this->responseDestination);
    }
    if($this->expectedIssuers){
      foreach($this->expectedIssuers as $expectedIssuer){
        self::debug("Comparing with expected Issuer: $expectedIssuer");
        if(trim($expectedIssuer) == trim($this->responseIssuer))
          $found = true;
      }
      if(!$found)
        $this->fail(__FUNCTION__, self::ERR_UNEXP_ISSUER,"SLOresponse issuer: ".$this->responseIssuer);
    }
    
    self::debug("Parsing SLOresponse status.");
    //Get status info
    self::parseStatus($samlResponse);

    $this->SAMLResponseToken = $samlToken;
        
    // Return whether logout has been successful or not.
    return self::isSuccess($aux);
  }



  //Validates the received SamlLogoutReq towards the list of authorised issuers.
  public function validateLogoutRequest($logoutReqToken){
    
    self::debug(__CLASS__.".".__FUNCTION__."()");
    
    self::trace("Received SamlLogoutRequest token:\n".$logoutReqToken);
    
    if($logoutReqToken == null || $logoutReqToken == "")
      $this->fail(__FUNCTION__, self::ERR_SLOREQ_EMPTY);
    
    
    self::debug("Parsing SLO request.");
    //Checks if it is a valid XML string.
    $samlReq = $this->parseXML($logoutReqToken);

    self::debug("Checking SLO request validity.");
    //Root node must be 'LogoutRequest'
    if(strtolower($samlReq->getName()) != 'logoutrequest')
      $this->fail(__FUNCTION__, self::ERR_UNEXP_ROOT_NODE);

    
    //Validates the signature against all trusted (no issuer here)
    self::debug("Checking slorequest signature against: ".print_r($this->trustedIssuers,true));
    $verified = false;
    foreach($this->trustedIssuers as $trustedIssuer){
        foreach($trustedIssuer as $cert){
            self::debug("Trying with: ".$cert);
            if($cert == NULL || $cert == "")
                continue;
            self::debug("Chk1");
            if($this->verifySignature($logoutReqToken,$cert)){
                self::trace("Cert validation successful");
                $verified = true;
                break;
            }
        }
    }
    if(!$verified){
        $this->fail(__FUNCTION__, self::ERR_SIG_VERIF_FAIL);
    }
    
    $this->SLOReqToken = $logoutReqToken;
  }



  //Returns an array with the important parameters of the received SLO request
  public function getSloRequestData(){
      $ret = array();
      
      $samlReq = $this->parseXML($this->SLOReqToken);
      
      $ret['id']                       = "".$samlReq["ID"];
      $ret['destination']              = "".$samlReq["Destination"];
      $ret['issuer'] = "".$samlReq->children(self::NS_SAML2,false)->Issuer;
      $ret['nameId'] = "".$samlReq->children(self::NS_SAML2,false)->NameID;

      return $ret;
  }

  
  public function generateSLOResponse($inResponseTo,$issuer,$statusInfo,$destination){
      self::debug(__CLASS__.".".__FUNCTION__."()");
      
      $Issuer = '<saml2:Issuer '
          .'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">'
          .htmlspecialchars($issuer)
          .'</saml2:Issuer>';

      
      $Status = $this->generateStatus($statusInfo);
      
      $sloResp = '<?xml version="1.0" encoding="UTF-8"?>'
          .'<saml2p:LogoutResponse '
          .' xmlns:saml2p="'.self::NS_SAML2P.'"'
          .' xmlns:ds="'.self::NS_XMLDSIG.'"'
          .' xmlns:saml2="'.self::NS_SAML2.'"'
          .' xmlns:stork="'.self::NS_STORK.'"'
          .' xmlns:storkp="'.self::NS_STORKP.'"'
          .' Consent="'.self::CNS_UNS.'"'
          .' Destination="'.htmlspecialchars($destination).'"'
          .' ID="'.htmlspecialchars($this->ID).'"'
          .' InResponseTo="'.$inResponseTo.'"'
          .' IssueInstant="'.self::generateTimestamp().'"'
          .' Version="2.0"'
          .'>'
          .$Issuer
          .$Status
          .'</saml2p:LogoutResponse>';

      self::debug("unsigned SLO response: ".$sloResp);
      
      //Sign the response
      $sloResp = $this->calculateXMLDsig($sloResp);
      
      return $sloResp;
  }
  
  
  //Gets the nameID content from a SLO request.
  public function getSloNameId($samlToken){

      if($samlToken == null || $samlToken == "")
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"Empty saml token.");
      
      //Checks if it is a valid XML string.
      $samlTok = $this->parseXML($samlToken);
      
      //We get the issuer
      return "".$samlTok->children(self::NS_SAML2,false)->NameID;
  }
  
  
  
  
  
  // Set whether to, the key strength and certificate to cipher the
  // assertions on the response.
  public function setCipherParams($encryptCert,$doCipher=TRUE,$keyAlgorithm=self::AES256_CBC){
      
      self::debug(__CLASS__.".".__FUNCTION__."()");
      
      $this->encryptCert  = $this->checkCert($encryptCert);
      $this->doCipher     = $doCipher;
      $this->keyAlgorithm = $keyAlgorithm;
  }
  
  
  
  //Receives the plain unsigned response xml and the certificate of
  //the recipient SP
  private function encryptAssertions($samlToken){
      
      self::debug(__CLASS__.".".__FUNCTION__."()");
      
      if($samlToken == null || $samlToken == "")
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"Empty saml token.");
      
      if($this->encryptCert == null || $this->encryptCert == "")
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"Recipient certificate for ciphering not set or empty.");
      
      self::debug("Plain input token to cipher: ".$samlToken);
      self::debug("Recipient certificate to cipher: ".$this->encryptCert);
      
      //Parse the input saml token XML
      $doc = new DOMDocument();
      if (!$doc->loadXML($samlToken))
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"Bad XML in input saml token.");
      
      //Get the recipient public key from the certificate for encryption
      $key = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type'=>'public'));
      $key->loadKey($this->encryptCert);
      
      
      //Find any plain assertions in the Response and encrypt them
      $assertions = $doc->getElementsByTagName('Assertion');
      self::debug("Found assertions to cipher: ".$assertions->length);
      while ($assertions->length > 0){
          
          //Grab the first assertion
          $assertion = $assertions->item(0);
          
          //Create the encoding context
          $enc = new XMLSecEnc();
          $enc->setNode($assertion);
          $enc->type = XMLSecEnc::Element;
          
          //Generate AES symmetric key
          self::debug("Generating symmetric key (".$this->keyAlgorithm.")...");
          $symmetricKey = new XMLSecurityKey($this->keyAlgorithm);
          $symmetricKey->generateSessionKey();
          
          //Encrypt symmetric key with recipient public key
          self::debug("Encrypting symmetric key with public key...");
          $enc->encryptKey($key, $symmetricKey);
          
          //Encrypt the Assertion with the symmetric key (will generate an
          //independent document)
          self::debug("Encrypting assertion with symmetric key...");
          $encData = $enc->encryptNode($symmetricKey,FALSE);

          /* 
          echo "LLEGA";
          //We need to attach the certificate used to encrypt to the token
          //(due to the reference SP eIDAS implementation failing if the
          //certificate used to encrypt is not attached)
          $encryptedKeyKeyInfoNode  = $doc->createElement('ds:KeyInfo');
          $encryptedKeyX509DataNode = $doc->createElement('ds:X509Data');
          $encryptedKeyX509CertNode = $doc->createElement('ds:X509Certificate');
          $encryptedKeyX509CertNode->appendChild($doc->createTextNode($this->encryptCert));
          $encryptedKeyX509DataNode->appendChild($encryptedKeyX509CertNode);
          $encryptedKeyKeyInfoNode->appendChild($encryptedKeyX509DataNode);
          
          //Add the certificate used to encrypt the cipher key to the keyinfo node          // TODO eIDAS
          $encryptedKeyNode = $encData->getElementsByTagName('EncryptedKey');
          $cipherDataNode = $encData->getElementsByTagName('CipherData');
          
          $cipherDataNode->parentNode->insertBefore($encryptedKeyKeyInfoNode,$cipherDataNode);
          
          echo "PASA";


    #Decrypt the assertion
          $assertion = $this->decryptXMLNode($encData,$objKey);  // TODO parece que estoy desencriptando con la llave privada rsa
          if ($assertion === NULL)
              $this->fail(__FUNCTION__, self::ERR_GENERIC,"Decrypted content is null.");
          
          #To parse the resulting xml, we need to add all the possible namespaces
          $xml = '<root '
              .'xmlns:saml2p="'.self::NS_SAML2P.'" '
              .'xmlns:ds="'.self::NS_XMLDSIG.'" '
              .'xmlns:saml2="'.self::NS_SAML2.'" '
              .'xmlns:stork="'.self::NS_STORK.'" '
              .'xmlns:storkp="'.self::NS_STORKP.'" '
              .'xmlns:xsi="'.self::NS_XSI.'" >'
              .$assertion
              .'</root>';
    
          #Parse the decrypted assertion to check its integrity
          self::debug("Parsing decrypted assertion...");
          $newDoc = new DOMDocument();
          if (!$newDoc->loadXML($xml))
              $this->fail(__FUNCTION__, self::ERR_GENERIC,"Error parsing decrypted XML. Possibly Bad symmetric key.");
                    
          #Check if the decrypted content was empty
          $decryptedElement = $newDoc->firstChild->firstChild;
          if ($decryptedElement === NULL)
              $this->fail(__FUNCTION__, self::ERR_GENERIC,"Decrypted content is empty.");
          
          #Check if the decrypted content is a valid DOM Node
          if (!($decryptedElement instanceof \DOMElement))
              $this->fail(__FUNCTION__, self::ERR_GENERIC,"Decrypted element is not a DOMElement.");
          
          //Parse the decrypted node to be attached to the document
          self::debug("Replacing encrypted assertion with plain one...");
          $f = $doc->createDocumentFragment();
          $f->appendXML($xml);
          
          //Replace the encrypted assertion with the plain one (warning!
          //this will void the saml token signature)
          $encAssertion->parentNode->replaceChild($f->firstChild->firstChild, $encAssertion);

          */


          //Transfer the node tree to the document space of the original
          //document
          $encData2 = $doc->importNode($encData,TRUE);
          
          //Create the container for the encrypted data
          $encAssertion = $doc->createElement('saml2:EncryptedAssertion');    
          
          //Append the encrypted data to the container
          $encAssertion->appendChild($encData2);
          
          //Replace the plain assertion with the encrypted one
          self::debug("Replacing plain assertion with encrypted one...");
          $assertion->parentNode->replaceChild($encAssertion,$assertion);
          
          //Search for any remaining plain assertions
          $assertions = $doc->getElementsByTagName('Assertion');
      }
      
      self::debug("Response with encrypted assertions:".$doc->saveXML());
      
      //Return the xml response
      return $doc->saveXML();
  }
  
  
  
  //Receives a DomElement object and a xmlsec key and returns a
  //decrypted DomElement. Doesn't perform any checks on the decrypted
  //data. If symmetric key was badly decrypted, it will return trash.
  private function decryptXMLNode(DOMElement $encryptedData, XMLSecurityKey $decryptKey){
      
      self::debug(__CLASS__.".".__FUNCTION__."()");

      
      $enc = new XMLSecEnc();
      $enc->setNode($encryptedData);
      $enc->type = $encryptedData->getAttribute("Type");

      self::debug("*******************".print_r($encryptedData,true));
      
      self::debug("Locating encrypted symmetric key...");
      $symmetricKey = $enc->locateKey($encryptedData);
      if (!$symmetricKey)
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"Could not locate key algorithm in encrypted data.");

      self::debug("*******************".print_r($symmetricKey,true));

      //Find the ciphering algorithm info (returns a XMLSecurityKey instance with the symmetric key)
      self::debug("Locating ciphering algorithm...");
      $symmetricKeyInfo = $enc->locateKeyInfo($symmetricKey);
      if (!$symmetricKeyInfo)
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"Could not locate <dsig:KeyInfo> for the encrypted key.");
            
      self::debug("*******************".print_r($symmetricKeyInfo,true));
      
      //Key will always be encrypted with the recipient public key
      if (!$symmetricKeyInfo->isEncrypted)
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"Symmetric key not encrypted. Must be encrypted.");
      
      //Decrypt key will be RSA, so it doesn't matter the specific key
      //type. We always set it as a RSA_OAEP_MGF1P
      $decryptKeyAlgo = $decryptKey->getAlgorith();
      $symKeyInfoAlgo = $symmetricKeyInfo->getAlgorith();
      if ($symKeyInfoAlgo === XMLSecurityKey::RSA_OAEP_MGF1P
      &&  ($decryptKeyAlgo === XMLSecurityKey::RSA_1_5
      ||   $decryptKeyAlgo === XMLSecurityKey::RSA_SHA1
      ||   $decryptKeyAlgo === XMLSecurityKey::RSA_SHA512)) {
          // Any RSA private key can be used on RSA_OAEP_MGF1P
          $decryptKeyAlgo = XMLSecurityKey::RSA_OAEP_MGF1P;
      }
      self::debug("Decrypt key algorithm: $decryptKeyAlgo.");
      self::debug("Symmetric key algorithm: $symKeyInfoAlgo.");
      
      //Check that decrypt and encrypt key formats match
      if ($decryptKeyAlgo !== $symKeyInfoAlgo)
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"Key used to encrypt ($symKeyInfoAlgo) and to decrypt ($decryptKeyAlgo) don't match");
      
      
      $encKey = $symmetricKeyInfo->encryptedCtx;
      //Load the RSA key to the security object
      self::debug("Loading RSA key to the encrypted key context...");
      $symmetricKeyInfo->key = $decryptKey->key;
      
      $keySize = $symmetricKey->getSymmetricKeySize();
      self::debug("Symmetric key size: $keySize.");
      if ($keySize === null)
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"Can't guess key size to check proper decryption");
      
      
      try {
          self::debug("Decrypting symmetric key...");
          $key = $encKey->decryptKey($symmetricKeyInfo);
          if (strlen($key) != $keySize)
              $this->fail(__FUNCTION__, self::ERR_GENERIC,'Unexpected key size ('.(strlen($key)*8).'bits) for encryption algorithm: '.var_export($symmetricKey->type));
          
      } catch (Exception $e) {
          self::debug('Failed to decrypt symmetric key');
          
          //Key oracle attack protection: Generate a correctly padded key
          //It is a random one and will fail, but will fail securely
          //Make sure that the key has the correct length
          $encryptedKey = $encKey->getCipherValue();
          $pkey = openssl_pkey_get_details($symmetricKeyInfo->key);
          $pkey = sha1(serialize($pkey), true);
          $key = sha1($encryptedKey . $pkey, true);
          if (strlen($key) > $keySize) {
              $key = substr($key, 0, $keySize);
          } elseif (strlen($key) < $keySize) {
              $key = str_pad($key, $keySize);
          }
      }


      self::debug("Decrypted symmetric key (raw): ". bin2hex("$key"));
      
      //Get the decrypted key back to its place
      //$symmetricKey->loadkey($key);
      $symmetricKey->key = $key;
      
      self::debug("Decrypted symmetric key (obj): ".print_r($symmetricKey,true));
      self::debug("Decrypted symmetric key (raw from obj): ".bin2hex($symmetricKey->key));
      self::debug("Data to decrypt: ".base64_encode($enc->getCipherValue()));
      
      //Decrypt the assertion
      self::debug('Decrypting data with symmetric key (if succeeded in decrypting it. Rubbish otherwise)');
      $decrypted = $enc->decryptNode($symmetricKey, false);

      self::debug("Decrypted data: $decrypted");

      
      return $decrypted;
  }
  
  
  
  
  // Set whether to expect encrypted assertions and the private key to
  // use to decrypt (should be the key linked to the certificate
  // trusted by the IdP, the one used to sign the requests)
  public function setDecipherParams($decryptPrivateKey,$doDecipher=TRUE,$onlyEncrypted=FALSE){
      
      self::debug(__CLASS__.".".__FUNCTION__."()");
      
      $this->decryptPrivateKey  = $this->checkKey($decryptPrivateKey);
      $this->doDecipher         = $doDecipher;
      $this->onlyEncrypted      = $onlyEncrypted;
  }
  
  
  
  
  //Receives a saml response token and returns a simpleXML object of
  //the response but replacing any encryptedAssertion by its decrypted
  //counterpart.
  private function decryptAssertions($samlToken){
      
      self::debug(__CLASS__.".".__FUNCTION__."()");
      
      if($samlToken == null || $samlToken == "")
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"Empty saml token.");
      
      if($this->decryptPrivateKey == null || $this->decryptPrivateKey == "")
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"Private key for deciphering not set or empty.");
      
      self::debug("Input token to decipher: ".$samlToken);
      self::debug("Private key to decipher: ".$this->decryptPrivateKey);
      
      
      //Load the private key to decipher
      self::debug("Loading decryption key...");  // TODO get the key type from the  <ds:KeyInfo><xenc:EncryptedKey><xenc:EncryptionMethod> --->  as it is my key, I know I use this algorithm
      $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_OAEP_MGF1P, array('type'=>'private'));
      $objKey->loadKey($this->decryptPrivateKey, FALSE);
      
      
      #Parse the input saml token XML
      $doc = new DOMDocument();   
      if (!$doc->loadXML($samlToken))
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"Bad XML in input saml token.");
      
      
      //If strictly only encrypted assertions are accepted, search
      //and delete all plain assertions
      if ($this->onlyEncrypted === TRUE){
            
          self::debug("Searching for plain assertions to delete...");
          $assertions = $doc->getElementsByTagName('Assertion');
          self::debug("Found plain assertions: ".$assertions->length);
          while ($assertions->length > 0){
                
              //Grab the first assertion
              $assertion = $assertions->item(0);
                
              //Remove it
              self::debug("Removing plain assertion...");
              $assertion->parentNode->removeChild($assertion);
                
              //Search for any remaining plain assertions
              $assertions = $doc->getElementsByTagName('Assertion');
          }
      }
      
      
      //Find any encrypted assertions in the Response and decrypt them
      $assertions = $doc->getElementsByTagName('EncryptedAssertion');
      self::debug("Found assertions to decipher: ".$assertions->length);
      while ($assertions->length > 0){
          
          self::debug("Decrypting assertion...");
          $encAssertion = $assertions->item(0);
          
          #Search for the encrypted data node inside the encrypted assertion node
          $encData = $encAssertion->getElementsByTagName('EncryptedData');
          if(is_array($encData))
              $encData = $encData[0];
          if($encData instanceof DOMNodeList)
              $encData = $encData->item(0);
          if ($encData === NULL)
              $this->fail(__FUNCTION__, self::ERR_GENERIC,"No encrypted data node found.");
          
          #Decrypt the assertion
          $assertion = $this->decryptXMLNode($encData,$objKey);  // TODO parece que estoy desencriptando con la llave privada rsa
          if ($assertion === NULL)
              $this->fail(__FUNCTION__, self::ERR_GENERIC,"Decrypted content is null.");
          
          #To parse the resulting xml, we need to add all the possible namespaces
          $xml = '<root '
              .'xmlns:saml2p="'.self::NS_SAML2P.'" '
              .'xmlns:ds="'.self::NS_XMLDSIG.'" '
              .'xmlns:saml2="'.self::NS_SAML2.'" '
              .'xmlns:stork="'.self::NS_STORK.'" '
              .'xmlns:storkp="'.self::NS_STORKP.'" '
              .'xmlns:xsi="'.self::NS_XSI.'" >'
              .$assertion
              .'</root>';
    
          #Parse the decrypted assertion to check its integrity
          self::debug("Parsing decrypted assertion...");
          $newDoc = new DOMDocument();
          if (!$newDoc->loadXML($xml))
              $this->fail(__FUNCTION__, self::ERR_GENERIC,"Error parsing decrypted XML. Possibly Bad symmetric key.");
                    
          #Check if the decrypted content was empty
          $decryptedElement = $newDoc->firstChild->firstChild;
          if ($decryptedElement === NULL)
              $this->fail(__FUNCTION__, self::ERR_GENERIC,"Decrypted content is empty.");
          
          #Check if the decrypted content is a valid DOM Node
          if (!($decryptedElement instanceof \DOMElement))
              $this->fail(__FUNCTION__, self::ERR_GENERIC,"Decrypted element is not a DOMElement.");
          
          //Parse the decrypted node to be attached to the document
          self::debug("Replacing encrypted assertion with plain one...");
          $f = $doc->createDocumentFragment();
          $f->appendXML($xml);
          
          //Replace the encrypted assertion with the plain one (warning!
          //this will void the saml token signature)
          $encAssertion->parentNode->replaceChild($f->firstChild->firstChild, $encAssertion);
          //$doc->documentElement->appendChild($f->firstChild->firstChild);
          //$encAssertion->parentNode->removeChild($encAssertion);
          
          //Search for any remaining encrypted assertions
          $assertions = $doc->getElementsByTagName('EncryptedAssertion');
      }
      
      self::debug("Response with plain assertions:".$doc->saveXML());
      
      //Convert to simpleXML object
      return $this->parseXML($doc->saveXML());
  }
  
  
  
  
  //Switch to eIDAS mode
  public function setEidasMode() {
      $this->mode = 1;
  }
  
  
  //Set eIDAS specific parameters (LoA is inferred from the QAA, but
  //can set here too)
  public function setEidasRequestParams($spType = self::EIDAS_SPTYPE_PUBLIC,
                                        $nameIdFormat = self::NAMEID_FORMAT_PERSISTENT,
                                        $QAALevel = 1){
      
      if($spType !== self::EIDAS_SPTYPE_PUBLIC
      && $spType !== self::EIDAS_SPTYPE_PRIVATE){
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"eIDAS SPType not valid: $spType");
      }
      
      
      if($nameIdFormat !== self::NAMEID_FORMAT_PERSISTENT
      && $nameIdFormat !== self::NAMEID_FORMAT_TRANSIENT
      && $nameIdFormat !== self::NAMEID_FORMAT_UNSPECIFIED){
          $this->fail(__FUNCTION__, self::ERR_GENERIC,"eIDAS nameID format not valid: $nameIdFormat");
      }
      
      
      $this->spType       = $spType;
      $this->nameIdFormat = $nameIdFormat;
      $this->QAALevel     = $QAALevel;
  }



  // TODO
  //Will generate a metadata signed document that must be published at
  //the URL stated in <issuer> of the SP
  public function generateSPMetadata() {
      
      self::debug(__CLASS__.".".__FUNCTION__."()");

      self::info("Generating metadata for the AuthnRequest");
      $metadata = '<?xml version="1.0" encoding="UTF-8"?>'
          .'<md:EntityDescriptor'
          .'    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"'
          .'    entityID="'.htmlspecialchars($this->Issuer).'"'
          .'    validUntil="'.self::generateTimestamp(time()+(1*24*60*60)).'">'
          .'  <md:SPSSODescriptor'
          .'      AuthnRequestsSigned="true" '
          .'      WantAssertionsSigned="true" '
          .'      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
          .'    <md:KeyDescriptor use="signing">'
          .'      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
          .'        <ds:X509Data>'
          .'          <ds:X509Certificate>'.self::implodeCert($this->signCert).'</ds:X509Certificate>'
          .'        </ds:X509Data>'
          .'      </ds:KeyInfo>'
          .'    </md:KeyDescriptor>'
          .'    <md:KeyDescriptor use="encryption">'
          .'      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
          .'        <ds:X509Data>'
          .'          <ds:X509Certificate>'.self::implodeCert($this->signCert).'</ds:X509Certificate>'
          .'        </ds:X509Data>'
          .'      </ds:KeyInfo>'
          .'    </md:KeyDescriptor>'
          .'    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>'
          .'    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>'
          .'    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>'
          .'    <md:AssertionConsumerService'
          .'        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"'
          .'        Location="'.htmlspecialchars($this->ReturnAddr).'"'
          .'        index="0"'
          .'        isDefault="true"/>'
          .'  </md:SPSSODescriptor>'
          .'  <md:Organization>'
          .'    <md:OrganizationName xml:lang="en"/>'
          .'    <md:OrganizationDisplayName xml:lang="en"/>'
          .'    <md:OrganizationURL xml:lang="en"/>'
          .'  </md:Organization>'
          .'  <md:ContactPerson contactType="support"/>'
          .'  <md:ContactPerson contactType="technical"/>'
          .'</md:EntityDescriptor>';
      
      
      //Sign the metadata
      self::info("Signing metadata");
      $metadata = $this->calculateXMLDsig($metadata, true);
      
      return $metadata;
  }
  
  
  
  





  // TODO
  //Will generate a metadata signed document that must be published at
  //the URL stated in <issuer> of the IDP
  public function generateIdPMetadata($SSOServiceURL="") {
      
      self::debug(__CLASS__.".".__FUNCTION__."()");
      
      self::info("Generating metadata for the IdP");
      
      //List of supported attributes
      $supportedAttributes = '';
      foreach (self::$eIdasAttributes as $FriendlyName => $Name){
          $supportedAttributes .= '<saml2:Attribute'
              .' xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"'
              .' FriendlyName="'.$FriendlyName.'"'
              .' Name="'.$Name.'"'
              .' NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" />';
      }
      
      
      $metadata ='<?xml version="1.0" encoding="UTF-8"?>'          
          .'<md:EntityDescriptor'
          .'    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"'
          .'    entityID="'.htmlspecialchars($this->Issuer).'"'
          .'    validUntil="'.self::generateTimestamp(time()+(1*24*60*60)).'">'
          .'  <md:Extensions>'
          .'    <alg:DigestMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"'
          .'         Algorithm="http://www.w3.org/2001/04/xmldsig-more#sha384" />'
          .'    <alg:DigestMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"'
          .'         Algorithm="http://www.w3.org/2001/04/xmlenc#sha512" />'
          .'    <alg:DigestMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"'
          .'         Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />'
          .'    <alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"'
          .'         Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" />'
          .'    <alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"'
          .'         Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />'
          .'    <alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"'
          .'         Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" />'
          .'    <alg:SigningMethod xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"'
          .'         Algorithm="http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1" />'
          .'  </md:Extensions>'
          .'  <md:IDPSSODescriptor'
          .'      WantAuthnRequestsSigned="true"'
          .'      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
          .'    <md:KeyDescriptor use="signing">'
          .'      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
          .'        <ds:X509Data>'
          .'          <ds:X509Certificate>'.self::implodeCert($this->signCert).'</ds:X509Certificate>'
          .'        </ds:X509Data>'
          .'      </ds:KeyInfo>'
          .'    </md:KeyDescriptor>'
          .'    <md:KeyDescriptor use="encryption">'
          .'      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
          .'        <ds:X509Data>'
          .'          <ds:X509Certificate>'.self::implodeCert($this->signCert).'</ds:X509Certificate>'
          .'        </ds:X509Data>'
          .'      </ds:KeyInfo>'
          .'      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes192-cbc" />'
          .'      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc" />'
          .'      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc" />'
          .'    </md:KeyDescriptor>'
          .'    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>'
          .'    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>'
          .'    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>'
          .'    <md:SingleSignOnService'
          .'        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"'
          .'        Location="'.$SSOServiceURL.'" />'
          .'    <md:SingleSignOnService'
          .'        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"'
          .'        Location="'.$SSOServiceURL.'" />'
          .$supportedAttributes
          .'  </md:IDPSSODescriptor>'
          .'  <md:Organization>'
          .'    <md:OrganizationName xml:lang="en"/>'
          .'    <md:OrganizationDisplayName xml:lang="en"/>'
          .'    <md:OrganizationURL xml:lang="en"/>'
          .'  </md:Organization>'
          .'  <md:ContactPerson contactType="support"/>'
          .'  <md:ContactPerson contactType="technical"/>'
          .'</md:EntityDescriptor>';
      
      
      //Sign the metadata (before extensions, but in this case, equals 'at the top')
      self::info("Signing IdP metadata");
      $metadata = $this->calculateXMLDsig($metadata, true);
      
      return $metadata;
  }

  
  
  
  
  
  
} // Class


































// Wrapper class to simplify integration of clave1.0 (Stork) authentication

class claveAuth {

    private $conf;

    private $claveSP;

    private $attributes;

       const LOG_TRACE    = 0;
  const LOG_DEBUG    = 1;
  const LOG_INFO     = 2;
  const LOG_WARN     = 3;
  const LOG_ERROR    = 4;
  const LOG_CRITICAL = 5;

  private static $logLevels = array(
        self::LOG_TRACE    => 'TRACE',
        self::LOG_DEBUG    => 'DEBUG',
        self::LOG_INFO     => 'INFO',
        self::LOG_WARN     => 'WARN',
        self::LOG_ERROR    => 'ERROR',
        self::LOG_CRITICAL => 'CRITICAL'
                                    );
  
  
  private static $logLevel    = self::LOG_TRACE;
  private static $logFile     = '/tmp/storkLog2';
  private static $logToFile   = true;
  private static $logToStdout = false;
  
  
  private static function log($content,$level){
    
    if($level < self::$logLevel)
      return;
    
    $prefix = "[".date('c',time())."][".self::$logLevels[$level]."]: ";
    
    if(is_object($content) || is_array($content))
      $message=print_r($content,TRUE);
    else
      $message=$content;
    
    if(self::$logToStdout)
      echo $prefix.$message."\n";
    
    if(self::$logToFile)
      file_put_contents(self::$logFile, $prefix.$message."\n",FILE_APPEND); 
  }
  
  private static function trace($message){
    self::log($message,self::LOG_TRACE);
  }
  private static function debug($message){
    self::log($message,self::LOG_DEBUG);
  }
  private static function info($message){
    self::log($message,self::LOG_INFO);
  }
  private static function warn($message){
    self::log($message,self::LOG_WARN);
  }
  private static function error($message){
    self::log($message,self::LOG_ERROR);
  }
  private static function critical($message){
    self::log($message,self::LOG_CRITICAL);
  }
    
    public function __construct ($configFile){
        
        $this->conf = self::getConfigFromFile($configFile);
        
        
        $this->claveSP  = new SPlib();
        
        $this->claveSP->forceAuthn();
        
        $this->claveSP->setSignatureKeyParams($this->conf['signCert'],
                                              $this->conf['signKey'],
                                              SPlib::RSA_SHA256);
        
        $this->claveSP->setSignatureParams(SPlib::SHA256,
                                           SPlib::EXC_C14N);

        //La URL de retorno es la misma que la actual, así que la calculamos
        $this->claveSP->setServiceProviderParams($this->conf['SPname'],
                                                 $this->conf['Issuer'],
                                                 self::full_url($_SERVER));
        
        $this->claveSP->setSPLocationParams($this->conf['SPCountry'],
                                            $this->conf['SPsector'],
                                            $this->conf['SPinstitution'],
                                            $this->conf['SPapp']);  

        $this->claveSP->setSPVidpParams($this->conf['SpId'],
                                        $this->conf['CitizenCountry']);

        $this->claveSP->setSTORKParams ($this->conf['endpoint'],
                                        $this->conf['QAA'],
                                        $this->conf['sectorShare'],
                                        $this->conf['crossSectorShare'],
                                        $this->conf['crossBorderShare']);
        
        foreach($this->conf['attributesToRequest'] as $attr)
            $this->claveSP->addRequestAttribute ($attr, false); 


        $this->attributes = array();
    }        
  

    //Returns true if authn succeeded, false if failed, redirects if new authn 
    public function authenticate (){
        
        self::debug("**Entra en authenticate");
        
        //If no response token on the request, then we must launch an authn process
        if(!array_key_exists('SAMLResponse', $_REQUEST)){
            self::debug("**do_auth");
            $this->do_Authenticate();
        }
        self::debug("**coming back");
        return $this->handleResponse($_REQUEST['SAMLResponse']);
    }
    

    //Transformamos los attrs para compatibilizarlos con el PoA
    public function getAttributes(){


        self::debug("**attrs::".print_r($this->attributes,true));

        
        $ret = array();
        foreach($this->attributes as $name => $values){
            $ret[$name] = $values[0];
        }

        self::debug("**attrs2::".print_r($ret,true));
        
        //Aislar DNI
        $ret['eIdentifier'] = explode('/',$this->attributes['eIdentifier'][0])[2];


        self::debug("**attrs3::".print_r($ret,true));
                
        return $ret;

        //return $this->attributes;
    }
    
    
    //Returns true if logout succeeded, false if failed, redirects if new logout 
    public function logout(){
        
        //If no response token on the request, then we must launch an authn process
        if(!array_key_exists('samlResponseLogout', $_REQUEST))
            $this->do_Logout();
        
        return $this->handleLogoutResponse($_REQUEST['samlResponseLogout']);
    }



    
    private function do_Logout(){
        $id = SPlib::generateID();
        
        $req = $this->claveSP->generateSLORequest($this->conf['Issuer'],
                                                  $this->conf['sloEndpoint'],
                                                  self::full_url($_SERVER),$id);
        $req = base64_encode($req);
        
        //Save data in session for the comeback
        session_start();
        $_SESSION['storkdemoSPphp']['slorequestId']  = $id;
        $_SESSION['storkdemoSPphp']['sloreturnPage'] = self::full_url($_SERVER);
        
        $this->redirectLogout($req, $this->conf['sloEndpoint']);
    }


    
    
    private function handleLogoutResponse($response){
                
        $resp = base64_decode($response);
        
        $claveSP = new SPlib();
        
        $claveSP->addTrustedCert($this->conf['validateCert']);
        
        session_start();
        
        $claveSP->setValidationContext($_SESSION['storkdemoSPphp']['slorequestId'],
                                       $_SESSION['storkdemoSPphp']['sloreturnPage']);
        
        if($claveSP->validateSLOResponse($resp))
            return true;
        
        return false;
    }



    
    private function handleResponse ($response){
        
        $resp = base64_decode($response);
        
        $claveSP = new SPlib();
        
        
        $claveSP->addTrustedCert($this->conf['validateCert']);
        
        session_start();
              
        $claveSP->setValidationContext($_SESSION['claveLib']['requestId'],
                                       $_SESSION['claveLib']['returnPage']);
        
        $claveSP->setDecipherParams($this->conf['signKey'],TRUE,FALSE);
        
        $claveSP->validateStorkResponse($resp);
        
        $errInfo = "";
        if(!$claveSP->isSuccess($errInfo))
            return false;
        
        $this->attributes = $claveSP->getAttributes();
        return true;
    }
    
    private function do_Authenticate(){
        $req = base64_encode($this->claveSP->generateStorkAuthRequest());
        
        //For response verification, store in session or in config the following:
        session_start();
        $_SESSION['claveLib']['requestId']  = $this->claveSP->getRequestId();
        $_SESSION['claveLib']['returnPage'] = self::full_url($_SERVER);
        

        $forcedIdP = '';
        $idpList = '';
        $excludedIdPList = '';
        $allowLegalPerson = '';
        
        if($this->conf['forcedIdP'] != NULL)
            $forcedIdP = '<input type="hidden" name="forcedIdP" value="'.$this->conf['forcedIdP'].'" />';
        if($this->conf['idpList'] != NULL)
            $idpList = '<input type="hidden" name="idpList" value="'.$this->conf['idpList'].'" />';
        if($this->conf['excludedIdPList'] != NULL)
            $excludedIdPList = '<input type="hidden" name="excludedIdPList" value="'.$this->conf['excludedIdPList'].'" />';
        if($this->conf['allowLegalPerson'] != NULL)
            $allowLegalPerson = '<input type="hidden" name="allowLegalPerson" value="'.$this->conf['allowLegalPerson'].'" />';
        
        $this->redirectLogin($req,$this->conf['endpoint'],
                        $forcedIdP,$idpList,$excludedIdPList,$allowLegalPerson);
    }


    private function redirectLogin($req,$endpoint,
                                   $forcedIdP="",$idpList="",
                                   $excludedIdPList="",$allowLegalPerson=""){
        self::redirect('SAMLRequest',$req,$endpoint,
                                   $forcedIdP,$idpList,
                                   $excludedIdPList,$allowLegalPerson);
    }

    private function redirectLogout($req,$endpoint,
                                    $forcedIdP="",$idpList="",
                                    $excludedIdPList="",$allowLegalPerson=""){
        self::redirect('samlRequestLogout',$req,$endpoint,
                                   $forcedIdP,$idpList,
                                   $excludedIdPList,$allowLegalPerson);
    }
    
    private static function redirect($postParam, $req,$endpoint,
                              $forcedIdP="",$idpList="",
                              $excludedIdPList="",$allowLegalPerson=""){
        
        echo "
<html lang=\"en\">
  <body onload=\"document.forms[0].submit();\">
	   <form name=\"redirectForm\" method=\"post\" action=\"".$endpoint."\">
		    <input type=\"hidden\" name=\"".$postParam."\" value=\"".$req."\" />
            $forcedIdP
            $idpList
            $excludedIdPList
            $allowLegalPerson
	   </form>
	 </body>
</html>
";
        exit(0);
    }


    
    private static function getConfigFromFile($file){
        
        try{
            //Don't use _once or the global variable might get unset.
            require($file);
        }catch(Exception $e){
            throw new Exception("Clave config file ".$file." not found.");
        }
        
        if(!isset($clave_config))
            throw new Exception('$clave_config global variable not found in '.$file);

        if(!is_array($clave_config))
            throw new Exception('$clave_config global variable not an array in '.$file);
        
        return $clave_config;
    }


    private static function url_origin( $s, $use_forwarded_host = false )
    {
        $ssl      = ( ! empty( $s['HTTPS'] ) && $s['HTTPS'] == 'on' );
        $sp       = strtolower( $s['SERVER_PROTOCOL'] );
        $protocol = substr( $sp, 0, strpos( $sp, '/' ) ) . ( ( $ssl ) ? 's' : '' );
        $port     = $s['SERVER_PORT'];
        $port     = ( ( ! $ssl && $port=='80' ) || ( $ssl && $port=='443' ) ) ? '' : ':'.$port;
        $host     = ( $use_forwarded_host && isset( $s['HTTP_X_FORWARDED_HOST'] ) ) ? $s['HTTP_X_FORWARDED_HOST'] : ( isset( $s['HTTP_HOST'] ) ? $s['HTTP_HOST'] : null );
        $host     = isset( $host ) ? $host : $s['SERVER_NAME'] . $port;
        return $protocol . '://' . $host;
    }
    
    private static function full_url( $s, $use_forwarded_host = false )
    {
        return self::url_origin( $s, $use_forwarded_host ) . $s['REQUEST_URI'];
    }
    
    
}




//Extract signature hash
//cat saml.pem | openssl rsautl -certin -verify -raw -hexdump -in sig3 -asn1parse


//Equivalent, but the second failsm if the prefx is different
//$samlResponse->children(self::NS_SAML2,false)->Assert
//$samlResponse->children('saml2',TRUE)->Assert
//$nsPrefixes = $samlResponse->getNamespaces();
