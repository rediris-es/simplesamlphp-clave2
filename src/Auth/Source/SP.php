<?php

namespace SimpleSAML\Module\clave\Auth\Source;


use Exception;
use SimpleSAML\Assert;
use SimpleSAML\Auth\Source;
use SimpleSAML\Auth\State;
use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Configuration;
use SimpleSAML\Module;
use SimpleSAML\Stats;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\Module\clave\SPlib;
use SimpleSAML\Module\clave\Tools;


/**
 * @method static handleUnsolicitedAuth($sourceId, $state, $redirectTo)
 */
class SP extends Source {
  
  
    private static array $mandatoryConfigParams = array('providerName','entityID','QAA',
    'certificate','privatekey','idpEntityID','SingleSignOnService','certData',
    'hostedSP','dialect','subdialect');
    
	/**
	 * The entity ID of this SP.
	 *
	 * @var string
	 */
	private string $entityId;
    
    
	/**
	 * The metadata of this SP (the authSource cofngi file entry content).
	 *
	 * @var Configuration.
	 */
	private Configuration $metadata;
    
    
    /**
	 * The entityID of the remote IdP we will be contacting.
	 *
	 * @var string  The IdP the user will log into.
	 */
	private string $idp;
    
    
	/**
	 * URL to discovery service.
	 *
	 * @var string|NULL
	 */
	private ?string $discoURL;
    
    
	/**
	 * The metadata of the hosted SP configured in the authSource.
	 *
	 * @var Configuration.
	 */
    private Configuration $spMetadata;
    
    
   	/**
	 * The metadata of the remote IdP.
	 *
	 * @var Configuration.
	 */ 
    private Configuration $idpMetadata;
    
    
	/**
	 * The Dialect this SP will use to contact the remote IdP
	 *
	 * @var string Dialect identifier.
	 */
    private string $dialect;
    
    
	/**
	 * The Sub-Dialect this SP will use to contact the remote IdP
	 *
	 * @var string Sub-Dialect identifier.
	 */
    private string $subdialect;
    
    
	/**
	 * The Certificate that will be used to sign the AuthnReq.
	 *
	 * @var string PEM encoded without headers.
	 */
    private string $certData;


	/**
	 * The Private Key that will be used to sign the AuthnReq.
	 *
	 * @var string PEM encoded without headers.
	 */
    private string $keyData;


    /**
     * Constructor for SAML2-eIDAS SP authentication source.
     *
     * @param array $info Information about this authentication source (contains AuthId, the id of this auth source).
     * @param array $config Configuration block of this authsource in authsources.php.
     * @throws Error\Exception
     * @throws Exception
     */
    public function __construct(array $info, array $config) {
        assert('is_array($info)');
        assert('is_array($config)');
        
        // Call the parent constructor first, as required by the interface.
        parent::__construct($info, $config);
        
        
        Logger::debug('Called SimpleSAML\Module\clave\Auth\Source\SP constructor');
        //Logger::debug('info: '.print_r($info, true));
        Logger::debug('config: '.print_r($config, true));
        
        
        
        //Load the metadata of the authsource (from the authsources file)
        $this->metadata = Configuration::loadFromArray($config,
        'authsources['.var_export($this->authId,true).']');
        
        
        //Get the hosted sp metadata
        $spConfId = Tools::getString($this->metadata,'hostedSP', NULL);
        if($spConfId == NULL)
            throw new Error\Exception("hostedSP field not defined for eIDAS auth source.");
        $this->spMetadata = Tools::getMetadataSet($spConfId,"clave-sp-hosted");
        Logger::debug('eIDAS SP hosted metadata: '.print_r($this->spMetadata,true));
        
        
        //Get the remote idp metadata
        $idpEntityId = Tools::getString($this->spMetadata,'idpEntityID', NULL);
        if($idpEntityId == NULL)
            throw new Error\Exception("idpEntityID field not defined for eIDAS auth source.");
        $this->idpMetadata = Tools::getMetadataSet($idpEntityId,"clave-idp-remote");
        Logger::debug('eIDAS IDP remote metadata ('.$idpEntityId.'): '.print_r($this->idpMetadata,true));



        //Check if all mandatory config is available (in any of the sets) // TODO review this, as there might be collisions, and review the list of mandatory
        foreach (self::$mandatoryConfigParams as $mandParam) {
            try {
                $this->metadata->getValue($mandParam);
            } catch (Assert\AssertionFailedException $e) {
                try {
                    $this->spMetadata->getValue($mandParam);
                } catch (Assert\AssertionFailedException $e) {
                    try {
                        $this->idpMetadata->getValue($mandParam);
                    } catch (Assert\AssertionFailedException $e) {
                        throw new Error\Exception("$mandParam field not defined for eIDAS auth source.");
                    }
                }
            }
        }
        
        
        //Set the class properties
        $this->discoURL = Tools::getString($this->metadata,'discoURL', 'clave/sp/countryselector.php');  // TODO: default value. can be moved elsewhere? can module name be parametrised? anyway, remember to change module name

        $this->entityId   = $this->spMetadata->getString('entityID');
        $this->idp        = $idpEntityId;
        $this->dialect    = $this->spMetadata->getString('dialect');
        $this->subdialect = $this->spMetadata->getString('subdialect');

        $this->certData = Tools::readCertKeyFile(Tools::getString($this->spMetadata, 'certificate', NULL));
        $this->keyData  = Tools::readCertKeyFile(Tools::getString($this->spMetadata, 'privatekey', NULL));

        // TODO: to delete as ssphp impl has changed. seek if this data needs to be passed elsewhere
        //      $this->idp = array('endpoint' => $this->idpMetadata->getString('SingleSignOnService', NULL),
        //                   'cert'     => $this->idpMetadata->getString('certData', NULL));
    }


    /**
     * Retrieve the URL to the metadata of this SP (eIDAS).
     *
     * @return string  The metadata URL.
     * @throws Assert\AssertionFailedException|Exception
     */
	public function getMetadataURL(): string {
        
        $spConfId = Tools::getString($this->metadata,'hostedSP', NULL);
        return Module::getModuleURL('clave/sp/metadata.php/'.'clave/'.urlencode($spConfId).'/'.urlencode($this->authId));
	}
    
    
    
	/**
	 * Retrieve the entity id of this SP.
	 *
	 * @return string  The entity id of this SP.
	 */
	public function getEntityId(): string {

        return $this->entityId;
	}
       
    
    
	/**
	 * Retrieve the metadata of this SP (the authSource content).
	 *
	 * @return Configuration  The metadata of this SP.
	 */
	public function getMetadata(): Configuration {
        
        return $this->metadata;
	}
    
    

	/**
	 * Retrieve the metadata of an IdP.
	 *
	 * @param string $entityId  The entity id of the IdP.
	 * @return Configuration  The metadata of the IdP.
	 */
	public function getIdPMetadata(string $entityId=""): Configuration {
		assert('is_string($entityId)');
        
        //Here we have just a fixed IdP, eIDAS does not support the list of allowed IDPs        
        return $this->idpMetadata;
    }


    /**
     * Start a discovery service operation, (country selector in eIDAS).
     *
     * @param array $state The state array.
     * @return bool
     * @throws Exception
     */
	private function startDisco(array $state): bool {

        Logger::debug('Called SimpleSAML\Module\clave\Auth\Source\SP startDisco');
        
        //Whether to show the country selector
        $showCountrySelector = Tools::getBoolean($this->spMetadata, 'showCountrySelector', false);
        
        //Go on with the authentication
        if($showCountrySelector === false){
            return true;
        }
        
        //If we have to show selector but country code already set on the request, go on too
        foreach($state['sp:postParams'] as $postParam => $value)
            if($postParam === 'country' && $value !== NULL
            && is_string($value) && $value !== ""){
                return true;
            }
        
        
        //Show country selector
		$id = State::saveState($state, 'clave:sp:sso');
        
		//$config = Configuration::getInstance();

        //Use country selector url defined in config (internal or absolute)
        $discoURL = $this->discoURL;        
        if (!preg_match('/^\s*https?:/',$this->discoURL)) {
            //It is relative to the module
            $discoURL = Module::getModuleURL($this->discoURL);
        }
        
        $returnTo = Module::getModuleURL('clave/sp/discoresp.php', array('AuthID' => $id)); // TODO: remove clave reference. make the module name a global or something
        
		$params = array( // TODO ver si son necesarios y describirlos
			//'entityID' => $this->entityId,     //The clave hosted SP entityID
			'return' => $returnTo,             //The script to go on with the auth process (contains the authsource ID)
			//'returnIDParam' => 'country'       //The param name where the country ID will be searched
		);

        $httpUtils = new HTTP();
        $httpUtils->redirectTrustedURL($discoURL, $params);
        return false;
	}


    /**
     * Start login.
     *
     * This function saves the information about the login, and redirects to the IdP.
     *
     * @param array &$state Information about the current authentication.
     * @throws Exception
     */
    public function authenticate(array &$state): void {
        assert('is_array($state)');

        Logger::debug('------------------STATE at SP.authenticate (start): '.print_r($state,true));
        
        Logger::debug('Called SimpleSAML\Module\clave\Auth\Source\SP authenticate');
                
        // We are going to need the authId in order to retrieve this authentication source later.
        $state['clave:sp:AuthId']      = $this->authId;
        
        
        
        //Remote IdP might be fixed by the hosted IdP calling (overrides the value on the authsource metadata)
        //This variable is the same for the SAML2 authsource
		if (isset($state['saml:idp'])
        && $state['saml:idp'] != ""){
            $idpEntityId = $state['saml:idp'];
            
            Logger::debug('eIDAS IDP remote fixed by hosted IDP: ('.$idpEntityId.')');
            $this->idp = $idpEntityId;
            
            $this->idpMetadata = Tools::getMetadataSet($idpEntityId,"clave-idp-remote");
            Logger::debug('eIDAS IDP remote metadata ('.$idpEntityId.'): '.print_r($this->idpMetadata,true));
        }
        
        
        
        //We will also need the clave idp remote to go on with the sso after the country selector discovery
        $state['clave:sp:idpEntityID'] = $this->idp;
        
        
        Logger::info("state: ".print_r($state,true));
        Logger::info("metadata: ".print_r($this->metadata,true));

        
        //Redirect to the Country Selector (if enabled and needed)
        $this->startDisco($state);

        Logger::debug('------------------STATE at SP.authenticate (end): '.print_r($state,true));
        
        //Go on with the authentication
        $this->startSSO( $this->idp, $state);
        assert('FALSE');   
	}


    /**
     * Send an SSO request to an IdP.
     *
     * @param string $idp The entity ID of the IdP.
     * @param array $state The state array for the current authentication.
     * @throws Exception
     */
	public function startSSO(string $idp, array $state) {
        assert('is_string($idp)');


        Logger::debug('------------------STATE at SP.authenticate (end): '.print_r($state,true));
        
        Logger::debug('Called SimpleSAML\Module\clave\Auth\Source\SP startSSO');
        
        Logger::debug("Hosted SP Certificate: ".$this->certData);
        
        //We get the Remote SP Metadata
        $remoteSpMeta  = Configuration::loadFromArray($state['SPMetadata']);


        $showCountrySelector = Tools::getBoolean($this->spMetadata, 'showCountrySelector', false);

        $endpoint = Tools::getString($this->idpMetadata,'SingleSignOnService', NULL);


        $sectorShare      = "";
        $crossSectorShare = "";
        $crossBorderShare = "";
        $LoA = 1;
        $reqIssuer = NULL;
        $SPCountry = NULL;
        $SPsector = NULL;
        $SPinstitution = NULL;
        $SPapp = NULL;
        $SpId = NULL;
        $CitizenCountry = NULL;
        $QAA = NULL;
        if ($this->dialect === 'stork'){
            
            //These params are set, in order of preference:
            // 1. From the remote SP metadata (if set)
            // 2. From the hosted SP metadata (if set)
            // 3. From the request (if it specified any values, else, empty string)
            $SPCountry = Tools::getString($remoteSpMeta, 'spCountry',Tools::getString($this->spMetadata,'spCountry', ''.$state['eidas:requestData']['spCountry']));
            $SPsector  = Tools::getString($remoteSpMeta, 'spSector',Tools::getString($this->spMetadata,'spSector', ''.$state['eidas:requestData']['spSector']));
            $SPinstitution = Tools::getString($remoteSpMeta, 'spInstitution',Tools::getString($this->spMetadata,'spInstitution', ''.$state['eidas:requestData']['spInstitution']));
            $SPapp = Tools::getString($remoteSpMeta, 'spApplication',Tools::getString($this->spMetadata,'spApplication', ''.$state['eidas:requestData']['spApplication']));
            //$SpId="$SPCountry-$SPsector-$SPinstitution-$SPapp";
            $SpId = Tools::getString($remoteSpMeta, 'spID',Tools::getString($this->spMetadata,'spID', ''.$state['eidas:requestData']['spID']));
            $sectorShare      = Tools::getBoolean($remoteSpMeta, 'eIDSectorShare', Tools::getBoolean($this->spMetadata, 'eIDSectorShare',
                                                 SPlib::stb($state['eidas:requestData']['eIDSectorShare'])));
            $crossSectorShare = Tools::getBoolean($remoteSpMeta, 'eIDCrossSectorShare', Tools::getBoolean($this->spMetadata,'eIDCrossSectorShare',
                                                 SPlib::stb($state['eidas:requestData']['eIDCrossSectorShare'])));
            $crossBorderShare = Tools::getBoolean($remoteSpMeta, 'eIDCrossBorderShare', Tools::getBoolean($this->spMetadata,'eIDCrossBorderShare',
                                                 SPlib::stb($state['eidas:requestData']['eIDCrossBorderShare'])));
                        
            $CitizenCountry = "";
            //For Spain's Clave based on stork, country is fixed
            if ($this->subdialect === 'clave-1.0'){
                $CitizenCountry = Tools::getString($remoteSpMeta, 'citizenCountryCode',Tools::getString($this->spMetadata,'citizenCountryCode', ''.$state['eidas:requestData']['citizenCountryCode']));
            }
            if ($this->subdialect === 'stork')
                if($showCountrySelector === true)
                    $CitizenCountry = $state['country'];
            
            
            //Issuer is set in this order:
            // 0. If the UseMetadataUrl is set, use hosted SP metadata URL
            // 1. Hosted SP metadata issuer field (if set)
            // 2. Remote SP metadata issuer field (if set)
            // 3. Issuer Field specified on the remote SP request
            // (Dropped using the entityId of the hosted SP)
            $useMetadataUrl = Tools::getBoolean($this->spMetadata, 'useMetadataUrl', False);
            if(!$useMetadataUrl)
                $reqIssuer = Tools::getString($this->spMetadata,'issuer',
                    Tools::getString($remoteSpMeta,'issuer',
                        $state['eidas:requestData']['issuer']));
            else
                $reqIssuer = $this->getMetadataURL();

            if(!array_key_exists('QAA',$state['eidas:requestData'])
            || $state['eidas:requestData']['QAA'] === NULL
            || $state['eidas:requestData']['QAA'] === "")
                $state['eidas:requestData']['QAA'] = 1;
            $QAA = Tools::getInteger($this->spMetadata,'QAA', Tools::getInteger($remoteSpMeta,'QAA', $state['eidas:requestData']['QAA'] ));
            $LoA = SPlib::qaaToLoA($QAA);
        }

        $SPType       = SPlib::EIDAS_SPTYPE_PUBLIC;
        $NameIDFormat = SPlib::NAMEID_FORMAT_PERSISTENT;
        if ($this->dialect === 'eidas'){ //On eIDAS, we always get the country selector value.
            
            //Set defaults for when the remote SP was in Stork mode
            if( isset($state['eidas:requestData']) && ( !array_key_exists('IdFormat',$state['eidas:requestData'])
            || $state['eidas:requestData']['IdFormat'] === NULL
            || $state['eidas:requestData']['IdFormat'] === "") )
                $state['eidas:requestData']['IdFormat'] = SPlib::NAMEID_FORMAT_PERSISTENT;
            
            if( isset($state['eidas:requestData']) && ( !array_key_exists('SPType',$state['eidas:requestData'])
            || $state['eidas:requestData']['SPType'] === NULL
            || $state['eidas:requestData']['SPType'] === ""))
                $state['eidas:requestData']['SPType'] = SPlib::EIDAS_SPTYPE_PUBLIC;
            
            if(isset($state['eidas:requestData']) && (!array_key_exists('LoA',$state['eidas:requestData'])
            || $state['eidas:requestData']['LoA'] === NULL
            || $state['eidas:requestData']['LoA'] === ""))
                $state['eidas:requestData']['LoA'] = SPlib::qaaToLoA($state['eidas:requestData']['QAA']);

            if(isset($state['eidas:requestData'])) {
                $defaultSPType = $state['eidas:requestData']['SPType'];
                $defaultIDFormat = $state['eidas:requestData']['IdFormat'];
                $SPType = Tools::getString($this->spMetadata, 'SPType', Tools::getString($remoteSpMeta, 'SPType', $defaultSPType));
                $NameIDFormat = Tools::getString($this->spMetadata, 'NameIDFormat', Tools::getString($remoteSpMeta, 'NameIDFormat', $defaultIDFormat));
            }

            // If the request had a LoA, that is the priority value
            if(isset($state['eidas:requestData']['LoA'])
                && $state['eidas:requestData']['LoA'] !== "") {
                Logger::debug("Setting LoA from request: ".$state['eidas:requestData']['LoA']);
                $LoA = $state['eidas:requestData']['LoA'];
            }
            else {
                $LoA = Tools::getString($this->spMetadata,'LoA', Tools::getString($remoteSpMeta,'LoA', SPlib::LOA_LOW));
                Logger::debug("Setting LoA from Metadata: ".$LoA);
            }
            $QAA          = SPlib::loaToQaa($LoA);
            $state['eidas:requestData']['QAA'] = SPlib::loaToQaa($LoA); //We overwrite it to avoid it overwriting the LoA later when the remote SP spoke stork
            
            $CitizenCountry = '';
            if($showCountrySelector === true)
                $CitizenCountry = $state['country'];
            
            //Get the metadata URL of this hosted SP
            $metadataURL = $this->getMetadataURL();

            //On eIDAS, the issuer is always the metadata URL
            $reqIssuer = $metadataURL;
        }

        //Hosted SP providerName
        $providerName = Tools::getString($this->spMetadata,'providerName', NULL);


        //Another terrible thing for clave: provider name has two
        //parts: the first one is the friendlyname of the certificate
        //to validate this request, the second part, the providerName
        //of the remote SP we are proxying, for statistics (we get it
        //from spApplication if set on remote sp metadata, or we get
        //it from the request if available)
        if ($this->subdialect === 'clave-1.0'
        || $this->subdialect === 'clave-2.0'){
            
            $remoteProviderName = null;
            
            //Search the value on the request
            if (isset($state['eidas:requestData']['ProviderName'])
            && $state['eidas:requestData']['ProviderName'] !== "") {
                $remoteProviderName = $state['eidas:requestData']['ProviderName'];
            }
            
            //Search the value on the metadata (will overwrite request
            //value. If not found, request value to be used)
            $remoteProviderName = Tools::getString($remoteSpMeta,'spApplication',$remoteProviderName);


            //The geniuses at Spanish Clave 2.0 only added this
            //feature for the RedIRIS proxy!!! if we try to use it for
            //any other administration it fails to identify the SP!!
            //So, I've parametrised this behaviour, to be able to
            //disable it on other deployments
            $forwardPN = Tools::getBoolean($this->spMetadata,'providerName.forward', true);
            if(!$forwardPN)
                $remoteProviderName = null;

            
            //If we finally found something, attach it
            if ($remoteProviderName !== null)
                $providerName = $providerName."_".$remoteProviderName;
        }
        
        
        
        
        //Get address of assertion consumer service for this module (it
        //ends with the id of the authsource, so we can retrieve the
        //correct authsource config on the acs)
        //For eIDAS, this has no effect, as the ACS is read from the eIDAS SP metadata
        $returnPage = Module::getModuleURL('clave/sp/clave-acs.php/'.$this->authId);
        
        
        //Build the authn request
        $eidas = new SPlib();
        Logger::debug("******************************+LoA: ".$LoA);
        if ($this->dialect === 'eidas'){
            $eidas->setEidasMode();
            $eidas->setEidasRequestParams($SPType,
                                          $NameIDFormat,
                                          $LoA);
        }
        
        
        //eIDAS always forces authn
        //if($state['eidas:requestData']['forceAuthn'])
        $eidas->forceAuthn();
        
        $eidas->setSignatureKeyParams($this->certData, $this->keyData, SPlib::RSA_SHA512);
        $eidas->setSignatureParams(SPlib::SHA512,SPlib::EXC_C14N);
        
        $eidas->setServiceProviderParams($providerName, 
                                         $reqIssuer,
                                         $returnPage);
        
        if ($this->dialect === 'stork'){
            $eidas->setSPLocationParams($SPCountry,$SPsector,
                                        $SPinstitution,$SPapp);  
            $eidas->setSPVidpParams($SpId,$CitizenCountry);
        }
        
        $eidas->setSTORKParams ($endpoint,
                                $QAA,
                                $sectorShare,
                                $crossSectorShare,
                                $crossBorderShare);

        //List of mandatory attribute names requested
        $mandatory  = array();
        //Unified list of attributes to request
        $attributes = array();
        
        
        //Workaround for Clave-2.0. It requires the
        //RelayState attribute to be passed (with its
        //value), but if not passed, it needs to be there
        //anyway (not in the specs, but they implemented
        //them wrong), so we set it as empty.
        if ($this->subdialect === 'clave-2.0'){
            
            $found=false;
            if(isset($state['eidas:requestData'])
                && isset($state['eidas:requestData']['requestedAttributes'])){
                foreach($state['eidas:requestData']['requestedAttributes'] as $attr)
                    if ($attr['friendlyName'] === 'RelayState')
                        $found=true;
            }
            
            if(!$found)
                $attributes []= array('RelayState', false);
            // TODO: implement for all eIDAS and STORK to forward the request attr values, if existing
        }
        
        
        //If the remote SP request carried attributes (was an eIDAs request)
        if(array_key_exists('requestedAttributes', $state['eidas:requestData'])
        && is_array($state['eidas:requestData']['requestedAttributes'])
        //&& count($state['eidas:requestData']['requestedAttributes']) > 0 //If the requesting remote SP does this wrong, not my problem
        ){
            
            foreach($state['eidas:requestData']['requestedAttributes'] as $attr){
                $name = NULL;
                if ($this->dialect === 'stork'){
                    $name = SPlib::getFriendlyName($attr['name']);
                }
                if ($this->dialect === 'eidas'){//el dialecto del SP hosted
                    
                    //If the remote SP uses stork dialect but is requesting eIDAs
                    //attributes, it will send the full name of the eIDAS attributes, and
                    //not the friendly name, so we try to get the friendly name, and if
                    //it fails, we consider it already is a friendly name
                    if(array_key_exists('friendlyName', $attr)){
                        $name = $attr['friendlyName'];
                    }
                    else{
                        $name = SPlib::getEidasFriendlyName($attr['name']); //We are expecting eIDAS attribute full names, so 1
                        if($name === "")
                            $name = $attr['name'];
                    }
                }
                $attributes []= array($name, $attr['isRequired'],$attr['values']);  // TODO: add the values array here
                
                //We store the list of mandatory attributes for response validation
                if(SPlib::stb($attr['isRequired']) === true){
                    $mandatory []= $name;
                }
            }
            
        }
        else{ //No attributes came on the remote SP request
            
            //Get fixed list of attributes to request from remote sp
            //metadata
            $attrsToRequest = $state['SPMetadata']['attributes'];
            
            //If not set, default to minimum dataset
            if($attrsToRequest == NULL || count($attrsToRequest)<=0){
                if ($this->dialect === 'stork')
                    $attrsToRequest = array("eIdentifier","givenName","surname");
                if ($this->dialect === 'eidas')
                    $attrsToRequest = array("PersonIdentifier","FirstName","FamilyName","DateOfBirth");
            }
            
            //Set default mandatoriness
            foreach($attrsToRequest as $attr){
                $mand = false;
                
                if ($this->dialect === 'eidas')
                    if (in_array($attr, array("PersonIdentifier","FirstName","FamilyName","DateOfBirth"))){
                        $mand = true;   //minimum dataset always mandatory.
                        $mandatory []= $attr;
                    }
                
                $attributes []= array($attr, $mand);
            }
        }        
        
        //Add the attributes to request
        foreach($attributes as $attribute){
            
            $values = NULL;
            
            if(isset($attribute[2])
            && is_array($attribute[2])
            && sizeof($attribute[2])>0)
                $values = $attribute[2];
            
            $eidas->addRequestAttribute($attribute[0], $attribute[1],$values);
        }
        



    // TODO Seguir

        //If SP sent a RelayState
        if (isset($state['saml:RelayState']) ){

            //Check if the remote SP or the hosted SP need us to keep the
            //RelayState (because it exceeds the standard size of 80)
            $holdRelayState = Tools::getBoolean($this->spMetadata,'holdRelayState',
                Tools::getBoolean($remoteSpMeta,'holdRelayState', false));
            Logger::debug('------------------------hold relay state?: '.$holdRelayState);
            
            if ($holdRelayState){
                $state['saml:HeldRelayState'] = $state['saml:RelayState'];
                $state['saml:RelayState'] = "RS_held_at_Bridge";
                Logger::debug('------------------------curr value: '.$state['saml:RelayState']);
                Logger::debug('------------------------held value: '.$state['saml:HeldRelayState']);
            }
        }
        
        
        //Save information needed for the comeback
        //   $state['clave:sp:reqTime']        = $eidas->getRequestTimestamp();
        $state['clave:sp:returnPage']     = $returnPage;
        $state['clave:sp:mandatoryAttrs'] = $mandatory;
        $id = State::saveState($state, 'clave:sp:req', true);
        Logger::debug("Generated Req ID: ".$id);
        
        
        //Set the id of the request, it must be the id of the saved state.
        $eidas->setRequestId($id);
        
        
        //Build Authn Request
        $req = base64_encode($eidas->generateStorkAuthRequest());
        Logger::debug("SimpleSAML\Module\clave\Auth\Source\SP Generated AuthnReq: ".$req);
        
        
        //Log for statistics: sent AuthnRequest to remote IdP  // TODO: Log any other interesting field?
        Stats::log('clave:sp:AuthnRequest', array(
            'spEntityID' =>  $this->entityId,  // TODO: put the entityId or the issuer?
            'idpEntityID' => $this->idp,
            'forceAuthn' => TRUE,//$state['eidas:requestData']['forceAuthn'],
            'isPassive' => FALSE,
            'protocol' => 'saml2-'.$this->dialect,
            'idpInit' => FALSE,
        ));
        
        
        
        
        //Perform redirection
        $this->redirect($endpoint,$req, $state);
        
        assert('FALSE');   
    }


    /**
     * Handle a response from an SSO operation.
     *
     * @param array $state The authentication state.
     * @param string $idp The entity id of the remote IdP.
     * @param array $attributes The attributes.
     * @throws Error\Exception
     * @throws Error\UnserializableException
     * @throws Exception
     */
	public function handleResponse(array $state, string $idp, array $attributes) {
        assert('is_string($idp)');
        
        $idpMetadata = $this->getIdpMetadata($idp);
        
        $spMetadataArray  = $this->metadata->toArray();
        $idpMetadataArray = $idpMetadata->toArray();
        
        
        //Save the state before calling the chain of AuthProcess filters
		$state['saml:sp:IdP'] = $idp;
		$state['PersistentAuthData'][] = 'saml:sp:IdP';
        
        $authProcState = array(
			'saml:sp:IdP' => $idp,
			'saml:sp:State' => $state,
			'ReturnCall' => array('SimpleSAML\Module\clave\Auth\Source\SP', 'onProcessingCompleted'),
            
			'Attributes' => $attributes, //Add received attributes to the state that will, in the end, be returned to the IdP
			'Destination' => $spMetadataArray,
			'Source' => $idpMetadataArray,
		);
        
		if (isset($state['saml:sp:NameID'])) {
			$authProcState['saml:sp:NameID'] = $state['saml:sp:NameID'];
		}
		if (isset($state['saml:sp:SessionIndex'])) {
			$authProcState['saml:sp:SessionIndex'] = $state['saml:sp:SessionIndex'];
		}
        $pc = new ProcessingChain($idpMetadataArray, $spMetadataArray, 'sp');
		$pc->processState($authProcState);
        
		self::onProcessingCompleted($authProcState);
        
        //$state['Attributes'] = $attributes;
        //Return control to the hosted IDP
        //SimpleSAML\Auth\Source::completeAuth($state);
    }


    /**
     * Called when we have completed the processing chain.
     *
     * @param array $authProcState The processing chain state.
     * @throws Error\Exception
     * @throws Exception
     */
	public static function onProcessingCompleted(array $authProcState) {
		assert('array_key_exists("saml:sp:IdP", $authProcState)');
		assert('array_key_exists("saml:sp:State", $authProcState)');
		assert('array_key_exists("Attributes", $authProcState)');
        
		$idp = $authProcState['saml:sp:IdP'];
		$state = $authProcState['saml:sp:State'];
        
		$sourceId = $state['clave:sp:AuthId'];
		$source = Source::getById($sourceId);
		if ($source === NULL) {
			throw new Exception('Could not find authentication source with id ' . $sourceId);
		}
        
		//Register a callback that we can call if we receive a logout request from the IdP. // TODO: review when implementing SLO
		//$source->addLogoutCallback($idp, $state);
        
		$state['Attributes'] = $authProcState['Attributes'];
        
		if (isset($state['saml:sp:isUnsolicited']) && (bool)$state['saml:sp:isUnsolicited']) {
			if (!empty($state['saml:sp:RelayState'])) {
				$redirectTo = $state['saml:sp:RelayState'];
			} else {
				$redirectTo = Tools::getString($source->getMetadata(),'RelayState', '/');
			}
			self::handleUnsolicitedAuth($sourceId, $state, $redirectTo);
		}

		Source::completeAuth($state);
	}


    /**
     * Do the POST redirection.
     * Will forward authorised POST parameters, if any
     * Some parameters are configurable, but also can be forwarded:
     * - If they came by POST, then that copy is sent to the remote IdP
     * - Else, if they are specifically defined in remote SP metadata, those are sent
     * - Else, if they are specifically defined in the authSource metadata, those are sent
     * - Else, not sent
     *
     * @param $destination
     * @param $req
     * @param $state
     * @throws Error\Exception
     * @throws Exception
     */
  private function redirect($destination, $req, $state){
      
      //Get the remote SP metadata
      $remoteSpMeta  = Configuration::loadFromArray($state['SPMetadata']);
      
      //Get the POST parameters forwarded from the remote SP request
      $forwardedParams = $state['sp:postParams'];
      
      //Add the relay state to the list of forwarded parameters (this way, if the user sent it from the SAML2Int interface, it will work) // TODO check
      if (isset($state['saml:RelayState']) ){
          $forwardedParams['RelayState'] = $state['saml:RelayState'];
      }
            
      
      //Workaround for Clave-2.0 nonsense. If RelayState POST param
      //not set, add it (emtpy).
      if ($this->subdialect === 'clave-2.0'){
          
          $found = false;
          $value = NULL;
          foreach($forwardedParams as $param => $value){
              if ($param === 'RelayState'){
                  $found=true;
                  break;
              }
          }
          
          if(!$found)
              $forwardedParams['RelayState'] = "dummyvalue"; //A value is always required to ensure eIDAS node response includes a relay state and is accepted by Clave2
          else if($value == NULL || $value == "")
              $forwardedParams['RelayState'] = "dummyvalue";
      }
      
      
      //Post params to send
      $post = array('SAMLRequest'  => $req);



      //Specific needs for Clave-1.0 STORK implementation
      if ($this->subdialect === 'clave-1.0'){
          
          if(!array_key_exists('idpList',$forwardedParams)){
              //IdP config values are the default if sp values not found, else not sent
              $idpList = Tools::getArray($remoteSpMeta,'idpList', Tools::getArray($this->spMetadata,'idpList', array()));
              if(count($idpList)>0)
                  $post['idpList'] = Tools::serializeIdpList($idpList);
          }

          if(!array_key_exists('excludedIdPList',$forwardedParams)){
              $idpExcludedList = Tools::getArray($remoteSpMeta,'idpExcludedList', Tools::getArray($this->spMetadata,'idpExcludedList', array()));
              if(count($idpExcludedList)>0)
                  $post['excludedIdPList'] = Tools::serializeIdpList($idpExcludedList);  
          }
          
          
          if(!array_key_exists('forcedIdP',$forwardedParams)){
              //Force a certain auth source
              $force = Tools::getString($remoteSpMeta,'force', Tools::getString($this->spMetadata,'force', NULL));
              if ($force != NULL)
                  $post['forcedIdP'] = $force;
          }
          
          
          if(!array_key_exists('allowLegalPerson',$forwardedParams)){
              //Allow legal person certificates to be used
              $legal = Tools::getBoolean($remoteSpMeta,'allowLegalPerson', false);
              if ($legal === true)
                  $post['allowLegalPerson'] = 'true';
          }
      }

      // TODO eIDAS
      if ($this->subdialect === 'eidas'
      || $this->subdialect === 'stork'){
          
          if(!array_key_exists('country',$forwardedParams)){
              //The state variable country will be set on the return page of the
              //discovery service (country selector)
              if (isset($state['country']))
                  $post['country'] = $state['country'];
          }
      }
      

      //Include the forwarded parameters in the POST [priority values. Will override any prior one]
      foreach($forwardedParams as $param => $value){
          $post[$param] = $value;
      }
      Logger::debug("forwarded: ".print_r($forwardedParams, true));
      Logger::debug("post: ".print_r($post, true));
      
      
      //Redirecting to Clave IdP (Only HTTP-POST binding supported)
      $httpUtils = new HTTP();
      $httpUtils->submitPOSTData($destination, $post);
   
  }




  // TODO: review and merge/refactor all the logout part. Not now. At the end, as it only is useful for clave1 (maybe in the future for clave2).


    /**
     * Start logout operation.
     *
     * @param array $state The logout state.
     * @throws Exception
     */
	public function logout(array &$state): void {
		assert('is_array($state)');
        
        $this->startSLO2($state);
	}


    /**
     * Start a SAML 2 logout operation.
     *
     * @param array $state The logout state.
     * @throws Exception
     */
	public function startSLO2(array &$state) {
		assert('is_array($state)');
        
        $providerName = Tools::getString($this->spMetadata,'providerName', NULL);
        
		$endpoint = Tools::getString($this->idpMetadata,'SingleLogoutService', NULL);
        if ($endpoint == NULL) {
			Logger::info('No logout endpoint for clave remote IdP.');
			return;
		}
        
        //Get address of logout consumer service for this module (it
        //ends with the id of the authsource, so we can retrieve the
        //correct authsource config on the acs)
        $returnPage = Module::getModuleURL('clave/sp/logout-return.php/'.$this->authId);


        $eidas = new SPlib();
   
        $eidas->setSignatureKeyParams($this->certData, $this->keyData,
                                      SPlib::RSA_SHA512);
        $eidas->setSignatureParams(SPlib::SHA512,SPlib::EXC_C14N);
        
        
        //Save information needed for the comeback
        $state['clave:sp:slo:returnPage'] = $returnPage;
        $id = State::saveState($state, 'clave:sp:slo:req', true);
        Logger::debug("Generated Req ID: ".$id);
        
        
        //Generate the logout request
        $req = base64_encode($eidas->generateSLORequest($providerName,
                                                        $endpoint,
                                                        $returnPage,
                                                        $id));
        Logger::debug("Generated LogoutRequest: ".$req);
        
        //Perform redirection
        $post = array('samlRequestLogout' => $req,
                      'RelayState'        => 'dummy');
    //'logoutRequest'? 'SAMLRequest'? 'samlRequestLogout'?
     
        //Redirecting to Clave IdP (Only HTTP-POST binding supported)
        $httpUtils = new HTTP();
        $httpUtils->submitPOSTData($endpoint, $post);
        
        
        /*
        //Stork SLO doesn't use standard SAML2, so we must reimplement it
        
		$lr = sspmod\saml\Message::buildLogoutRequest($this->spMetadata, $this->idpMetadata);
        //Stork does not use nameID
		$lr->setNameId(array(
            'Value' => $this->spMetadata->getString('providerName', NULL),
            //'NameQualifier' => '',
            //'SPNameQualifier' => '',
            'Format' => 'urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified',
        ));
		//$lr->setSessionIndex($sessionIndex);
		$lr->setRelayState($id);
		$lr->setDestination($endpoint);
        $lr->setId($id);
        
        //Always POST binding in Clave
		$b = SAML2_Binding::getBinding('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');
		$b->send($lr);
        */
        
		assert('FALSE');
	}

}


assert('FALSE');
