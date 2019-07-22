<?php
 
class sspmod_clave_Auth_Source_SP extends SimpleSAML_Auth_Source {
  
  
    private static $mandatoryConfigParams = array('providerName','entityid','QAA',
    'certificate','privatekey','idpEntityID','SingleSignOnService','certData',
    'hostedSP','dialect','subdialect');
    
	/**
	 * The entity ID of this SP.
	 *
	 * @var string
	 */
	private $entityId;
    
    
	/**
	 * The metadata of this SP (the authSource cofngi file entry content).
	 *
	 * @var SimpleSAML_Configuration.
	 */
	private $metadata;
    
    
    /**
	 * The entityID of the remote IdP we will be contacting.
	 *
	 * @var string  The IdP the user will log into.
	 */
	private $idp;
    
    
	/**
	 * URL to discovery service.
	 *
	 * @var string|NULL
	 */
	private $discoURL;
    
    
	/**
	 * The metadata of the hosted SP configured in the authSource.
	 *
	 * @var SimpleSAML_Configuration.
	 */
    private $spMetadata;
    
    
   	/**
	 * The metadata of the remote IdP.
	 *
	 * @var SimpleSAML_Configuration.
	 */ 
    private $idpMetadata;
    
    
	/**
	 * The Dialect this SP will use to contact the remote IdP
	 *
	 * @var string Dialect identifier.
	 */
    private $dialect;
    
    
	/**
	 * The Sub-Dialect this SP will use to contact the remote IdP
	 *
	 * @var string Sub-Dialect identifier.
	 */
    private $subdialect;
    
    
	/**
	 * The Certificate that will be used to sign the AuthnReq.
	 *
	 * @var string PEM encoded without headers.
	 */
    private $certData;


	/**
	 * The Private Key that will be used to sign the AuthnReq.
	 *
	 * @var string PEM encoded without headers.
	 */
    private $keyData;


	/**
	 * Constructor for SAML2-eIDAS SP authentication source.
	 *
	 * @param array $info  Information about this authentication source (contains AuthId, the id of this auth source).
	 * @param array $config  Configuration block of this authsource in authsources.php.
	 */
    public function __construct($info, $config) {
        assert('is_array($info)');
        assert('is_array($config)');
        
        // Call the parent constructor first, as required by the interface.
        parent::__construct($info, $config);
        
        
        SimpleSAML_Logger::debug('Called sspmod_clave_Auth_Source_SP constructor');
        //SimpleSAML_Logger::debug('info: '.print_r($info, true));
        SimpleSAML_Logger::debug('config: '.print_r($config, true));
        
        
        
        //Load the metadata of the authsource (from the authsources file)
        $this->metadata = SimpleSAML_Configuration::loadFromArray($config, 
        'authsources['.var_export($this->authId,true).']');
        
        
        //Get the hosted sp metadata
        $spConfId = $this->metadata->getString('hostedSP', NULL);
        if($spConfId == NULL)
            throw new SimpleSAML_Error_Exception("hostedSP field not defined for eIDAS auth source.");
        $this->spMetadata = sspmod_clave_Tools::getMetadataSet($spConfId,"clave-sp-hosted");
        SimpleSAML_Logger::debug('eIDAS SP hosted metadata: '.print_r($this->spMetadata,true));
        
        
        //Get the remote idp metadata
        $idpEntityId = $this->spMetadata->getString('idpEntityID', NULL);
        if($idpEntityId == NULL)
            throw new SimpleSAML_Error_Exception("idpEntityID field not defined for eIDAS auth source.");
        $this->idpMetadata = sspmod_clave_Tools::getMetadataSet($idpEntityId,"clave-idp-remote");
        SimpleSAML_Logger::debug('eIDAS IDP remote metadata ('.$idpEntityId.'): '.print_r($this->idpMetadata,true));
        
        
        
        //Check if all mandatory config is available (in any of the sets) // TODO review this, as there might be collisions, and review the list of mandatory
        foreach (self::$mandatoryConfigParams as $mandParam) {
            $value = $this->metadata->getValue($mandParam, NULL);
            if ($value == NULL)
                $value = $this->spMetadata->getValue($mandParam, NULL);
            if ($value == NULL)
                $value = $this->idpMetadata->getValue($mandParam, NULL);
            if ($value == NULL)
                throw new SimpleSAML_Error_Exception("$mandParam field not defined for eIDAS auth source."); 
        }
        
        
        //Set the class properties
        $this->discoURL   = $this->metadata->getString('discoURL', 'clave/sp/countryselector.php'); // TODO: default value. can be moved elsewhere? can module name be parametrised? anyway, remember to change module name
        $this->entityId   = $this->spMetadata->getString('entityid');
        $this->idp        = $idpEntityId;
        $this->dialect    = $this->spMetadata->getString('dialect');
        $this->subdialect = $this->spMetadata->getString('subdialect');
        
        $this->certData = sspmod_clave_Tools::readCertKeyFile($this->spMetadata->getString('certificate', NULL));
        $this->keyData  = sspmod_clave_Tools::readCertKeyFile($this->spMetadata->getString('privatekey', NULL)); 
                
        // TODO: to delete as ssphp impl has changed. seek if this data needs to be passed elsewhere
        //      $this->idp = array('endpoint' => $this->idpMetadata->getString('SingleSignOnService', NULL),
        //                   'cert'     => $this->idpMetadata->getString('certData', NULL));
    }
    
    
    
	/**
	 * Retrieve the URL to the metadata of this SP (eIDAS).
	 *
	 * @return string  The metadata URL.
	 */
	public function getMetadataURL() {
        
        $spConfId = $this->metadata->getString('hostedSP', NULL);
        return SimpleSAML\Module::getModuleURL('clave/sp/metadata.php/'.'clave/'.urlencode($spConfId).'/'.urlencode($this->authId));
	}
    
    
    
	/**
	 * Retrieve the entity id of this SP.
	 *
	 * @return string  The entity id of this SP.
	 */
	public function getEntityId() {

        return $this->entityId;
	}
       
    
    
	/**
	 * Retrieve the metadata of this SP (the authSource content).
	 *
	 * @return SimpleSAML_Configuration  The metadata of this SP.
	 */
	public function getMetadata() {
        
        return $this->metadata;
	}
    
    

	/**
	 * Retrieve the metadata of an IdP.
	 *
	 * @param string $entityId  The entity id of the IdP.
	 * @return SimpleSAML_Configuration  The metadata of the IdP.
	 */
	public function getIdPMetadata($entityId="") {
		assert('is_string($entityId)');
        
        //Here we have just a fixed IdP, eIDAS does not support the list of allowed IDPs        
        return $this->idpMetadata;
    }
    
    
    
	/**
	 * Start a discovery service operation, (country selector in eIDAS).
	 *
	 * @param array $state  The state array.
	 */
	private function startDisco(array $state) {

        SimpleSAML_Logger::debug('Called sspmod_clave_Auth_Source_SP startDisco');
        
        //Whether to show the country selctor
        $showCountrySelector = $this->spMetadata->getBoolean('showCountrySelector', false);
        
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
		$id = SimpleSAML_Auth_State::saveState($state, 'clave:sp:sso');
        
		$config = SimpleSAML_Configuration::getInstance();

        //Use country selector url defined in config (internal or absolute)
        $discoURL = $this->discoURL;        
        if (!preg_match('/^\s*https?:/',$this->discoURL)) {
            //It is relative to the module
            $discoURL = SimpleSAML_Module::getModuleURL($this->discoURL);
        }
        
        $returnTo = SimpleSAML_Module::getModuleURL('clave/sp/discoresp.php', array('AuthID' => $id)); // TODO: remove clave reference. make the module name a global or something
        
		$params = array( // TODO ver si son necesarios y describirlos
			//'entityID' => $this->entityId,     //The clave hosted SP entityID
			'return' => $returnTo,             //The script to go on with the auth process (contains the authsource ID)
			//'returnIDParam' => 'country'       //The param name where the country ID will be searched
		);
        
		\SimpleSAML\Utils\HTTP::redirectTrustedURL($discoURL, $params);
	}
 
    

    
	/**
	 * Start login.
	 *
	 * This function saves the information about the login, and redirects to the IdP.
	 *
	 * @param array &$state  Information about the current authentication.
	 */
	public function authenticate(&$state) {
        assert('is_array($state)');
        
        SimpleSAML_Logger::debug('Called sspmod_clave_Auth_Source_SP authenticate');
                
        // We are going to need the authId in order to retrieve this authentication source later.
        $state['clave:sp:AuthId']      = $this->authId;
        
        
        
        //Remote IdP might be fixed by the hosted IdP calling (overrides the value on the authsource metadata)
        //This variable is the same for the SAML2 authsource
		if (isset($state['saml:idp'])
        && $state['saml:idp'] != ""){
            $idpEntityId = $state['saml:idp'];
            
            SimpleSAML_Logger::debug('eIDAS IDP remote fixed by hosted IDP: ('.$idpEntityId.')');
            $this->idp = $idpEntityId;
            
            $this->idpMetadata = sspmod_clave_Tools::getMetadataSet($idpEntityId,"clave-idp-remote");
            SimpleSAML_Logger::debug('eIDAS IDP remote metadata ('.$idpEntityId.'): '.print_r($this->idpMetadata,true));
        }
        
        
        
        //We will also need the clave idp remote to go on with the sso after the country selector discovery
        $state['clave:sp:idpEntityID'] = $this->idp;
        
        
        SimpleSAML_Logger::info("state: ".print_r($state,true));
        SimpleSAML_Logger::info("metadata: ".print_r($this->metadata,true));

        
        //Redirect to the Country Selector (if enabled and needed)
        $this->startDisco($state);
        
        //Go on with the authentication
        $this->startSSO( $this->idp, $state);
        assert('FALSE');   
	}

 

 

	/**
	 * Send a SSO request to an IdP.
	 *
	 * @param string $idp  The entity ID of the IdP.
	 * @param array $state  The state array for the current authentication.
	 */
	public function startSSO($idp, array $state) {
        assert('is_string($idp)');
        
        SimpleSAML_Logger::debug('Called sspmod_clave_Auth_Source_SP startSSO');
        
        SimpleSAML_Logger::debug("Hosted SP Certificate: ".$this->certData);
        
        //We get the Remote SP Metadata
        $remoteSpMeta  = SimpleSAML_Configuration::loadFromArray($state['SPMetadata']);
        
        
        $showCountrySelector = $this->spMetadata->getBoolean('showCountrySelector', false);

        $endpoint = $this->idpMetadata->getString('SingleSignOnService', NULL);
        
        
        $sectorShare      = "";
        $crossSectorShare = "";
        $crossBorderShare = "";
        $LoA = 1;
        if ($this->dialect === 'stork'){
            
            //These params are set, in order of preference:
            // 1. From the remote SP metadata (if set)
            // 2. From the hosted SP metadata (if set)
            // 3. From the request (if it specified any values, else, empty string)
            $SPCountry = $remoteSpMeta->getString('spCountry',$this->spMetadata->getString('spCountry', ''.$state['eidas:requestData']['spCountry']));
            $SPsector  = $remoteSpMeta->getString('spSector',$this->spMetadata->getString('spSector', ''.$state['eidas:requestData']['spSector']));
            $SPinstitution = $remoteSpMeta->getString('spInstitution',$this->spMetadata->getString('spInstitution', ''.$state['eidas:requestData']['spInstitution']));
            $SPapp = $remoteSpMeta->getString('spApplication',$this->spMetadata->getString('spApplication', ''.$state['eidas:requestData']['spApplication']));
            //$SpId="$SPCountry-$SPsector-$SPinstitution-$SPapp";
            $SpId = $remoteSpMeta->getString('spID',$this->spMetadata->getString('spID', ''.$state['eidas:requestData']['spID']));
            $sectorShare      = $remoteSpMeta->getBoolean('eIDSectorShare', $this->spMetadata->getBoolean('eIDSectorShare',
                                                 sspmod_clave_SPlib::stb($state['eidas:requestData']['eIDSectorShare'])));
            $crossSectorShare = $remoteSpMeta->getBoolean('eIDCrossSectorShare', $this->spMetadata->getBoolean('eIDCrossSectorShare',
                                                 sspmod_clave_SPlib::stb($state['eidas:requestData']['eIDCrossSectorShare'])));
            $crossBorderShare = $remoteSpMeta->getBoolean('eIDCrossBorderShare', $this->spMetadata->getBoolean('eIDCrossBorderShare',
                                                 sspmod_clave_SPlib::stb($state['eidas:requestData']['eIDCrossBorderShare'])));
                        
            $CitizenCountry = "";
            //For Spain's Clave based on stork, country is fixed
            if ($this->subdialect === 'clave-1.0'){
                $CitizenCountry = $remoteSpMeta->getString('citizenCountryCode',$this->spMetadata->getString('citizenCountryCode', ''.$state['eidas:requestData']['citizenCountryCode']));
            }
            if ($this->subdialect === 'stork')
                if($showCountrySelector === true)
                    $CitizenCountry = $state['country'];
            
            
            //Issuer is set in this order:
            // 1. Hosted SP metadata issuer field (if set)
            // 2. Remote SP metadata issuer field (if set)
            // 3. Issuer Field specified on the remote SP request
            // (Dropped using the entityId of the hosted SP)
            $reqIssuer = $this->spMetadata->getString('issuer', $remoteSpMeta->getString('issuer', $state['eidas:requestData']['issuer']));

            if(!array_key_exists('QAA',$state['eidas:requestData'])
            || $state['eidas:requestData']['QAA'] === NULL
            || $state['eidas:requestData']['QAA'] === "")
                $state['eidas:requestData']['QAA'] = 1;
            $QAA = $this->spMetadata->getInteger('QAA', $remoteSpMeta->getInteger('QAA', $state['eidas:requestData']['QAA'] ));
            $LoA = sspmod_clave_SPlib::qaaToLoA($QAA);
        }
        
        if ($this->dialect === 'eidas'){ //On eIDAS, we always get the country selector value.
            
            //Set defaults for when the remote SP was in Stork mode
            if(!array_key_exists('IdFormat',$state['eidas:requestData'])
            || $state['eidas:requestData']['IdFormat'] === NULL
            || $state['eidas:requestData']['IdFormat'] === "")
                $state['eidas:requestData']['IdFormat'] = sspmod_clave_SPlib::NAMEID_FORMAT_PERSISTENT;
            
            if(!array_key_exists('SPType',$state['eidas:requestData'])
            || $state['eidas:requestData']['SPType'] === NULL
            || $state['eidas:requestData']['SPType'] === "")
                $state['eidas:requestData']['SPType'] = sspmod_clave_SPlib::EIDAS_SPTYPE_PUBLIC;
            
            if(!array_key_exists('LoA',$state['eidas:requestData'])
            || $state['eidas:requestData']['LoA'] === NULL
            || $state['eidas:requestData']['LoA'] === "")
                $state['eidas:requestData']['LoA'] = sspmod_clave_SPlib::qaaToLoA($state['eidas:requestData']['QAA']);
            
            $SPType       = $this->spMetadata->getString('SPType', $remoteSpMeta->getString('SPType', $state['eidas:requestData']['SPType']));
            $NameIDFormat = $this->spMetadata->getString('NameIDFormat', $remoteSpMeta->getString('NameIDFormat', $state['eidas:requestData']['IdFormat']));
            $LoA          = $this->spMetadata->getString('LoA', $remoteSpMeta->getString('LoA', $state['eidas:requestData']['LoA']));
            $QAA          = sspmod_clave_SPlib::loaToQaa($LoA);
            $state['eidas:requestData']['QAA'] = sspmod_clave_SPlib::loaToQaa($LoA); //We overwrite it to avoid it overwriting the LoA later when the remote SP spoke stork
            
            $CitizenCountry = '';
            if($showCountrySelector === true)
                $CitizenCountry = $state['country'];
            
            //Get the metadata URL of this hosted SP
            $metadataURL = $this->getMetadataURL();

            //On eIDAS, the issuer is always the metadata URL
            $reqIssuer = $metadataURL;
        }

        //Hosted SP providerName
        $providerName = $this->spMetadata->getString('providerName', NULL);


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
            $remoteProviderName = $remoteSpMeta->getString('spApplication',$remoteProviderName);
            
            
            //If we finally found something, attach it
            if ($remoteProviderName !== null)
                $providerName = $providerName."_".$remoteProviderName;
        }
        
        
        
        
        //Get address of assertion consumer service for this module (it
        //ends with the id of the authsource, so we can retrieve the
        //correct authsource config on the acs)
        //For eIDAS, this has no effect, as the ACS is read from the eIDAS SP metadata
        $returnPage = SimpleSAML_Module::getModuleURL('clave/sp/clave-acs.php/'.$this->authId);
        
        
        //Build the authn request
        $eidas = new sspmod_clave_SPlib();
        SimpleSAML_Logger::debug("******************************+LoA: ".$LoA);
        if ($this->dialect === 'eidas'){
            $eidas->setEidasMode();
            $eidas->setEidasRequestParams($SPType,
                                          $NameIDFormat,
                                          $LoA);
        }
        
        
        //eIDAS always forces authn
        //if($state['eidas:requestData']['forceAuthn'])
        $eidas->forceAuthn();
        
        $eidas->setSignatureKeyParams($this->certData, $this->keyData, sspmod_clave_SPlib::RSA_SHA512);
        $eidas->setSignatureParams(sspmod_clave_SPlib::SHA512,sspmod_clave_SPlib::EXC_C14N);
        
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
            foreach($state['eidas:requestData']['requestedAttributes'] as $attr)
                if ($attr['friendlyName'] === 'RelayState')
                    $found=true;
            
            if(!$found)
                $attributes []= array('RelayState', false);  // TODO SEGUIR
            // TODO: implement for all eIDAS and STORK to forward the reuqest attr values, if existing
        }
        
        
        //If the remote SP request carried attributes (was an eIDAs request)
        if(array_key_exists('requestedAttributes', $state['eidas:requestData'])
        && is_array($state['eidas:requestData']['requestedAttributes'])
        //&& count($state['eidas:requestData']['requestedAttributes']) > 0 //If the requesting remote SP does this wrong, not my problem
        ){
            
            foreach($state['eidas:requestData']['requestedAttributes'] as $attr){
                
                if ($this->dialect === 'stork'){
                    $name = sspmod_clave_SPlib::getFriendlyName($attr['name']);
                }
                if ($this->dialect === 'eidas'){//el dialecto del SP hosted
                    
                    //If the remote SP uses stork dialect but is requestin eIDAs
                    //attributes, it will send the full name of the eIDAS attributes, and
                    //not the friendly name, so we try to get the friendly name, and if
                    //it fails, we consider it already is a friendly name
                    if(array_key_exists('friendlyName', $attr)){
                        $name = $attr['friendlyName'];
                    }
                    else{
                        $name = sspmod_clave_SPlib::getEidasFriendlyName($attr['name']); //We are expecting eIDAS attribute full names, so 1
                        if($name === "")
                            $name = $attr['name'];
                    }
                }
                $attributes []= array($name, $attr['isRequired'],$attr['values']);  // TODO: add the values array here
                
                //We store the list of mandatory attributes for response validation
                if(sspmod_clave_SPlib::stb($attr['isRequired']) === true){
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
                $mandatory = false;
                
                if ($this->dialect === 'eidas')
                    if (in_array($attr, array("PersonIdentifier","FirstName","FamilyName","DateOfBirth"))){
                        $mandatory = true;   //minimum dataset always mandatory.
                        $mandatory []= $attr;
                    }
                
                $attributes []= array($attr, $mandatory);
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
        
        
        
        //Save information needed for the comeback
        //   $state['clave:sp:reqTime']        = $eidas->getRequestTimestamp();
        $state['clave:sp:returnPage']     = $returnPage;
        $state['clave:sp:mandatoryAttrs'] = $mandatory;
        $id = SimpleSAML_Auth_State::saveState($state, 'clave:sp:req', true);
        SimpleSAML_Logger::debug("Generated Req ID: ".$id);
        
        
        //Set the id of the request, it must be the id of the saved state.
        $eidas->setRequestId($id);
        
        
        //Build Authn Request
        $req = base64_encode($eidas->generateStorkAuthRequest());
        SimpleSAML_Logger::debug("sspmod_clave_Auth_Source_SP Generated AuthnReq: ".$req);
        
        
        //Log for statistics: sent AuthnRequest to remote IdP  // TODO: Log any other interesting field?
        SimpleSAML_Stats::log('clave:sp:AuthnRequest', array(
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
	 * Handle a response from a SSO operation.
	 *
	 * @param array $state  The authentication state.
	 * @param string $idp  The entity id of the remote IdP.
	 * @param array $attributes  The attributes.
	 */
	public function handleResponse(array $state, $idp, array $attributes) {
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
			'ReturnCall' => array('sspmod_clave_Auth_Source_SP', 'onProcessingCompleted'),
            
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
        $pc = new SimpleSAML_Auth_ProcessingChain($idpMetadataArray, $spMetadataArray, 'sp');
		$pc->processState($authProcState);
        
		self::onProcessingCompleted($authProcState);
        
        //$state['Attributes'] = $attributes;
        //Return control to the hosted IDP
        //SimpleSAML_Auth_Source::completeAuth($state);
    }



	/**
	 * Called when we have completed the processing chain.
	 *
	 * @param array $authProcState  The processing chain state.
	 */
	public static function onProcessingCompleted(array $authProcState) {
		assert('array_key_exists("saml:sp:IdP", $authProcState)');
		assert('array_key_exists("saml:sp:State", $authProcState)');
		assert('array_key_exists("Attributes", $authProcState)');
        
		$idp = $authProcState['saml:sp:IdP'];
		$state = $authProcState['saml:sp:State'];
        
		$sourceId = $state['clave:sp:AuthId'];
		$source = SimpleSAML_Auth_Source::getById($sourceId);
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
				$redirectTo = $source->getMetadata()->getString('RelayState', '/');
			}
			self::handleUnsolicitedAuth($sourceId, $state, $redirectTo);
		}
        
		SimpleSAML_Auth_Source::completeAuth($state);
	}

    
  
  //Do the POST redirection.
  //Will forward authorised POST parameters, if any
  //Some parameters are configurable, but also can be forwarded:
  // - If they came by POST, then that copy is sent to the remote IdP
  // - Else, if they are specifically defined in remote SP metadata, those are sent
  // - Else, if they are specifically defined in tthe authSource metadata, those are sent
  // - Else, not sent
  private function redirect($destination, $req, $state){
      
      //Get the remote SP metadata
      $remoteSpMeta  = SimpleSAML_Configuration::loadFromArray($state['SPMetadata']);
      
      //Get the POST parameters forwarded from the remote SP request
      $forwardedParams = $state['sp:postParams'];
      
      
      //Workaround for Clave-2.0 nonsense. If RelayState POST param
      //not set, add it (emtpy).
      if ($this->subdialect === 'clave-2.0'){
          
          $found=false;
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
              $idpList = $remoteSpMeta->getArray('idpList', $this->spMetadata->getArray('idpList', array()));  
              if(count($idpList)>0)
                  $post['idpList'] = sspmod_clave_Tools::serializeIdpList($idpList);
          }

          if(!array_key_exists('excludedIdPList',$forwardedParams)){
              $idpExcludedList = $remoteSpMeta->getArray('idpExcludedList', $this->spMetadata->getArray('idpExcludedList', array()));
              if(count($idpExcludedList)>0)
                  $post['excludedIdPList'] = sspmod_clave_Tools::serializeIdpList($idpExcludedList);  
          }
          
          
          if(!array_key_exists('forcedIdP',$forwardedParams)){
              //Force a certain auth source
              $force = $remoteSpMeta->getString('force', $this->spMetadata->getString('force', NULL));
              if ($force != NULL)
                  $post['forcedIdP'] = $force;
          }
          
          
          if(!array_key_exists('allowLegalPerson',$forwardedParams)){
              //Allow legal person certificates to be used
              $legal = $remoteSpMeta->getBoolean('allowLegalPerson', false);
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
      SimpleSAML_Logger::debug("forwarded: ".print_r($forwardedParams, true));
      SimpleSAML_Logger::debug("post: ".print_r($post, true));
      
      
      //Redirecting to Clave IdP (Only HTTP-POST binding supported)
      SimpleSAML_Utilities::postRedirect($destination, $post);
   
  }




  // TODO: review and merge/refactor all the logout part. Not now. At the end, as it only is useful for clave1 (maybe in the future for clave2).


	/**
	 * Start logout operation.
	 *
	 * @param array $state  The logout state.
	 */
	public function logout(&$state) {
		assert('is_array($state)');
        
        $this->startSLO2($state);
        return;
	}


	/**
	 * Start a SAML 2 logout operation.
	 *
	 * @param array $state  The logout state.
	 */
	public function startSLO2(&$state) {
		assert('is_array($state)');
        
        $providerName = $this->spMetadata->getString('providerName', NULL);
        
		$endpoint = $this->idpMetadata->getString('SingleLogoutService', NULL);
        if ($endpoint === NULL) {
			SimpleSAML_Logger::info('No logout endpoint for clave remote IdP.');
			return;
		}
        
        //Get address of logout consumer service for this module (it
        //ends with the id of the authsource, so we can retrieve the
        //correct authsource config on the acs)
        $returnPage = SimpleSAML_Module::getModuleURL('clave/sp/logout-return.php/'.$this->authId);


        $eidas = new sspmod_clave_SPlib();
   
        $eidas->setSignatureKeyParams($this->certData, $this->keyData,
                                      sspmod_clave_SPlib::RSA_SHA512);
        $eidas->setSignatureParams(sspmod_clave_SPlib::SHA512,sspmod_clave_SPlib::EXC_C14N);
        
        
        //Save information needed for the comeback
        $state['clave:sp:slo:returnPage'] = $returnPage;
        $id = SimpleSAML_Auth_State::saveState($state, 'clave:sp:slo:req', true);
        SimpleSAML_Logger::debug("Generated Req ID: ".$id);
        
        
        //Generate the logout requestx
        $req = base64_encode($eidas->generateSLORequest($providerName,
                                                        $endpoint,
                                                        $returnPage,
                                                        $id));
        SimpleSAML_Logger::debug("Generated LogoutRequest: ".$req);
        
        //Perform redirection
        $post = array('samlRequestLogout' => $req,
                      'RelayState'        => 'dummy',));
    //'logoutRequest'? 'SAMLRequest'? 'samlRequestLogout'?
     
        //Redirecting to Clave IdP (Only HTTP-POST binding supported)
        SimpleSAML_Utilities::postRedirect($endpoint, $post);
        
        
        /*
        //Stork SLO doesn't use standard SAML2, so we must reimplement it
        
		$lr = sspmod_saml_Message::buildLogoutRequest($this->spMetadata, $this->idpMetadata);
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
