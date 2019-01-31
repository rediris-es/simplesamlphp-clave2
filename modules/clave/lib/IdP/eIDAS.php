<?php
/**
 * The specific parts of the IdP for SAML 2.0 eIDAS Protocol and
 * deployment. Internally it will rely on my SPlib, but this will
 * implement the proper SSPHP API to be called by the class that
 * extends SimpleSAML_IdP
 *
 * @author Francisco José Aragó Monzonís, RedIRIS <francisco.arago@externos.rediris.es>
 * @package Clave
 */


// TODO: when everything is working, rename the SPlib and all its internal and external references to eIDASlib

class sspmod_clave_IdP_eIDAS
{




    /**
     * Send a response to the SP.
     *
     * @param array $state The authentication state.
     */
    public static function sendResponse(array $state)
    {
        assert('isset($state["Attributes"])');
        assert('isset($state["SPMetadata"])');
        assert('isset($state["saml:ConsumerURL"])');
        assert('array_key_exists("saml:RequestId", $state)'); // Can be NULL
        assert('array_key_exists("saml:RelayState", $state)'); // Can be NULL.
        
        
        
        //Get the remote SP metadata
        $spMetadata  = SimpleSAML_Configuration::loadFromArray($state['SPMetadata']);
        $spEntityId = $spMetadata->getString('entityid',NULL);
        SimpleSAML_Logger::debug('eIDAS SP remote metadata ('.$spEntityId.'): '.print_r($spMetadata,true));
        
        
        
        SimpleSAML\Logger::info('Sending eIDAS Response to '.var_export($spEntityId, true));
        
        
        $requestId = $state['saml:RequestId'];
        $relayState = $state['saml:RelayState'];
        $consumerURL = $state['saml:ConsumerURL'];
        
        
        $idp = sspmod_clave_IdP::getByState($state);
        
        
        //Get the hosted IdP metadata
        $idpMetadata = $idp->getConfig();
        
        
        //We clone the assertions on the response, as they are signed // TODO: decission needs to be taken later. move to a specific variable.
        //on source (signature kept for legal reasons).    // TODO: make this dialect dependent? or just hierachize assertion building as I did below?
        $rawassertions = null;
        if(isset($state['eidas:raw:assertions']))
            $rawassertions = $state['eidas:raw:assertions'];
        
        //Special structure to build the assertions from scratch if a multi-assertion response is required. No standard AuthFilters may apply here
        $structassertions = null;
        if(isset($state['eidas:struct:assertions']))
            $structassertions = $state['eidas:struct:assertions'];
        
        //The standard ssp attributes. These may have gone through any standard AuthFilter modification
        $singleassertion = null;
        if(isset($state['Attributes']))
            $singleassertion = $state['Attributes'];
        
        //Original request Data
        $reqData = $state['eidas:requestData'];




        
        
        //Signing certificate and key
        $hiCertPath = $idpMetadata->getString('certificate', NULL);
        $hiKeyPath  = $idpMetadata->getString('privatekey', NULL);       
        if($hiCertPath == NULL || $hiKeyPath == NULL)
            throw new SimpleSAML_Error_Exception("'certificate' and/or 'privatekey' parameters not defined in eIDAS hosted IdP Metadata.");
        
        $hikeypem  = sspmod_clave_Tools::readCertKeyFile($hiKeyPath);
        $hicertpem = sspmod_clave_Tools::readCertKeyFile($hiCertPath);
        
        
        //Mode for the IdP (remote SP specific or hosted IdP default)
        $IdPdialect    = $spMetadata->getString('dialect',$idpMetadata->getString('dialect'));
        $IdPsubdialect = $spMetadata->getString('subdialect',$idpMetadata->getString('subdialect'));

        
        //Get response encryption config (remote SP configuration prioritary over hosted IdP config)
        $encryptAssertions = $spMetadata->getBoolean('assertion.encryption',$idpMetadata->getBoolean('assertion.encryption', false));        
        SimpleSAML_Logger::debug('Encrypt assertions: '.$encryptAssertions);
        
        $encryptAlgorithm  = $spMetadata->getString('assertion.encryption.keyAlgorithm',
        $idpMetadata->getString('assertion.encryption.keyAlgorithm', sspmod_clave_SPlib::AES256_CBC));
        $storkize = $spMetadata->getBoolean('assertion.storkize',$idpMetadata->getBoolean('assertion.storkize', false));

        

        //Hybrid STORK-eIDAS-own brew behaviour to get the ACS  // TODO: should we keep it like this? or maybe turn it around? (if fixed, use it, otherwise, use request value)?
        //if ($SPdialect === 'stork')
        //    $acs  = $reqData['assertionConsumerService'];
        //if ($SPdialect === 'eidas')
        //    $acs = $spMetadata->getArray('AssertionConsumerService',array(['Location' => ""]))[0]['Location'];

        //Try to get the ACS from the request
        $acs='';
        if(array_key_exists('assertionConsumerService',$reqData))
            $acs  = $reqData['assertionConsumerService'];
        //If none, get it from the remote SP metadata
        if($acs === NULL || $acs === '')
            $acs = $spMetadata->getArray('AssertionConsumerService',array(['Location' => ""]))[0]['Location'];
        
        if($acs === NULL || $acs == "")
            throw new SimpleSAML_Error_Exception("Assertion Consumer Service URL not found on the request nor metadata for the entity: $spEntityId.");
        
        
        
        //Obtain the full URL of the IdP Metadata page
        $metadataUrl = SimpleSAML_Module::getModuleURL('clave/idp/metadata.php');
        

        //Set the list of POST params to forward from the remote IDP response, if any
        $forwardedParams = array();
        if(isset($state['idp:postParams'])){
            $forwardedParams = $state['idp:postParams'];
        }
        
            
        
        //Build response
        $storkResp = new sspmod_clave_SPlib();


        if ($IdPdialect === 'eidas')
            $storkResp->setEidasMode();
        
        
        $storkResp->setSignatureKeyParams($hicertpem, $hikeypem, sspmod_clave_SPlib::RSA_SHA256);
        
        $storkResp->setSignatureParams(sspmod_clave_SPlib::SHA256,sspmod_clave_SPlib::EXC_C14N);
        
        $storkResp->setCipherParams($reqData['spCert'],$encryptAssertions,$encryptAlgorithm);
        
        $storkResp->setResponseParameters($storkResp::CNS_OBT,
                                          $acs,
                                          $reqData['id'],
                                          $idpMetadata->getString('issuer', $metadataUrl)
                                          );

        
        //Build the assertions, based on the existing variables
        //(generate the xml and pass it as it were raw):
        // * if struct, we prefer struct, but if only one assertion, use standard, if >1 use struct
        // * if no struct but raw, use raw
        // * if no struct nor raw, use standard
        $assertions = '';
        
        if($structassertions !== null){
            
            
            foreach($structassertions as $assertionData){
                
                
                //Set the NameID of the response
                if(isset($state['saml:sp:NameID'])){
                    $assertionData['NameID'] = $state['saml:sp:NameID'];
                    
                    if(!isset($assertionData['NameIDFormat']))
                        $assertionData['NameIDFormat'] = sspmod_clave_SPlib::NAMEID_FORMAT_PERSISTENT;
                }
                
                //TODO: If we want to add conditions, these must be set here by the IdP
                //$assertionData['Address'];
                //$assertionData['Recipient'];          
                //$assertionData['Audience'];  
                
                $assertions .= $storkResp->generateAssertion($assertionData);            
            }
            
        }
        else if($rawassertions !== null){
            
            $assertions = $rawassertions;
            
        }else{ //This was called from a standard AuthSource and only has the standard attribute list
            
            //Build transfer object from the standard attribute list
            $assertionData = array();
            $assertionData['Issuer'] = $idpMetadata->getString('issuer', $metadataUrl);
            if(isset($state['saml:sp:NameID'])){
                $assertionData['NameID'] = $state['saml:sp:NameID'];
                $assertionData['NameIDFormat'] = sspmod_clave_SPlib::NAMEID_FORMAT_PERSISTENT;
            }
            
            $assertionData['attributes'] = array();
            foreach($singleassertion as $attributename => $values){
                $assertionData['attributes'] []= array(
                    'values'       => $values,
                    'friendlyName' => $attributename,
                    'name'         => $attributename,
                );
            }
            
            $assertions = $storkResp->generateAssertion($assertionData);            
            
        }
        
        // TODO SEGUIR MAÑANA: when this part is done, it should be functional. tried test env for clave and it does not work. recreate it also. first test the clave lib over clave with normal functioning, then start testing over esmo specific env-----> create test env (and create special script to deploy both modules), Integrate last version of the lib? and deploy in test environment in stork.uji.es (and devel mockups as needed)
        
        
        //We build a status response with the status codes returned by Clave
        if(isset($state['eidas:raw:status']))
            $status = $state['eidas:raw:status'];
        else if (isset($state['eidas:status'])){
            $status = $storkResp->generateStatus( array(
                'Code' => $state['eidas:status']['MainStatusCode'],
                'SubCode' => $state['eidas:status']['SecondaryStatusCode'],
                'Message' => $state['eidas:status']['StatusMessage'],
            ));
        }else{ //The AuthSource was standard, so a call here can only happen on success
            $status = $storkResp->generateStatus( array(
                'Code' => sspmod_clave_SPlib::ST_SUCCESS,
            ));
        }
        
        
        
        $resp = $storkResp->generateStorkResponse($status,$assertions,true,true,$storkize);
        SimpleSAML_Logger::debug("Response to send to the remote SP: ".$resp);        
        
        
        
        //Log statistics: sentResponse to remote clave SP
        $status = array(
            'Code' => $state['eidas:status']['MainStatusCode'],
            'SubCode' => $state['eidas:status']['SecondaryStatusCode'],
            'Message' => $state['eidas:status']['StatusMessage'],
        );
        $statsData = array(
            'spEntityID' => $spEntityId,
            'idpEntityID' => $idpMetadata->getString('issuer', $metadataUrl),
            'protocol' => 'saml2-'.$IdPdialect,
            'status' => $status,
        );
        if (isset($state['saml:AuthnRequestReceivedAt'])) {
            $statsData['logintime'] = microtime(TRUE) - $state['saml:AuthnRequestReceivedAt'];
        }
        SimpleSAML_Stats::log('clave:idp:Response', $statsData);
        
        
        
        
        //Redirect to the remote SP
        $post = array(
            'SAMLResponse'  => base64_encode($resp),
        ) + $forwardedParams;
        SimpleSAML_Utilities::postRedirect($acs, $post);
    }
    
    
    
    /**
     * Handle authentication error.
     *
     * SimpleSAML_Error_Exception $exception  The exception.
     *
     * @param array $state The error state.
     */
    public static function handleAuthError(SimpleSAML_Error_Exception $exception, array $state)
    {
        assert('isset($state["SPMetadata"])');
        assert('isset($state["saml:ConsumerURL"])');
        assert('array_key_exists("saml:RequestId", $state)'); // Can be NULL.
        assert('array_key_exists("saml:RelayState", $state)'); // Can be NULL.



        //Get the remote SP metadata
        $spMetadata  = SimpleSAML_Configuration::loadFromArray($state['SPMetadata']);
        $spEntityId = $spMetadata->getString('entityid',NULL);
        SimpleSAML_Logger::debug('eIDAS SP remote metadata ('.$spEntityId.'): '.print_r($spMetadata,true));
        
        
        
        SimpleSAML\Logger::info('Sending eIDAS Response to '.var_export($spEntityId, true));
        
        
        $requestId = $state['saml:RequestId'];
        $relayState = $state['saml:RelayState'];
        $consumerURL = $state['saml:ConsumerURL'];
        $protocolBinding = $state['saml:Binding'];        
        
        $idp = sspmod_clave_IdP::getByState($state);
        
        
        //Get the hosted IdP metadata
        $idpMetadata = $idp->getConfig();
        
        
        
        $error = sspmod_saml_Error::fromException($exception);
        
        SimpleSAML\Logger::warning("Returning error to SP with entity ID '".var_export($spEntityId, true)."'.");
        $exception->log(SimpleSAML\Logger::WARNING);

        $ar = self::buildResponse($idpMetadata, $spMetadata, $consumerURL);
        $ar->setInResponseTo($requestId);
        $ar->setRelayState($relayState);

        $status = array(
            'Code'    => $error->getStatus(),
            'SubCode' => $error->getSubStatus(),
            'Message' => $error->getStatusMessage(),
        );
        $ar->setStatus($status);

        $statsData = array(
            'spEntityID'  => $spEntityId,
            'idpEntityID' => $idpMetadata->getString('entityID'),
            'protocol'    => 'saml2',
            'error'       => $status,
        );
        if (isset($state['saml:AuthnRequestReceivedAt'])) {
            $statsData['logintime'] = microtime(true) - $state['saml:AuthnRequestReceivedAt'];
        }
        SimpleSAML_Stats::log('saml:idp:Response:error', $statsData);

        $binding = \SAML2\Binding::getBinding($protocolBinding);
        $binding->send($ar);
        
        
    }
    
    
    
    /**
     * Build a authentication response based on information in the metadata.
     *
     * @param SimpleSAML_Configuration $idpMetadata The metadata of the IdP.
     * @param SimpleSAML_Configuration $spMetadata The metadata of the SP.
     * @param string                   $consumerURL The Destination URL of the response.
     *
     * @return \SAML2\Response The SAML2 response corresponding to the given data.
     */
    private static function buildResponse(
        SimpleSAML_Configuration $idpMetadata,
        SimpleSAML_Configuration $spMetadata,
        $consumerURL
    ) {

        $signResponse = $spMetadata->getBoolean('saml20.sign.response', null);
        if ($signResponse === null) {
            $signResponse = $idpMetadata->getBoolean('saml20.sign.response', true);
        }

        $r = new \SAML2\Response();

        $r->setIssuer($idpMetadata->getString('entityID'));  // TODO: quizá deba cambiar esto para que se devuelva el de la respuesta original. O hacerlo dialect-specific. Decidir
        $r->setDestination($consumerURL);

        if ($signResponse) {
            sspmod_saml_Message::addSign($idpMetadata, $spMetadata, $r);
        }

        return $r;
    }
}

