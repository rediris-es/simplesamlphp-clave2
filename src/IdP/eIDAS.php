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
     * @throws \SimpleSAML\Error\Exception
     * @throws Exception
     */
    public static function sendResponse(array $state)
    {
        assert('isset($state["Attributes"])');
        assert('isset($state["SPMetadata"])');
        assert('isset($state["saml:ConsumerURL"])');
        assert('array_key_exists("saml:RequestId", $state)'); // Can be NULL
        assert('array_key_exists("saml:RelayState", $state)'); // Can be NULL.
        
        
        
        //Get the remote SP metadata
        $spMetadata  = SimpleSAML\Configuration::loadFromArray($state['SPMetadata']);
        $spEntityId = $spMetadata->getString('entityid',NULL);
        SimpleSAML\Logger::debug('eIDAS SP remote metadata ('.$spEntityId.'): '.print_r($spMetadata,true));
        
        
        
        SimpleSAML\Logger::info('Sending eIDAS Response to '.var_export($spEntityId, true));
        
        
        $requestId = $state['saml:RequestId'];
        $relayState = $state['saml:RelayState'];
        SimpleSAML\Logger::debug('------------------Relay State on sendResponse: '.$state['saml:RelayState']);
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
            throw new SimpleSAML\Error\Exception("'certificate' and/or 'privatekey' parameters not defined in eIDAS hosted IdP Metadata.");
        
        $hikeypem  = sspmod_clave_Tools::readCertKeyFile($hiKeyPath);
        $hicertpem = sspmod_clave_Tools::readCertKeyFile($hiCertPath);
        
        
        //Mode for the IdP (remote SP specific or hosted IdP default)
        $IdPdialect    = $spMetadata->getString('dialect',$idpMetadata->getString('dialect'));
        $IdPsubdialect = $spMetadata->getString('subdialect',$idpMetadata->getString('subdialect'));

        
        //Get response encryption config (remote SP configuration prioritary over hosted IdP config)
        $encryptAssertions = $spMetadata->getBoolean('assertion.encryption',$idpMetadata->getBoolean('assertion.encryption', false));        
        SimpleSAML\Logger::debug('Encrypt assertions: '.$encryptAssertions);
        
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
            throw new SimpleSAML\Error\Exception("Assertion Consumer Service URL not found on the request nor metadata for the entity: $spEntityId.");
        
        
        
        //Obtain the full URL of the IdP Metadata page
        $metadataUrl = SimpleSAML\Module::getModuleURL('clave/idp/metadata.php');
        

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
        
        if($encryptAssertions === TRUE)
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
        $assertions = array();
        
        if($structassertions !== null){
            
            
            foreach($structassertions as $assertionData){
                
                // TODO: This block is legacy. Should be implemented on the esmo
                //   module authsource acs and removed from here. It is already
                //   implemented on this acs
                //Set the NameID of the response
                if(isset($state['saml:sp:NameID'])){
                    $assertionData['NameID'] = $state['saml:sp:NameID'];
                }
                else{
                    //Set the NameID from the eIDAS ID attribute
                    //$idAttrName = 'eIdentifier';  // TODO: is this mandatory in STORK? fro the moment, leave it out // TODO: maybe define a param to mark the ID attr line in AdAS?
                    $idAttrName = 'PersonIdentifier';
                    foreach($assertionData['attributes'] as $attr){
                        if($attr['friendlyName'] == $idAttrName
                        || $attr['name'] == $idAttrName){
                            $assertionData['NameID'] = $attr['values'][0];
                            break;
                        }
                    }
                }
                    
                if(!isset($assertionData['NameIDFormat']))
                    $assertionData['NameIDFormat'] = sspmod_clave_SPlib::NAMEID_FORMAT_PERSISTENT;
                
                
                //TODO: If we want to add conditions, these must be set here by the IdP
                //$assertionData['Address'];
                //$assertionData['Recipient'];          
                //$assertionData['Audience'];  
                
                $assertions []= $storkResp->generateAssertion($assertionData);               
            }
            
        }
        else if($rawassertions !== null){
            
            $assertions = $rawassertions;
            
        }else{ //This was called from a standard AuthSource and only has the standard attribute list
            
            //Build transfer object from the standard attribute list
            $assertionData = array();
            $assertionData['Issuer'] = $idpMetadata->getString('issuer', $metadataUrl);            
            
            $assertionData['attributes'] = array();
            foreach($singleassertion as $attributename => $values){

                //In some cases, I might have stored the full names here:
                $attributefullname = $attributename;
                if(isset($state['eidas:attr:names']))
                    if(isset($state['eidas:attr:names'][$attributename]))
                        $attributefullname = $state['eidas:attr:names'][$attributename];
                
                $assertionData['attributes'] []= array(
                    'values'       => $values,
                    'friendlyName' => $attributename,
                    'name'         => $attributefullname,
                );
            }


            if(isset($state['saml:sp:NameID'])){
                $assertionData['NameID'] = $state['saml:sp:NameID'];
            }
            else{
                //Set the NameID from the eIDAS ID attribute
                //$idAttrName = 'eIdentifier';  // TODO: is this mandatory in STORK? fro the moment, leave it out
                $idAttrName = 'PersonIdentifier';
                foreach($assertionData['attributes'] as $attr){
                    if($attr['friendlyName'] == $idAttrName
                    || $attr['name'] == $idAttrName){
                        $assertionData['NameID'] = $attr['values'][0];
                        break;
                    }
                }
            }
            $assertionData['NameIDFormat'] = sspmod_clave_SPlib::NAMEID_FORMAT_PERSISTENT;
            
            
            //Set the effective LoA that was used:
            if (isset($state['saml:AuthnContextClassRef'])){
                $assertionData['AuthnContextClassRef'] = $state['saml:AuthnContextClassRef'];
            }
                        
            $assertions = array($storkResp->generateAssertion($assertionData));
            
        }
        
        
        
        //We build a status response with the status codes returned by Clave
        if(isset($state['eidas:raw:status']))
            $status = $state['eidas:raw:status'];
        else if (isset($state['eidas:status'])){
            $status = $storkResp->generateStatus( array(
                'MainStatusCode' => $state['eidas:status']['MainStatusCode'],
                'SecondaryStatusCode' => $state['eidas:status']['SecondaryStatusCode'],
                'StatusMessage' => $state['eidas:status']['StatusMessage'],
            ));
        }else{ //The AuthSource was standard, so a call here can only happen on success
            $status = $storkResp->generateStatus( array(
                'MainStatusCode' => sspmod_clave_SPlib::ST_SUCCESS,
            ));
        }
        
        
        
        $resp = $storkResp->generateStorkResponse($status,$assertions,true,true,$storkize);
        SimpleSAML\Logger::debug("Response to send to the remote SP: ".$resp);
        
        
        
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
        SimpleSAML\Stats::log('clave:idp:Response', $statsData);
        
        
        
        
        //Redirect to the remote SP
        $post = array(
            'SAMLResponse'  => base64_encode($resp),
        ) + $forwardedParams;
        
        if($relayState != NULL)
            $post['RelayState'] = $relayState;
        
        SimpleSAML\Utils\HTTP::submitPOSTData($acs, $post);
    }


    /**
     * Handle authentication error.
     *
     * SimpleSAML\Error\Exception $exception  The exception.
     *
     * @param array $state The error state.
     * @throws Exception
     */
    public static function handleAuthError(SimpleSAML\Error\Exception $exception, array $state)
    {
        assert('isset($state["SPMetadata"])');
        assert('isset($state["saml:ConsumerURL"])');
        assert('array_key_exists("saml:RequestId", $state)'); // Can be NULL.
        assert('array_key_exists("saml:RelayState", $state)'); // Can be NULL.
        
        
        
        //Get the remote SP metadata
        $spMetadata  = SimpleSAML\Configuration::loadFromArray($state['SPMetadata']);
        $spEntityId = $spMetadata->getString('entityid',NULL);
        SimpleSAML\Logger::debug('eIDAS SP remote metadata ('.$spEntityId.'): '.print_r($spMetadata,true));
        
        
        
        SimpleSAML\Logger::info('Sending eIDAS Response to '.var_export($spEntityId, true));

        $relayState = NULL;
        if(isset($state['saml:RelayState']))
            $relayState = $state['saml:RelayState'];
        
        $requestId = $state['saml:RequestId'];
        $consumerURL = $state['saml:ConsumerURL'];
        $protocolBinding = $state['saml:Binding'];        
        
        $idp = sspmod_clave_IdP::getByState($state);
        
        
        //Get the hosted IdP metadata
        $idpMetadata = $idp->getConfig();
        
        
        
        //$error = SimpleSAML\Error\Exception::fromException($exception);
        $error = \SimpleSAML\Module\saml\Error::fromException($exception);
        
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
        SimpleSAML\Stats::log('saml:idp:Response:error', $statsData);

        $binding = SAML2\Binding::getBinding($protocolBinding);
        $binding->send($ar);
        
        
    }


    /**
     * Build a authentication response based on information in the metadata.
     *
     * @param SimpleSAML\Configuration $idpMetadata The metadata of the IdP.
     * @param SimpleSAML\Configuration $spMetadata The metadata of the SP.
     * @param string $consumerURL The Destination URL of the response.
     *
     * @return SAML2\Response The SAML2 response corresponding to the given data.
     * @throws Exception
     */
    private static function buildResponse(
        SimpleSAML\Configuration $idpMetadata,
        SimpleSAML\Configuration $spMetadata,
        $consumerURL
    ) {

        $signResponse = $spMetadata->getBoolean('saml20.sign.response', null);
        if ($signResponse === null) {
            $signResponse = $idpMetadata->getBoolean('saml20.sign.response', true);
        }

        $r = new SAML2\Response();

        $r->setIssuer($idpMetadata->getString('entityID'));  // TODO: quizá deba cambiar esto para que se devuelva el de la respuesta original. O hacerlo dialect-specific. Decidir
        $r->setDestination($consumerURL);

        if ($signResponse) {
            SimpleSAML\Module\saml\Message::addSign($idpMetadata, $spMetadata, $r);
        }

        return $r;
    }
}

