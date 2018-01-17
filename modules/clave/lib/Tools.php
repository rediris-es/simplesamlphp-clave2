<?php


class sspmod_clave_Tools {



    //Loads a metadata set from the clave specific metadata
    //files. Metadata directory is taken from the global configuration
    // @param $entityId The Id of the entoty whose metadata we want
    // @param $set which metadada set to read from (the name of the file without extension)
    // @return a SimpleSAML_Configuration object with the metadata for the entity
    public static function getMetadataSet($entityId, $set){
    
        $globalConfig = SimpleSAML_Configuration::getInstance();
        $metadataDirectory = $globalConfig->getString('metadatadir', 'metadata/');
        $metadataDirectory = $globalConfig->resolvePath($metadataDirectory) . '/';

        $metadataFile = $metadataDirectory.'/'.$set.'.php';
        try{
            //Don't use _once or the global variable might get unset.
            require($metadataFile);
        }catch(Exception $e){
            throw new Exception("Clave Metadata file ".$metadataFile." not found.");
        }
        
        if(!isset($claveMeta))
            throw new Exception("Clave Metadata set ".$set.": malformed or undefined global clave metadata variable");
    
        if(!isset($claveMeta[$entityId]))
            throw new Exception("Entity ".$entityId." not found in set ".$set);
    
        return SimpleSAML_Configuration::loadFromArray($claveMeta[$entityId]);
    }


    //Retrieves metadata for a given clave SP, but taking into account
    //whether he must search the clave or the saml20 metadatafiles.
    public static function getSPMetadata($claveConfig,$spEntityId){
        
        //Retrieve the metadata for the requesting SP
        $spMetadata = NULL;
        if(!$claveConfig->getBoolean('sp.useSaml20Meta', false)){
            $spMetadata = sspmod_clave_Tools::getMetadataSet($spEntityId,"clave-sp-remote");
        }else{
            $metadata   = SimpleSAML_Metadata_MetaDataStorageHandler::getMetadataHandler();
            $spMetadata = $metadata->getMetaDataConfig($spEntityId, 'saml20-sp-remote');
        }
        
        return $spMetadata;
    }
    
    
    // Reads file relative to the configured cert directory
    public static function readCertKeyFile ($relativePath){
        
        if($relativePath == null || $relativePath == '')
            throw new Exception('Unable to load cert or key from file: path is empty');
        
        $path = SimpleSAML_Utilities::resolveCert($relativePath);
        $data = @file_get_contents($path);
        if ($data === false){
            throw new Exception('Unable to load cert or key from file "' . $path . '"');
        }
        
        return $data;
    }



    //Lists of clave paraeters are sent as ; separated field strings
    public static function serializeIdpList ($idpArray){
        
        if(count($idpArray) <= 0)
            return "";
        
        $idpList = "";
        foreach($idpArray as $idp){
            $idpList .= $idp.';';
        }
        //Remove trailing separator
        $idpList = substr($idpList,0,strlen($idpList)-1);
        
        return $idpList;
    }

/*
    public static function findX509SignCertOnMetadata ($metadata){
        $pem = NULL;
        
        $keys = $metadata->getArray('keys',NULL);
        if ($keys == NULL)
            throw new Exception('No key entry found in metadata: '.print_r($metadata,true));
        
        foreach($keys as $key){
            if($key['type'] != 'X509Certificate')
                continue;
            if(!$key['signing'])
                continue;
            $pem = $key['X509Certificate'];
        }
        
        if($pem == NULL || $pem == '')
            throw new Exception('No X509 signing certificate found in metadata: '.print_r($metadata,true));
        
        return $pem;
    }
*/
    
    //Now it returns an array
    public static function findX509SignCertOnMetadata ($metadata){
        $ret = array();
        
        $keys = $metadata->getArray('keys',NULL);
        if ($keys == NULL)
            throw new Exception('No key entry found in metadata: '.print_r($metadata,true));
        
        foreach($keys as $key){
            if($key['type'] != 'X509Certificate')
                continue;
            if(!$key['signing'])
                continue;
            if(!$key['X509Certificate'] || $key['X509Certificate'] == "")
                continue;
            
            $ret []= $key['X509Certificate'];
        }
        
        if(sizeof($ret) <= 0)
            throw new Exception('No X509 signing certificate found in metadata: '.print_r($metadata,true));
        
        return $ret;
    }
    
    
}