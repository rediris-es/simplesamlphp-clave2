<?php

namespace SimpleSAML\Module\clave;


use Exception;
use SimpleSAML\Assert\AssertionFailedException;
use SimpleSAML\Configuration;
use SimpleSAML\Error\MetadataNotFound;
use SimpleSAML\Metadata\MetaDataStorageHandler;

class Tools {


    /**
     * Loads a metadata set from the clave specific metadata files. Metadata
     * directory is taken from the global configuration
     *
     * The Id of the entoty whose metadata we want
     * @param $entityId
     * which metadada set to read from (the name of the file without extension)
     * @param $set
     * metadata for the entity
     * @return Configuration
     * @throws Exception
     */
    public static function getMetadataSet($entityId, $set): Configuration
    {
    
        $globalConfig = Configuration::getInstance();
        $metadataDirectory = self::getString($globalConfig,'metadatadir', 'metadata/');
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
    
        return Configuration::loadFromArray($claveMeta[$entityId]);
    }


    /**
     * Retrieves metadata for a given clave SP, but taking into account
     * whether he must search the clave or the saml20 metadatafiles.
     * @param Configuration $claveConfig
     * @param $spEntityId
     * @return Configuration|null
     * @throws MetadataNotFound
     * @throws Exception
     */
    public static function getSPMetadata(Configuration $claveConfig, $spEntityId): ?Configuration
    {
        
        //Retrieve the metadata for the requesting SP
        $spMetadata = NULL;
        if(!self::getBoolean($claveConfig,'sp.useSaml20Meta', false)){
            $spMetadata = Tools::getMetadataSet($spEntityId,"clave-sp-remote");
        }else{
            $metadata   = MetaDataStorageHandler::getMetadataHandler();
            $spMetadata = $metadata->getMetaDataConfig($spEntityId, 'saml20-sp-remote');
        }
        
        return $spMetadata;
    }
    
    

    /**
     * Reads file relative to the configured cert directory
     *
     * @param string $relativePath
     * @return string
     * @throws Exception
     */
    public static function readCertKeyFile (string $relativePath): string
    {
        
        if($relativePath == null || $relativePath == '')
            throw new Exception('Unable to load cert or key from file: path is empty');
        
        $path = (new \SimpleSAML\Utils\Config)->getCertPath($relativePath);
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
    /**
     * @param Configuration $metadata
     * @return array
     * @throws Exception
     */
    public static function findX509SignCertOnMetadata (Configuration $metadata): array
    {
        $ret = array();
        
        $keys = self::getArray($metadata,'keys', NULL);
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


    /**
     * @param Configuration $configArray
     * @param string $field
     * @param string|null $default
     * @return string|NULL
     */
    public static function getString (Configuration $configArray, string $field, string $default=NULL): ?string
    {
        try{
            return $configArray->getString($field);
        }catch (AssertionFailedException $e){
            return $default;
        }
    }

    /**
     * @param Configuration $configArray
     * @param string $field
     * @param boolean|null $default
     * @return boolean|NULL
     */
    public static function getBoolean (Configuration $configArray, string $field, bool $default=NULL): bool
    {
        try{
            return $configArray->getBoolean($field);
        }catch (AssertionFailedException $e){
            return $default;
        }
    }

    /**
     * @param Configuration $configArray
     * @param string $field
     * @param int|null $default
     * @return int|null
     */
    public static function getInteger (Configuration $configArray, string $field, int $default=NULL): ?int
    {
        try{
            return $configArray->getInteger($field);
        }catch (AssertionFailedException $e){
            return $default;
        }
    }

    /**
     * @param Configuration $configArray
     * @param string $field
     * @param array|null $default
     * @return array|null
     */
    public static function getArray (Configuration $configArray, string $field, array $default=NULL): ?array
    {
        try{
            return $configArray->getArray($field);
        }catch (AssertionFailedException $e){
            return $default;
        }
    }
}