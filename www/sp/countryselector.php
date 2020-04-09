<?php

/**
 * Country selector interface for eIDAS
 *
 */

//Hosted IdP config
$claveConfig = sspmod_clave_Tools::getMetadataSet("__DYNAMIC:1__","clave-idp-hosted");
SimpleSAML\Logger::debug('Clave Idp hosted metadata: '.print_r($claveConfig,true));


//Hosted SP config
$hostedSP = $claveConfig->getString('hostedSP', NULL);
if($hostedSP == NULL)
    throw new SimpleSAML_Error_Exception("No clave hosted SP configuration defined in clave bridge configuration.");
$claveSP = sspmod_clave_Tools::getMetadataSet($hostedSP,"clave-sp-hosted");
SimpleSAML\Logger::debug('Clave SP hosted metadata: '.print_r($claveSP,true));


//Get the list of countries
$countries = $claveSP->getArray('countries', array());




//$spEntityId    = $_GET['entityID']; //Hosted SP entity ID
$returnURL     = \SimpleSAML\Utils\HTTP::checkURLAllowed($_GET['return']);
//$returnIdParam = $_GET['returnIDParam'];
$returnIdParam = "country";

$countryLines = '';
foreach($countries as $countryCode => $countryName)
    $countryLines .= '<option value="'.$countryCode.'">'.$countryName.'</option>';


$page =  '<html>'
    .'  <body>'
    .'    <form action="'.$returnURL.'" method="POST">'
    .'      Seleccione su país de orígen:<br/>'
    .'      <br/>'
    .'      <select name="'.$returnIdParam.'">'
    .$countryLines
    .'      </select>'
    .'      <br/>'
    .'      <br/>'
    .'      <input type="submit" value="Continuar">'
    .'    </form>'
    .'  <body>'
    .'<html>';


echo $page;


//\SimpleSAML\Utils\HTTP::redirectTrustedURL($returnURL,array($returnIdParam => 'ES'));



//TODO multilanguage

//TODO include ssphp template header and footer

/*
// TODO implement all html in the module as templates (see if the other modules redirects use the standard calls)
  
        // Make use of an XHTML template to present the select IdP choice to the user. Currently the supported options
        // is either a drop down menu or a list view.
         
        switch ($this->config->getString('idpdisco.layout', 'links')) {
            case 'dropdown':
                $templateFile = 'selectidp-dropdown.php';
                break;
            case 'links':
                $templateFile = 'selectidp-links.php';
                break;
            default:
                throw new Exception('Invalid value for the \'idpdisco.layout\' option.');
        }

        $t = new SimpleSAML_XHTML_Template($this->config, $templateFile, 'disco');
        $t->data['idplist'] = $idpList;
        $t->data['preferredidp'] = $preferredIdP;
        $t->data['return'] = $this->returnURL;
        $t->data['returnIDParam'] = $this->returnIdParam;
        $t->data['entityID'] = $this->spEntityId;
        $t->data['urlpattern'] = htmlspecialchars(\SimpleSAML\Utils\HTTP::getSelfURLNoQuery());
        $t->data['rememberenabled'] = $this->config->getBoolean('idpdisco.enableremember', false);
        $t->show();



*/