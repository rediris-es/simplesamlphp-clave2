<?php

/**
 * Country selector interface for eIDAS
 *
 */

//$spEntityId    = $_GET['entityID']; //Hosted SP entity ID
$returnURL     = \SimpleSAML\Utils\HTTP::checkURLAllowed($_GET['return']);
//$returnIdParam = $_GET['returnIDParam'];
$returnIdParam = "country";

echo '<html>'
    .'  <body>'
    .'    <form action="'.$returnURL.'" method="POST">'
    .'      Seleccione su país de orígen:<br/>'
    .'      <br/>'
    .'      <select name="'.$returnIdParam.'">'
    .'        <option value="ES">Spain</option>'
    .'        <option value="AT">Austria</option>'
    .'        <option value="SE">Sweden</option>'
    .'        <option value="GR">Greece</option>'
    .'      </select>'
    .'      <br/>'
    .'      <br/>'
    .'      <input type="submit" value="OK">'
    .'    </form>'
    .'  <body>'
    .'<html>';

    

// TODO read the country list from clave remote IdP or hosted SP config


//\SimpleSAML\Utils\HTTP::redirectTrustedURL($returnURL,array($returnIdParam => 'ES'));



// TODO multilanguage

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