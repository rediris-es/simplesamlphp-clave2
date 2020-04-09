<?php
/**
 * Clave IdP for simpleSAMLphp. [DEPRECATED]
 *
 */


//Now we redirect to the proper endpoint

SimpleSAML_Logger::info('Call to Clave bridge IdP side [old endpoint]');

SimpleSAML_Utilities::postRedirect(SimpleSAML_Module::getModuleURL('clave/idp/SSOService.php'), $_POST);
//header('Location: '.SimpleSAML_Module::getModuleURL('clave/idp/SSOService.php'));
die();
