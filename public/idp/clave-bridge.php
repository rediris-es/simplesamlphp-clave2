<?php
/**
 * Clave IdP for simpleSAMLphp. [DEPRECATED]
 *
 */


//Now we redirect to the proper endpoint

SimpleSAML\Logger::info('Call to Clave bridge IdP side [old endpoint]');

SimpleSAML\Utils\HTTP::submitPOSTData(SimpleSAML\Module::getModuleURL('clave/idp/SSOService.php'), $_POST);
//header('Location: '.SimpleSAML\Module::getModuleURL('clave/idp/SSOService.php'));
die();
