<?php

/**
 * The configuration of SimpleSAMLphp
 */

$httpUtils = new \SimpleSAML\Utils\HTTP();

$config = [
 
 
 
    /*
     * Custom function for session checking called on session init and loading.
     * See docs/simplesamlphp-advancedfeatures.md for function code example.
     *
     * Example:
     *   'session.check_function' => ['\SimpleSAML\Module\example\Util', 'checkSession'],
     */
    // Function to virtually invalidate sessions on the bridge. This way, 
    // any AuthnRequest received by the IdP endpoints will always trigger the wired authsource
    // to do the authentication against the remote IdP. 
'session.check_function' => function (\SimpleSAML\Session $session, bool $init = false): bool {
    // On session creation SSP calls this with $init=true (return ignored).
    if ($init) {
        return true;
    }
    // Bridge policy: any session carrying authentication is discarded,
    // so every AuthnRequest re-authenticates at the auth source.
    // The 'admin' authority is exempted or the SSP admin UI becomes
    // unusable (instant logout loop).
    foreach ($session->getAuthorities() as $authority) {
        if ($authority !== 'admin') {
            return false;
        }
    }
    return true;
},

];
