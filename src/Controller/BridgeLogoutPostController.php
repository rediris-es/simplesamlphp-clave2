<?php
namespace SimpleSAML\Module\clave\Controller;

use Symfony\Component\HttpFoundation\Response;

class BridgeLogoutPostController
{
    public function __invoke(): Response
    {
        // 1. Capture whatever your script echoes/prints
        ob_start();
       
        // 2. Include your legacy script (it will still have full access to $_POST)
        require __DIR__ . '/../../public/sp/bridge-logout.php';
       
        // 3. Return the script's output as a proper response
        return new Response(ob_get_clean());
    }
}