<?php

namespace SimpleSAML\Module\authX509\Auth\Process;

use SimpleSAML\Auth;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Utils;
use Webmozart\Assert\Assert;

/**
 * Filter which shows a warning if the user's client certificate is about to expire.
 *
 ** <code>
 * // show about2xpire warning if client certificate is about to expire
 * 10 => array(
 *     'class' => 'authX509:ExpiryWarning',
 *     'warndaysbefore' => '30',
 * ),
 * </code>
 *
 * @author Joost van Dijk, SURFnet. <Joost.vanDijk@surfnet.nl>
 * @package SimpleSAMLphp
 */

class ExpiryWarning extends Auth\ProcessingFilter
{
    /** @var int */
    private $warndaysbefore = 30;

    /** @var string|null */
    private $renewurl = null;

    /**
     * Initialize this filter.
     *
     * @param array $config  Configuration information about this filter.
     * @param mixed $reserved  For future use.
     */
    public function __construct(array $config, $reserved)
    {
        parent::__construct($config, $reserved);

        if (array_key_exists('warndaysbefore', $config)) {
            $this->warndaysbefore = $config['warndaysbefore'];
            if (!is_string($this->warndaysbefore)) {
                throw new \Exception('Invalid value for \'warndaysbefore\'-option to authX509::ExpiryWarning filter.');
            }
        }

        if (array_key_exists('renewurl', $config)) {
            $this->renewurl = $config['renewurl'];
            if (!is_string($this->renewurl)) {
                throw new \Exception('Invalid value for \'renewurl\'-option to authX509::ExpiryWarning filter.');
            }
        }
    }

    /**
     * Process an authentication response.
     *
     * This function saves the state, and if necessary redirects the user to the page where the user
     * is informed about the expiry date of his/her certificate.
     *
     * @param array $state  The state of the response.
     * @return void
     */
    public function process(array &$state): void
    {
        if (isset($state['isPassive']) && $state['isPassive'] === true) {
            // We have a passive request. Skip the warning
            return;
        }

        if (
            !isset($_SERVER['SSL_CLIENT_CERT']) ||
            ($_SERVER['SSL_CLIENT_CERT'] == '')
        ) {
            return;
        }

        $client_cert = $_SERVER['SSL_CLIENT_CERT'];
        $client_cert_data = openssl_x509_parse($client_cert);
        if ($client_cert_data == false) {
            Logger::error('authX509: invalid cert');
            return;
        }
        $validTo = $client_cert_data['validTo_time_t'];
        $now = time();
        $daysleft = (int) (($validTo - $now) / 86400); //24*60*60
        if ($daysleft > $this->warndaysbefore) {
            // We have a certificate that will be valid for some time. Skip the warning
            return;
        }

        Logger::warning('authX509: user certificate expires in ' . $daysleft . ' days');
        $state['daysleft'] = $daysleft;
        $state['renewurl'] = $this->renewurl;

        // Save state and redirect
        $id = Auth\State::saveState($state, 'warning:expire');
        $url = Module::getModuleURL('authX509/expirywarning.php');
        Utils\HTTP::redirectTrustedURL($url, ['StateId' => $id]);
    }
}
