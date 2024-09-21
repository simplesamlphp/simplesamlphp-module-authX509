<?php

declare(strict_types=1);

namespace SimpleSAML\Module\authX509\Auth\Source;

use Exception;
use SimpleSAML\Assert\Assert;
use SimpleSAML\Auth;
use SimpleSAML\Configuration;
use SimpleSAML\Error;
use SimpleSAML\Logger;
use SimpleSAML\Module\ldap\ConnectorFactory;
use SimpleSAML\Module\ldap\ConnectorInterface;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\Ldap\Entry;
use Symfony\Component\Ldap\Ldap;
use Symfony\Component\Ldap\Security\LdapUserProvider;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;

use function array_fill_keys;
use function array_key_exists;
use function array_merge;
use function array_values;
use function current;
use function is_null;
use function openssl_x509_parse;
use function sprintf;

/**
 * This class implements x509 certificate authentication with certificate validation against an LDAP directory.
 *
 * @package SimpleSAMLphp
 */

class X509userCert extends Auth\Source
{
    /** @var \SimpleSAML\Module\ldap\ConnectorInterface */
    protected ConnectorInterface $connector;

    /**
     * The ldap-authsource to use
     * @var string
     */
    private string $backend;

    /**
     * The ldap-authsource config to use
     * @var \SimpleSAML\Configuration
     */
    private Configuration $ldapConfig;

    /**
     * x509 attributes to use from the certificate for searching the user in the LDAP directory.
     * @var array<string, string>
     */
    private array $x509attributes = ['UID' => 'uid'];

    /**
     * LDAP attribute containing the user certificate.
     * This can be set to NULL to avoid looking up the certificate in LDAP
     * @var array|null
     */
    private ?array $ldapusercert = ['userCertificate;binary'];


    /**
     * Constructor for this authentication source.
     *
     * All subclasses who implement their own constructor must call this constructor before using $config for anything.
     *
     * @param array $info Information about this authentication source.
     * @param array &$config Configuration for this authentication source.
     */
    public function __construct(array $info, array &$config)
    {
        parent::__construct($info, $config);

        if (isset($config['authX509:x509attributes'])) {
            $this->x509attributes = $config['authX509:x509attributes'];
        }

        if (array_key_exists('authX509:ldapusercert', $config)) {
            $this->ldapusercert = $config['authX509:ldapusercert'];
        }

        Assert::keyExists($config, 'backend');
        $this->backend = $config['backend'];

        // Get the authsources file, which should contain the backend-config
        $authSources = Configuration::getConfig('authsources.php');

        // Verify that the authsource config exists
        if (!$authSources->hasValue($this->backend)) {
            throw new Error\Exception(
                sprintf('Authsource [%s] not found in authsources.php', $this->backend),
            );
        }

        // Get just the specified authsource config values
        $this->ldapConfig = $authSources->getConfigItem($this->backend);
        $type = current($this->ldapConfig->toArray());
        Assert::oneOf($type, ['ldap:Ldap']);

        $this->connector = ConnectorFactory::fromAuthSource($this->backend);
    }


    /**
     * Finish a failed authentication.
     *
     * This function can be overloaded by a child authentication class that wish to perform some operations on failure.
     *
     * @param array &$state Information about the current authentication.
     */
    public function authFailed(&$state): void
    {
        $config = Configuration::getInstance();
        $errorcode = $state['authX509.error'];
        $errorcodes = (new Error\ErrorCodes())->getAllMessages();

        $t = new Template($config, 'authX509:X509error.twig');
        $httpUtils = new Utils\HTTP();
        $t->data['loginurl'] = $httpUtils->getSelfURL();

        if (!empty($errorcode)) {
            if (array_key_exists($errorcode, $errorcodes['title'])) {
                $t->data['errortitle'] = $errorcodes['title'][$errorcode];
            }
            if (array_key_exists($errorcode, $errorcodes['descr'])) {
                $t->data['errordescr'] = $errorcodes['descr'][$errorcode];
            }
        }

        $t->send();
        exit();
    }


    /**
     * Validate certificate and login.
     *
     * This function try to validate the certificate. On success, the user is logged in without going through the login
     * page. On failure, The authX509:X509error.php template is loaded.
     *
     * @param array &$state Information about the current authentication.
     */
    public function authenticate(array &$state): void
    {
        if (
            !isset($_SERVER['SSL_CLIENT_CERT']) ||
            ($_SERVER['SSL_CLIENT_CERT'] == '')
        ) {
            $state['authX509.error'] = "NOCERT";
            $this->authFailed($state);

            throw new Exception("Should never be reached");
        }

        $client_cert = $_SERVER['SSL_CLIENT_CERT'];
        $client_cert_data = openssl_x509_parse($client_cert);
        if ($client_cert_data === false) {
            Logger::error('authX509: invalid cert');
            $state['authX509.error'] = "INVALIDCERT";
            $this->authFailed($state);

            throw new Exception("Should never be reached");
        }

        $entry = $dn = null;
        foreach ($this->x509attributes as $x509_attr => $attr) {
            // value is scalar
            if (array_key_exists($x509_attr, $client_cert_data['subject'])) {
                $value = $client_cert_data['subject'][$x509_attr];
                Logger::info('authX509: cert ' . $x509_attr . ' = ' . $value);
                $entry = $this->findUserByAttribute($attr, $value);
                if ($entry !== null) {
                    $dn = $attr;
                    break;
                }
            }
        }

        if ($entry === null) {
            Logger::error('authX509: cert has no matching user in LDAP.');
            $state['authX509.error'] = "UNKNOWNCERT";
            $this->authFailed($state);

            throw new Exception("Should never be reached");
        }

        if ($this->ldapusercert === null) {
            // do not check for certificate match
            if (is_null($this->ldapConfig->getOptionalArray('attributes', null))) {
                $attributes = $entry->getAttributes();
            } else {
                $attributes = array_intersect_key(
                    $entry->getAttributes(),
                    array_fill_keys(array_values($this->ldapConfig->getArray('attributes')), null),
                );
            }

            $state['Attributes'] = $attributes;
            $this->authSuccesful($state);

            throw new Exception("Should never be reached");
        }

        $ldap_certs = [];
        foreach ($this->ldapusercert as $attr) {
            $ldap_certs[$attr] = $entry->getAttribute($attr);
        }

        if (empty($ldap_certs)) {
            Logger::error('authX509: no certificate found in LDAP for dn=' . $dn);
            $state['authX509.error'] = "UNKNOWNCERT";
            $this->authFailed($state);

            throw new Exception("Should never be reached");
        }


        $merged_ldapcerts = [];
        foreach ($this->ldapusercert as $attr) {
            $merged_ldapcerts = array_merge($merged_ldapcerts, $ldap_certs[$attr]);
        }
        $ldap_certs = $merged_ldapcerts;

        $cryptoUtils = new Utils\Crypto();
        foreach ($ldap_certs as $ldap_cert) {
            $pem = $cryptoUtils->der2pem($ldap_cert);
            $ldap_cert_data = openssl_x509_parse($pem);
            if ($ldap_cert_data === false) {
                Logger::error('authX509: cert in LDAP is invalid for dn=' . $dn);
                continue;
            }

            if ($ldap_cert_data === $client_cert_data) {
                if (is_null($this->ldapConfig->getOptionalArray('attributes', null))) {
                    $attributes = $entry->getAttributes();
                } else {
                    $attributes = array_intersect_key(
                        $entry->getAttributes(),
                        array_fill_keys(array_values($this->ldapConfig->getArray('attributes')), null),
                    );
                }

                $state['Attributes'] = $attributes;
                $this->authSuccesful($state);

                throw new Exception("Should never be reached");
            }
        }

        Logger::error('authX509: no matching cert in LDAP for dn=' . $dn);
        $state['authX509.error'] = "UNKNOWNCERT";
        $this->authFailed($state);

        throw new Exception("Should never be reached");
    }


    /**
     * Finish a successful authentication.
     *
     * This function can be overloaded by a child authentication class that wish to perform some operations after login.
     *
     * @param array &$state Information about the current authentication.
     */
    public function authSuccesful(array &$state): void
    {
        Auth\Source::completeAuth($state);

        throw new Exception("Should never be reached");
    }


    /**
     * Find user in LDAP-store
     *
     * @param string $attr
     * @param string $value
     * @return \Symfony\Component\Ldap\Entry|null
     */
    public function findUserByAttribute(string $attr, string $value): ?Entry
    {
        $searchBase = $this->ldapConfig->getArray('search.base');

        $searchUsername = $this->ldapConfig->getOptionalString('search.username', null);
        Assert::nullOrnotWhitespaceOnly($searchUsername);

        $searchPassword = $this->ldapConfig->getOptionalString('search.password', null);
        Assert::nullOrnotWhitespaceOnly($searchPassword);

        $ldap = ConnectorFactory::fromAuthSource($this->backend);
        $connection = new Ldap($ldap->getAdapter());

        foreach ($searchBase as $base) {
            $ldapUserProvider = new LdapUserProvider($connection, $base, $searchUsername, $searchPassword, [], $attr);
            try {
                return $ldapUserProvider->loadUserByIdentifier($value)->getEntry();
            } catch (UserNotFoundException $e) {
                continue;
            }
        }

        // We haven't found the user
        return null;
    }
}
