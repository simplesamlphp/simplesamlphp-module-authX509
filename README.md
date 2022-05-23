# simplesamlphp-module-authx509

![Build Status](https://github.com/simplesamlphp/simplesamlphp-module-authX509/workflows/CI/badge.svg?branch=master)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/simplesamlphp/simplesamlphp-module-authX509/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/simplesamlphp/simplesamlphp-module-authX509/?branch=master)
[![Coverage Status](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-authX509/branch/master/graph/badge.svg)](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-authX509)
[![Type Coverage](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-authX509/coverage.svg)](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-authX509)
[![Psalm Level](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-authX509/level.svg)](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-authX509)

Provides an authentication source for SimpleSAMLphp for users to authenticate
by presenting their X.509 client certificate.

Installation
------------

Once you have installed SimpleSAMLphp, installing this module is
very simple.  Just execute the following command in the root of your
SimpleSAMLphp installation:

```
composer.phar require simplesamlphp/simplesamlphp-module-authx509:dev-master
```

where `dev-master` instructs Composer to install the `master` (**development**)
branch from the Git repository. See the
[releases](https://github.com/simplesamlphp/simplesamlphp-module-authx509/releases)
available if you want to use a stable version of the module.

Documentation
-------------

See [docs/authX509.md](https://github.com/simplesamlphp/simplesamlphp-module-authx509/blob/master/docs/authX509.md)
