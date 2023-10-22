# OTP

[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

PHP implementation of [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) and [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238). Generates one-time passwords.

Provides a ready-to-use TOTP generator class for integration with authenticator apps such as Google Authenticator. A second class is also provided for HOTP implementations with custom counters.

## 1 Installation

```sh
composer require covaleski/otp
```

## 2 Usage

All extensions of the `Hotp` class have a `getPassword()` method, which provides the current password based on the counter in use, and a `getUri()` method, which returns the integration URI for authenticator apps.

Use a PHP or JS QR code generator to output the URI as a QR code. I'd recommend the second option to spare the server and make the application faster. However, if you wish to do this job server-side, take a look at [3 Testing](#3-testing).

### 2.1 TOTP and authenticator apps

The `Totp` class provides an instant way to integrate and verify passwords with authenticator apps. It is also possible to set a custom time step and a time offset after instanciating the class.

#### Instanciating

You must provide the following parameters when instanciating the `Totp` class:

  - `$digits`: how many digits the password must have (usually 6 to 8);
  - `$issuer`: name of who's emitting the secret (your company, app, etc.);
  - `$label`: text which will be shown in the authenticator app;
  - `$secret`: a 20-byte unique token for the user.

It is possible to use the `setOffset()` method to change the TOTP generation time offset and `setStep()` (defaults to 0) to change the seconds each step has (defaults to 30 seconds).

```php
$totp = new Totp(
    6,
    'Foobar Co.',
    'Foobar Co.: jonh.doe@foobar.co.uk',
    '____20ByteSecret____',
);

// (optional) Set a custom offset or time step.
$totp
    ->setOffset(300)
    ->setStep(45);
```

#### Verifying a password

```php
// Get the n-digits code sent by the user.
// Example: 032942.
$mfa_code = $_POST['mfa_code'];

// Check the code.
if ($mfa_code !== $totp->getPassword()) {
    // Unauthorized...
}
```

#### Getting the URI.

```php
// Get the URI.
$uri = $totp->getUri();

// Example 1 - Output as a JavaScript constant.
echo <<<HTML
    <script>
        const totpUri = '{$uri}';
        // Use a JS third-party library to make the QR code.
    </script>
    HTML;

// Example 2 - API response.
echo json_encode([
    'totp_uri' => $uri,
]);

// Example 3 - Make the QR code with a third-party PHP library.
$image = \Third\Party\Library::createQR($uri);
$base64 = base64_encode($image);
$data_uri = 'data:image/png;base64,' . $base64;
echo <<<HTML
    <img src="{$data_uri}"/>
    HTML;
```

### 2.2 HOTP and custom counters

If you have a specific counter system you wish to implement between your application and authenticator apps, just extend the `Hotp` class and provide two methods:

- `getCounter()`:
  - Must return the current counter;
  - Counters may be controlled by time, synchronized increments and other methods;
- `getUri()`:
  - Must return a URI containing the integration data;
  - URI parameters may vary according to each implementation;
  - [Google Authenticator](https://github.com/google/google-authenticator/wiki/Key-Uri-Format) format: `otpauth://TYPE/LABEL?PARAMETERS`;
  - TOTP example: `otpauth://totp/Some%20Label?secret=BASE32ENCODEDSECRET&issuer=Some%20Issuer`.

The `Hotp` class will do the rest:

- Generate the HMAC-SHA-1 string;
- Dinamically truncate the HMAC binary string;
- Compute the HOTP value and output the required amount of digits.

```php
class FooOtp extends Hotp
{
    public function getUri(): string
    {}

    protected function getCounter(): string
    {}
}
```

## 3 Testing

Tests were made with PHPUnit. Use the following command to run all of them.

```sh
./vendor/bin/phpunit
```

For integration testing, QR codes are generated and put in `tests/output` using a third-party library. If you wish to use it in production, see [chillerlan/php-qrcode](https://github.com/chillerlan/php-qrcode).
