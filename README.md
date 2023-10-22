# OTP

[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

PHP implementation of [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) and [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238). Generates one-time passwords.

Provides a ready-to-use TOTP generator class for integration with authenticator apps such as Google Authenticator. A second class is also provided for HOTP implementations with custom counters.

## 1 Installation

```sh
composer require covaleski/otp
```

## 2 Usage

All extensions of the `Hotp` class have a `getPassword()` method, which provides the current password based on the generated counter, and a `getUri()` method, which returns a integration URI for authenticator apps.

### 2.1 Note on QR codes

The content of authenticator QR codes is just the OTP URI. You can emit those by passing the value of `getPassword()` to a QR code generator of your choice.

I'd recommend finding a JavaScript library and letting the browser create it so you spare your server and make your application back-end faster. If you wish to do this job server-side, take a look at [3 Testing](#3-testing).

**DO NOT** use external libraries such as Google Charts to generate your QR code! Your URI contains your user's OTP secret and it's a big security gap to send it as a GET variable or rellying in third-party websites to handle it.

### 2.2 TOTP and authenticator apps

The `Totp` class provides an instant way to integrate and verify passwords with authenticator apps.

#### 2.2.1 Instanciating

You must provide the following parameters when instanciating the `Totp` class:

- `int $digits`: how many digits the password must have (usually 6 to 8);
- `string $issuer`: name of who's emitting the secret (your company, app, etc.);
- `string $label`: text which will be shown in the authenticator app;
- `string $secret`: a 20-byte unique token for the user.

It is possible to use the `setOffset()` method to change the TOTP time offset (defaults to 0) and `setStep()` to change the seconds each step has (defaults to 30 seconds).

Note that some implementations may ignore one or more parameters in favor of specific configuration. For example, Google Authenticator ignores offsets and always uses 30 seconds as the time step.

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

#### 2.2.2 Verifying a password

Any sent password can be easily checked using `getPassword()`.

```php
// Get the n-digits code sent by the user.
// Example: 032942.
$auth_code = (string) $_POST['auth_code'];

// Check the code.
if ($auth_code !== $totp->getPassword()) {
    // Unauthorized...
}
```

#### 2.2.3 Getting the URI.

Use `getUri()` to get the OTP URI - it is used to generate the QR codes.

```php
// Get the URI.
$uri = $totp->getUri();
```

### 2.3 HOTP and custom counters

If you have a specific counter system you wish to implement between your application and authenticator apps, just extend the `Hotp` class and provide two methods:

- `protected getCounter(): string`:
  - Must return the current counter;
  - Counters may be controlled by time, synchronized increments and other methods;
- `public getUri(): string`:
  - Must return a URI containing the integration data;
  - URI parameters may vary according to each implementation;
  - The `Hotp` class provide a `createUri()` method to easily create URIs suitable for most authenticator apps;
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
    {
        return get_foo_counter();
    }

    protected function getCounter(): string
    {
        // Build URI.
        return $this->createUri('foootp', [
            'foobar' => 'baz',
            'issuer' => $this->issuer,
            'label' => $this->label,
            'secret' => $this->secret,
        ]);
    }
}
```

## 3 Testing

Tests were made with PHPUnit. Use the following command to run all of them.

```sh
./vendor/bin/phpunit
```

For integration testing, QR codes are generated and put in `tests/output` using a third-party library. If you wish to use it in production, see [chillerlan/php-qrcode](https://github.com/chillerlan/php-qrcode).
