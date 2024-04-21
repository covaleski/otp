# OTP

[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

PHP implementation of [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) and [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238). Generates one-time passwords.

Provides a ready-to-use TOTP class for easy integration with authenticator apps along with an extensible HOTP class for custom one-time password implementations.

## 1 Installation

```sh
composer require covaleski/otp
```

## 2 Usage

### 2.1 TOTP

The `Totp` class can be used to fastly integrate your application with authenticator apps, either by validating codes or generating URIs that can be outputted as QR codes to register new accounts.

#### 2.1.1 Example 1: creating URIs

```php
use Covaleski\Otp\Totp;

// Define some settings.
$digits = 6;
$issuer = 'Foobar Inc.';
$label = 'Foobar: john@foobar.com';

// Create a secret.
$secret = '1234';

// Instantiate the TOTP class.
$totp = new Totp($digits, $issuer, $label, $secret);

// Output the URI.
echo $totp->getUri();
```

OTP URI contents are usually outputted as QR codes.

#### 2.1.2 Example 2: generating codes

```php
use Covaleski\Otp\Totp;

// Instantiate the TOPT class like the first example.
$totp = new Totp($digits, $issuer, $label, $secret);

// Get the current password.
echo 'Your current code is ' . $totp->getPassword();
```

#### 2.1.3 Example 3: validating codes

```php
use Covaleski\Otp\Totp;

// Instantiate the TOPT class like the first example.
$totp = new Totp($digits, $issuer, $label, $secret);

// Get the code sent by the user.
$password = $_POST['code'];

// Compare codes.
if ($password === $totp->getPassword()) {
    echo 'Authenticated successfully!';
} else {
    echo 'Invalid code.';
}
```

#### 2.1.4 Example 4: customizing

The example below creates a TOTP object that:

- Outputs 8-digit codes;
- Change the code every 15 seconds;
- Calculates the code with a time offset of 1 hour.

```php
use Covaleski\Otp\Totp;

// Define settings.
$digits = 8;
$issuer = 'My Store Co.';
$label = 'My Store: michael@foomail.net';
$secret = 'SomeRandomGeneratedSecret1234';

// Instantiate and configure.
$totp = new Totp($digits, $issuer, $label, $secret);
$totp
    ->setStep(15)
    ->setOffset(3600);
```

Note that some implementations may ignore one or more URI parameters, and might even reject URIs that contain unsupported options.

For wider compatibility, you might want to use 6-digit codes with 30 seconds steps (default).

### 2.2 Custom HOTP implementation

You can extend the `Covaleski\Otp\Hotp` to create your own one-time password implementation.

Extensions must provide two methods: `getCounter()` and `getUri()`. The first one must output the current counter as a binary string (e.g. a time counter), and the second is responsible for providing the integration URI.

Counters may depend on time, synchronized increments or other approaches (it's up to you), while URIs are necessary so you can generate QR codes for authenticator apps.

If you opt to set your OTP accounts manually in those apps (without QR codes), you must always insert your secrets as base32 encoded strings.

Furthermore, the `Hotp` class will do the rest and:

- Generate the HMAC-SHA-1 string;
- Dinamically truncate the HMAC binary string;
- Compute the HOTP value and output the required amount of digits.

See how the methods are implemented in the `Covaleski\Otp\Totp` class:

```php
class Totp extends Hotp
{
    // ...Other class members...

    /**
     * Get the current time counter.
     *
     * Returns the counter as a 16-byte binary string.
     */
    protected function getCounter(): string
    {
        // Get and offset the current UNIX timestamp.
        $time = time() + $this->offset;
        // Calculate the number of steps.
        $counter = floor($time / $this->step);

        // Format for HMAC value generation.
        $counter = dechex($counter);
        $counter = str_pad($counter, 16, '0', STR_PAD_LEFT);

        return hex2bin($counter);
    }

    /**
     * Get the URI for authentication apps.
     */
    public function getUri(): string
    {
        // Encode the secret as base32.
        $secret = Base32::encode($this->secret);
        $secret = str_replace('=', '', $secret);

        // Build URI.
        return $this->createUri('totp', [
            'secret' => $secret,
            'issuer' => $this->issuer,
            'algorithm' => 'SHA1',
            'digits' => $this->digits,
            'period' => $this->step,
        ]);
    }

    // ...Other class members...
}
```

## 3 Testing

Tests were made with PHPUnit. Use the following command to run them.

```sh
./vendor/bin/phpunit
```
