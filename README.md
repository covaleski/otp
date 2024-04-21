# OTP

[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

PHP implementation of [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226.txt) and [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.txt). Generates one-time passwords.

Provides a ready-to-use TOTP class for easy integration with authenticator apps along with an extensible HOTP class for custom one-time password implementations.

## 1 Installation

```sh
composer require covaleski/otp
```

## 2 Usage

### 2.1 TOTP

The `Totp` class can be used to:

- Emit codes;
- Validate received codes;
- Create URIs for QR code generation.

#### 2.1.1 Creating URIs

Authenticator QR codes are just the OTP URIs encoded as a QR code. Follow the steps below to create the URI.

```php
use Covaleski\Otp\Totp;

// Define some settings.
$digits = 6;
$issuer = 'Foobar Inc.';
$label = 'Foobar: john@foobar.com';

// Create a secret.
$secret = '1234';

// Instantiate the TOTP class and get the URI.
$totp = new Totp($digits, $issuer, $label, $secret);
$uri = $totp->getUri();
```

You can output the URI as a QR code using any library of your choice.

#### 2.1.2 Generating and validating codes

Use `getPassword()` to get the current code.

```php
use Covaleski\Otp\Totp;

// Instantiate the TOPT class.
$digits = 6;
$totp = new Totp(6, 'Cool LLC', 'Cool: john@cool.com', $secret);

// Get the current password.
$input = (string) $_POST['code'];
$is_valid = $totp->getPassword() === $input;
echo 'Your code is ' . ($is_valid ? 'correct!' : 'incorrect!');
```

#### 2.1.3 Customizing

You can change several parameters of your generator. The example below creates a TOTP object that:

- Outputs 8-digit codes;
- Change the code every 15 seconds;
- Calculates the code with a time offset of 1 hour.

```php
use Covaleski\Otp\Totp;

// Instantiate and configure.
$totp = new Totp(8, $issuer, $label, $secret);
$totp
    ->setStep(15)
    ->setOffset(3600);
```

Note that some implementations may ignore or even reject one or more custom TOTP parameters. The most compatible configuration (usually) is to generate 6-digit codes every 30 seconds with no time offset.

### 2.2 Custom HOTP implementation

You can extend the `Covaleski\Otp\Hotp` to create your own one-time password implementation.

Extensions must provide two methods: `getCounter()` and `getUri()`. The first one must output the current counter as an 8-byte binary string (e.g. a time counter), and the second is responsible for providing the integration URI.

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
     * Returns the counter as a 8-byte binary string.
     */
    protected function getCounter(): string
    {
        // Get and offset the current UNIX timestamp.
        $time = time() + $this->offset;

        // Calculate the number of steps.
        $counter = floor($time / $this->step);

        // Format the number as an 8-byte binary string.
        $counter = dechex($counter);
        $counter = str_pad($counter, 16, '0', STR_PAD_LEFT);
        $counter = hex2bin($counter);

        return $counter;
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

The `Totp` class depends on time to create its counter and encode its secrets as base32 strings when creating the URI.

## 3 Testing

Tests were made with PHPUnit. Use the following command to run them.

```sh
./vendor/bin/phpunit
```
