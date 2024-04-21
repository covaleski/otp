<?php

namespace Tests;

use Covaleski\Otp\Totp;
use PHPUnit\Framework\TestCase;

/**
 * @coversDefaultClass \Covaleski\Otp\Totp
 */
final class TotpTest extends TestCase
{
    /**
     * Provides TOTP valid configurations.
     */
    protected function validConfigProvider(): array
    {
        return [
            // Test a 20-byte password with classic settings.
            [
                // Configuration:
                [
                    'secret' => 'foofoofoofoofoofoooo',
                    'issuer' => 'Foobar Inc.',
                    'label' => 'Foobar: john@foobar.com',
                    'digits' => 6,
                    'step' => null,
                    'offset' => null,
                ],
                // Expected URI:
                'otpauth://totp/Foobar%3A%20john%40foobar.com'
                    .'?secret=MZXW6ZTPN5TG633GN5XWM33PMZXW633P'
                    .'&issuer=Foobar%20Inc.'
                    .'&algorithm=SHA1'
                    .'&digits=6'
                    .'&period=30',
                // Expected codes:
                [
                    '1713657790' => '692918', // 2024-04-21 00:03:10 UTC
                    '1713657820' => '702856', // 2024-04-21 00:03:40 UTC
                    '1713657850' => '289358', // 2024-04-21 00:04:10 UTC
                    '1713657880' => '675511', // 2024-04-21 00:04:40 UTC
                    '1713657910' => '796899', // 2024-04-21 00:05:10 UTC
                    '1713657940' => '234109', // 2024-04-21 00:05:40 UTC
                ],
            ],
            // Test a longer password with more digits and a shorter step.
            [
                // Configuration:
                [
                    'secret' => 'Very_Very#Long@Password98765432123456789!WowSoSecure',
                    'issuer' => 'Hello World Co.',
                    'label' => 'Hello World: mary@helloworld.com',
                    'digits' => 8,
                    'step' => 15,
                    'offset' => null,
                ],
                // Expected URI:
                'otpauth://totp/Hello%20World%3A%20mary%40helloworld.com'
                    .'?secret=KZSXE6K7KZSXE6JDJRXW4Z2AKBQXG43XN5ZGIOJYG43DKNBTGIYTEMZUGU3DOOBZEFLW652TN5JWKY3VOJSQ'
                    .'&issuer=Hello%20World%20Co.'
                    .'&algorithm=SHA1'
                    .'&digits=8'
                    .'&period=15',
                // Expected codes:
                [
                    '1713663125' => '57880942', // 2024-04-21 01:32:05 UTC
                    '1713663140' => '42277421', // 2024-04-21 01:32:20 UTC
                    '1713663155' => '24756955', // 2024-04-21 01:32:35 UTC
                    '1713663170' => '54462549', // 2024-04-21 01:32:50 UTC
                    '1713663185' => '66337917', // 2024-04-21 01:33:05 UTC
                    '1713663200' => '86410188', // 2024-04-21 01:33:20 UTC
                ],
            ],
            // Test a short password with 1 digit, larger steps and an offset.
            // This would be a very unsecure option.
            [
                // Configuration:
                [
                    'secret' => '9',
                    'issuer' => 'So Secure LLC',
                    'label' => 'So Secure: mitchel@secure123.net',
                    'digits' => 1,
                    'step' => 60,
                    'offset' => 3600,
                ],
                // Expected URI:
                'otpauth://totp/So%20Secure%3A%20mitchel%40secure123.net'
                    .'?secret=HE'
                    .'&issuer=So%20Secure%20LLC'
                    .'&algorithm=SHA1'
                    .'&digits=1'
                    .'&period=60',
                // Expected codes:
                [
                    '1713661985' => '4', // 2024-04-21 01:13 UTC
                    '1713662045' => '7', // 2024-04-21 01:14 UTC
                    '1713662105' => '2', // 2024-04-21 01:15 UTC
                    '1713662165' => '7', // 2024-04-21 01:16 UTC
                    '1713662225' => '6', // 2024-04-21 01:17 UTC
                    '1713662285' => '0', // 2024-04-21 01:18 UTC
                ],
            ],
            // Test password padding.
            [
                // Configuration:
                [
                    'secret' => '123456789',
                    'issuer' => 'Test Inc.',
                    'label' => 'Test: michael@test.com',
                    'digits' => 6,
                    'step' => '5',
                    'offset' => null,
                ],
                // Expected URI:
                'otpauth://totp/Test%3A%20michael%40test.com'
                    .'?secret=GEZDGNBVGY3TQOI'
                    .'&issuer=Test%20Inc.'
                    .'&algorithm=SHA1'
                    .'&digits=6'
                    .'&period=5',
                // Expected codes:
                [
                    '1713707647' => '065886', // 2024-04-21 13:54:07 UTC
                ],
            ],
        ];
    }

    /**
     * @covers ::__construct
     * @covers ::computeDigits
     * @covers ::createUri
     * @covers ::getCounter
     * @covers ::getHmacValue
     * @covers ::getPassword
     * @covers ::getUri
     * @covers ::truncate
     * @covers ::setOffset
     * @covers ::setStep
     *
     * @dataProvider validConfigProvider
     */
    public function testCanGenerateUriAndPasswords(
        array $config,
        string $expected_uri,
        array $expected_passwords,
    ): void {
        // Create TOTP object.
        $totp = new Totp(
            $config['digits'],
            $config['issuer'],
            $config['label'],
            $config['secret'],
        );

        // Set step and offset.
        if (isset($config['step'])) {
            $totp->setStep($config['step']);
        }
        if (isset($config['offset'])) {
            $totp->setOffset($config['offset']);
        }

        // Check URI.
        $this->assertSame($expected_uri, $totp->getUri());

        // Check passwords.
        foreach ($expected_passwords as $timestamp => $password) {
            Timestamp::$value = (int) $timestamp;
            $this->assertSame($password, $totp->getPassword());
        }
    }

    /**
     * @covers ::__construct
     */
    public function testMustUseNonEmptyPasswords(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Totp(6, 'My Company', 'MC: john@mycompany.com', '');
    }
}

/**
 * Stores a custom timestamp for testing purposes.
 */
class Timestamp
{
    /**
     * Timestamp in use.
     */
    public static int $value = 0;
}

namespace Covaleski\Otp;

/**
 * Return a custom timestamp for testing purposes.
 */
function time(): int
{
    return \Tests\Timestamp::$value;
}
