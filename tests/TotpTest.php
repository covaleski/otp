<?php

use chillerlan\QRCode\{QRCode, QROptions};
use Covaleski\DataEncoding\Base32;
use Covaleski\Otp\Totp;
use PHPUnit\Framework\TestCase;

/**
 * Tests the Time-based One-time Password.
 */
class TotpTest extends TestCase
{
    /**
     * Test if the TOTP class can generate passwords under different secrets.
     */
    public function testCanGeneratePasswordAndUri(): void
    {
        // Generate secrets.
        $secrets = $this->createSecrets(2);        

        // Create debug output folder.
        $path = __DIR__ . '/output';
        $prefix = 'totp-test-' . time() . '-';
        $path .= '/' . str_replace('.', '-', uniqid($prefix, true));
        mkdir($path);

        // Generate passwords and URLs.
        $qr_options = new QROptions();
        $qr_options->imageTransparent = false;
        $qr_code = new QRCode($qr_options);
        foreach ($secrets as $i => $secret) {
            // Create TOPT object.
            $issuer = 'Issuer ' . chr(ord('A') + $i);
            $domain = strtolower(str_replace(' ', '-', $issuer));
            $label = "{$issuer}: jonh.doe@{$domain}.com";
            $totp = new Totp(6, $issuer, $label, $secret);
            // Test password and URI generation.
            $this->assertIsNumeric($totp->getPassword());
            $uri = $totp->getUri();
            $this->assertNotEmpty($uri);
            // Create passwords with different offsets for testing.
            $passwords = [];
            for ($j = 0; $j <= 300; $j += 30) {
                $str = $j > 0 ? "+{$j} seconds" : 'now';
                $key = date('Y-m-d H:i:s', strtotime($str));
                $passwords[$key] = $totp->setOffset($j)->getPassword();
            }
            // Emit files for authenticator testing.
            $data = [
                'label' => $label,
                'issuer' => $issuer,
                'uri' => $uri,
                'secret' => [
                    'base16' => bin2hex($secret),
                    'base32' => Base32::encode($secret),
                    'base64' => base64_encode($secret),
                ],
                'passwords' => $passwords,
            ];
            $data = json_encode($data, JSON_PRETTY_PRINT);
            file_put_contents("{$path}/{$i}-data.json", $data);
            $qr_code->render($uri, "{$path}/{$i}-qr-code.png");
        }
    }

    /**
     * Create a list of random binary secrets.
     */
    protected function createSecrets(int $count): array
    {
        // Generate random 20-byte secrets.
        $passwords = [];
        for ($i = 0; $i < $count; $i++) {
            $password = [];
            for ($j = 0; $j < 20; $j++) {
                $password[] = random_int(0, 255);
            }
            $passwords[] = pack('C*', ...$password);
        }

        return $passwords;
    }
}