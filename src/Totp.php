<?php

namespace Covaleski\Otp;

use Covaleski\DataEncoding\Base32;

/**
 * Generates time-based one-time passwords.
 *
 * Implementation of RFC 6238.
 *
 * @see https://www.rfc-editor.org/rfc/rfc6238.txt
 */
class Totp extends Hotp
{
    /**
     * Time step in seconds.
     */
    protected $step = 30;

    /**
     * Time offset in seconds from the Unix epoch.
     */
    protected $offset = 0;

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

    /**
     * Set the offset in seconds.
     */
    public function setOffset(int $seconds): static
    {
        $this->offset = $seconds;

        return $this;
    }

    /**
     * Set time step in seconds for counter generation.
     */
    public function setStep(int $step): static
    {
        $this->step = $step;

        return $this;
    }
}
