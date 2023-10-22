<?php

namespace Covaleski\Otp;

/**
 * Generates HMAC-based one-time passwords.
 * 
 * Implementation of RFC 4226.
 * 
 * @see https://datatracker.ietf.org/doc/html/rfc4226
 */
abstract class Hotp
{
    /**
     * Get the current counter value.
     */
    abstract protected function getCounter(): string;

    /**
     * Get the integration URI.
     * 
     * Necessary to create QR codes.
     */
    abstract protected function getUri(): string;

    /**
     * Stored secret.
     */
    protected string $secret;

    /**
     * Create the HOPT instance.
     */
    public function __construct(
        /** Number of digits the password must contain. */
        protected int $digits,
        /** Authentication issuer. */
        protected string $issuer,
        /** Authentication label. */
        protected string $label,
        /** Secret to combine with the counter and generate passwords. */
        string $secret,
    )
    {
        // Check the secret length and store it.
        if (strlen($secret) !== 20) {
            $msg = 'Secret must be 20-byte long.';
            throw new \InvalidArgumentException($msg);
        }
        $this->secret = $secret;
    }

    /**
     * Generate a new password.
     */
    public function getPassword(): string
    {
        // Step 1 - Generate an HMAC-SHA-1 value.
        $string = $this->getHmacValue();
        // Step 2 - Generate a 4-byte string (Dynamic Truncation).
        $string = $this->truncate($string);
        // Step 3 - Compute an HOTP value.
        $digits = $this->computeDigits($string);

        return $digits;
    }

    /**
     * Transform a trucated binary string into a n-digits password.
     */
    protected function computeDigits(string $string): int
    {
        // Unpack the truncated binary string into a 32-bit integer value.
        $number = (int) unpack('N', $string)[1];

        // Perform the reduction modulo to get the required digits.
        $digits = $number % (10 ** $this->digits);

        return $digits;
    }

    /**
     * Generate an HMAC-SHA-1 value combining the counter value and the secret.
     */
    protected function getHmacValue(): string
    {
        // Get the current counter.
        $counter = $this->getCounter();

        // Generate the HMAC value as a binary string.
        $value = hash_hmac('sha1', $counter, $this->secret, true);

        // Ensure it's 160-bit long.
        if (strlen($value) !== 20) {
            $msg = 'Failed to obtain a 20-byte long HMAC-SHA-1 value.';
            throw new \Exception($msg);
        }
        return $value;
    }

    /**
     * Dynamically truncate a 160-bit HMAC-SHA-1 binary string.
     */
    protected function truncate(string $hmac_value): string
    {
        // Unpack the string bytes as 8-bit integers.
        $bytes = unpack('C20', $hmac_value);

        // Use the string's low-order 4 bits as the offset.
        $offset = $bytes[20] & 0x0f;

        // Extract 4 bytes using the dynamic offset.
        $slice = array_slice($bytes, $offset, 4, false);
        // Mask the most significant bit.
        $slice[0] = $slice[0] & 0x7f;
        
        // Pack the extracted bytes as a binary string again.
        $string = pack('C4', ...$slice);

        return $string;
    }
}
