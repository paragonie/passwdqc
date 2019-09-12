<?php
declare(strict_types=1);
namespace ParagonIE\Passwdqc;

/**
 * Class Params
 *
 * Not supported (due to no PAM integration):
 *
 * - random
 * - enforce
 * - retry
 *
 * @package ParagonIE\Passwdqc
 */
class Params
{
    /**
     * The minimum allowed password lengths for different kinds of
     * passwords/passphrases.
     *
     * @var int[]
     */
    protected $min = [
        PHP_INT_MAX,
        24,
        11,
        8,
        7
    ];

    /**
     * The maximum allowed password length.
     *
     * This can be used to prevent users from setting passwords that may be too
     * long for some system services.
     *
     * The value 8 is treated specially: if max is set to 8, passwords longer
     * than 8 characters will not be rejected, but will be truncated to 8
     * characters for the strength checks and the user will be warned.
     *
     * This is to be used with the traditional DES-based password hashes,
     * which truncate the password at 8 characters.
     *
     * It is important that you do set max = 8 if you are using the traditional
     * hashes, or some weak passwords will pass the checks.
     *
     * @var int
     */
    protected $max = 40;

    /**
     * The number of words required for a passphrase, or 0 to disable the support
     * for user-chosen passphrases.
     *
     * @var int
     */
    protected $passphrase = 3;

    /**
     * The length of common substring required to conclude that a password is
     * at least partially based on information found in a character string,
     * or 0 to disable the substring search.
     *
     * Note that the password will not be rejected once a weak substring is
     * found; it will instead be subjected to the usual strength requirements
     * with the weak substring partially discounted.
     *
     * The substring search is case-insensitive and is able to detect and
     * remove a common substring spelled backwards.
     *
     * @var int
     */
    protected $match = 4;

    /**
     * Whether a new password is allowed to be similar to the old one.
     *
     * The passwords are considered to be similar when there is a sufficiently
     * long common substring and the new password with the substring partially
     * discounted would be weak.
     *
     * @var string ('permit', 'deny')
     */
    protected $similar = 'deny';

    /**
     * @return int
     */
    public function getMatch(): int
    {
        return $this->match;
    }

    /**
     * @return int
     */
    public function getMax(): int
    {
        return $this->max;
    }

    /**
     * @param int $offset
     * @return int
     */
    public function getMin(int $offset = 0): int
    {
        if ($offset < 0 || $offset > 4) {
            throw new \RangeException('Offset is out of range. Must be between 0 and 4.');
        }
        return $this->min[$offset];
    }

    /**
     * @return int
     */
    public function getPassphrase(): int
    {
       return $this->passphrase;
    }

    /**
     * @return string
     */
    public function getSimilar(): string
    {
        return $this->similar;
    }

    /**
     * @return bool
     */
    public function getSimilarDeny(): bool
    {
        return $this->similar === 'deny';
    }

    /**
     * Set the minimum values in one go.
     *
     * @param array $min
     * @return Params
     * @throws \Exception
     * @throws \RangeException
     */
    public function setMin(array $min): self
    {
        $min = \array_values($min);
        if (\count($min) !== 5) {
            throw new \Exception('Minimum values must contain 5 elements');
        }
        if (\count($min, \COUNT_RECURSIVE) !== 5) {
            throw new \Exception('Minimum values must contain 5 elements');
        }
        for ($i = 0; $i < 5; ++$i) {
            if ($min[$i] === null) {
                $min[$i] = PHP_INT_MAX;
            } elseif (\is_numeric($min[$i])) {
                $min[$i] = (int) $min[$i];
            } else {
                throw new \Exception('Minimum values must only contain integers.');
            }
            if ($min[$i] < 0) {
                throw new \RangeException('Value must be a positive integer.');
            }
            if ($i > 0 && $min[$i] < $min[$i - 1]) {
                throw new \RangeException(
                    'Each subsequent number is required to be no larger than the preceding one.'
                );
            }
        }
        $this->min = $min;
        return $this;
    }

    /**
     * Sets a particular minimum value.
     *
     * @param int $value
     * @param int $offset
     * @return Params
     * @throws \RangeException
     */
    public function setMinValue(int $value, int $offset): self
    {
        if ($offset < 0 || $offset > 4) {
            throw new \RangeException('Offset is out of range. Must be between 0 and 4.');
        }
        if ($value < 0) {
            throw new \RangeException('Value must be a positive integer.');
        }
        $this->min[$offset] = $value;
        return $this;
    }

    /**
     * Sets the maximum length for passwords to be evaluated.
     *
     * @param int $max
     * @return Params
     */
    public function setMax(int $max): self
    {
        if ($max < 0) {
            throw new \RangeException('Value must be a positive integer.');
        }
        $this->max = $max;
        return $this;
    }

    /**
     * Set the minimum number of words in a passphrase.
     *
     * @param int $passphrase
     * @return Params
     */
    public function setPassphrase(int $passphrase): self
    {
        if ($passphrase < 0) {
            throw new \RangeException('Value must be a positive integer.');
        }
        $this->passphrase = $passphrase;
        return $this;
    }

    /**
     * @param int $match
     * @return Params
     */
    public function setMatch(int $match): self
    {
        if ($match < 0) {
            throw new \RangeException('Value must be a positive integer.');
        }
        $this->match = $match;
        return $this;
    }

    /**
     * @param string $similar
     * @return Params
     * @throws \Exception
     */
    public function setSimilar(string $similar): self
    {
        switch ($similar) {
            case 'permit':
            case 'deny':
                $this->similar = $similar;
                break;
            default:
                throw new \Exception('Invalid similar parameter');
        }
        return $this;
    }
}
