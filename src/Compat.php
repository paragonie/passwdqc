<?php
declare(strict_types=1);
namespace ParagonIE\Passwdqc;
use ParagonIE\ConstantTime\Binary;

/**
 * Class Compat
 *
 * This class aims to be mostly API compatible with the original C
 * implementation of passwdqc.
 *
 * @package ParagonIE\Passwdqc
 */
abstract class Compat
{
    use WordList;

    const F_ENFORCE_MASK =         0x00000003;
    const F_ENFORCE_USERS =        0x00000001;
    const F_ENFORCE_ROOT =         0x00000002;
    const F_ENFORCE_EVERYONE =     self::F_ENFORCE_MASK;
    const F_NON_UNIX =             0x00000004;
    const F_ASK_OLDAUTHOK_MASK =   0x00000030;
    const F_ASK_OLDAUTHOK_PRELIM = 0x00000010;
    const F_ASK_OLDAUTHOK_UPDATE = 0x00000020;
    const F_CHECK_OLDAUTHOK =      0x00000040;
    const F_USE_FIRST_PASS =       0x00000100;
    const F_USE_AUTHTOK =          0x00000200;
    const PASSWDQC_VERSION =       '1.3.1';

    const REASON_ERROR = 'check failed';
    const REASON_SAME = 'is the same as the old one';
    const REASON_SIMILAR = 'is based on the old one';
    const REASON_SHORT = 'too short';
    const REASON_LONG = 'too long';
    const REASON_SIMPLESHORT = 'not enough different characters or classes for this length';
    const REASON_SIMPLE = 'not enough different characters or classes';
    const REASON_PERSONAL = 'based on personal login information';
    const REASON_WORD = 'based on a dictionary word and not a passphrase';
    const REASON_SEQ = 'based on a common sequence of characters and not a passphrase';

    const FIXED_BITS = 15;

    /**
     * @var string
     */
    protected static $lastReason;

    /**
     * @var string[]
     */
    protected static $seq = [
        "0123456789",
        "`1234567890-=",
        "~!@#$%^&*()_+",
        "abcdefghijklmnopqrstuvwxyz",
        "a1b2c3d4e5f6g7h8i9j0",
        "1a2b3c4d5e6f7g8h9i0j",
        "abc123",
        "qwertyuiop[]\\asdfghjkl;'zxcvbnm,./",
        "qwertyuiop{}|asdfghjkl:\"zxcvbnm<>?",
        "qwertyuiopasdfghjklzxcvbnm",
        "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/-['=]\\",
        "!qaz@wsx#edc\$rfv%tgb^yhn&ujm*ik<(ol>)p:?_{\"+}|",
        "qazwsxedcrfvtgbyhnujmikolp",
        "1q2w3e4r5t6y7u8i9o0p-[=]",
        "q1w2e3r4t5y6u7i8o9p0[-]=\\",
        "1qaz1qaz",
        "1qaz!qaz", /* can't unify '1' and '!' - see comment in unify() */
        "1qazzaq1",
        "zaq!1qaz",
        "zaq!2wsx"
    ];

    /**
     * Overloadable. Gets the default passwdqc parameters.
     *
     * @return Params
     */
    protected static function getDefaultParams(): Params
    {
        return new Params();
    }

    /**
     * Get the reason the last password was rejected.
     *
     * @return string
     */
    public static function getLastReason(): string
    {
        return self::$lastReason;
    }

    /**
     * Calculates the expected number of different characters for a random
     * password of a given length.  The result is rounded down.  We use this
     * with the _requested_ minimum length (so longer passwords don't have
     * to meet this strict requirement for their length).
     *
     * @param int $charset
     * @param int $length
     * @return int
     */
    public static function expected_different(int $charset, int $length): int
    {
        $x = ($charset - 1) << self::FIXED_BITS / $charset;
        $y = $x;
        while (--$length > 0) {
            $y = ($y * $x) >> self::FIXED_BITS;
        }
        $z = $charset * 1 << (self::FIXED_BITS - $y);
        return (int) ($z >> self::FIXED_BITS);
    }

    /**
     * Needle is based on haystack if both contain a long enough common
     * substring and needle would be too simple for a password with the
     * substring either removed with partial length credit for it added
     * or partially discounted for the purpose of the length check.
     *
     * @param Params|null $params
     * @param string $haystack
     * @param string $needle
     * @param string $original
     * @param int $mode
     * @return bool
     */
    public static function is_based(
        Params $params = null,
        string $haystack = '',
        string $needle = '',
        string $original = '',
        int $mode = 0
    ): bool {
        if ($params === null) {
            $params = static::getDefaultParams();
        }
        if ($params->getMatch() === 0) {
            return false;
        }
        if ($params->getMatch() < 0) {
            return true;
        }
        $length = Binary::safeStrlen($needle);
        $bias = 0;
        $worst_bias = 0;

        // Begin the loop:
        for ($i = 0; $i <= $length - $params->getMatch(); ++$i) {
            for ($j = $params->getMatch(); $i + $j <= $length; ++$j) {
                $bias = 0;
                $j1 = $j - 1;
                $q0 = $needle[$i];
                $q1 = Binary::safeSubstr($needle, $i + 1);

                /* Next 3 lines: for (p = haystack; *p; p++) */
                $haystack_len = Binary::safeStrlen($haystack);
                for ($k = 0; $k < $haystack_len; ++$k) {
                    $p = Binary::safeSubstr($haystack, $k);

                    /* if (*p == q0 && !strncmp(p + 1, q1, j1)) { */
                    if ($p[0] === $q0
                            &&
                        \strncmp(
                            Binary::safeSubstr($p, 1),
                            $q1,
                            $j1
                        ) === 0
                    ) {
                        if (($mode & 0xff) === 0) {
                            /* remove j chars */
                            $pos = $length - ($i + $j);
                            /* not reversed */
                            if (!($mode & 0x100)) {
                                $pos = $i;
                            }
                            $scratch = Binary::safeSubstr(
                                    $original,
                                    0,
                                    $pos
                                ) . Binary::safeSubstr(
                                    $original,
                                    ($pos + $j),
                                    ($length + 1 - ($pos + $j))
                                );
                            /* add credit for match_length - 1 chars */
                            $bias = $params->getMatch() - 1;
                            if (self::is_simple($params, $scratch, $bias, $bias)) {
                                return true;
                            }
                        } else {
                            /* discount */
                            /* Require a 1 character longer match for substrings containing leetspeak
                             * when matching against dictionary words */
                            $bias = -1;
                            /* words */
                            if (($mode & 0xff) === 1) {
                                $pos = $i;
                                $end = $i + $j;
                                /* reversed */
                                if (($mode & 0x100) > 0) {
                                    $pos = $length - $end;
                                    $end = $length - $i;
                                }
                                for (; $pos < $end; ++$pos) {
                                    if (!\ctype_alpha($original[$pos])) {
                                        if ($j === $params->getMatch()) {
                                            continue 3;
                                        }
                                        $bias = 0;
                                    }
                                }
                            }

                            /* discount j - (match_length + bias) chars */
                            $bias += $params->getMatch() - $j;
                            /* bias <= -1 */
                            if ($bias < $worst_bias) {
                                if (self::is_simple(
                                    $params,
                                    $original,
                                    $bias,
                                    (($mode & 0xff) === 1 ? 0 : $bias)
                                )) {
                                    return false;
                                }
                            }
                        }
                    }
                }
            }
            /* Zero bias implies that there were no matches for this length.  If so,
             * there's no reason to try the next substring length (it would result in
             * no matches as well).  We break out of the substring length loop and
             * proceed with all substring lengths for the next position in needle. */
            if ($bias === 0) {
                break;
            }
        }
        return false;
    }

    /**
     * A password is too simple if it is too short for its class, or doesn't
     * contain enough different characters for its class, or doesn't contain
     * enough words for a passphrase.
     *
     * The biases are added to the length, and they may be positive or negative.
     * The passphrase length check uses passphrase_bias instead of bias so that
     * zero may be passed for this parameter when the (other) bias is non-zero
     * because of a dictionary word, which is perfectly normal for a passphrase.
     * The biases do not affect the number of different characters, character
     * classes, and word count.
     *
     * @param Params|null $params
     * @param string $newPassword
     * @param int $bias
     * @param int $passphraseBias
     * @return bool
     */
    public static function is_simple(
        Params $params = null,
        string $newPassword = '',
        int $bias = 0,
        int $passphraseBias = 0
    ): bool {
        if ($params === null) {
            $params = static::getDefaultParams();
        }
        $length = Binary::safeStrlen($newPassword);
        if ($length < 1) {
            return true;
        }

        $words = $chars = 0;
        $p = '';

        $digits = $lowers = $uppers = $others = $unknowns = 0;

        for ($i = 0; $i < $length; ++$i) {
            $c = $newPassword[$i];
            if (!self::is_ascii($c)) {
                ++$unknowns;
            } elseif (\ctype_digit($c)) {
                ++$digits;
            } elseif (\ctype_lower($c)) {
                ++$lowers;
            } elseif (\ctype_upper($c)) {
                ++$uppers;
            } else {
                ++$others;
            }

            if (self::is_ascii($p)) {
                if (self::is_ascii($c)) {
                    if (\ctype_alpha($c) && !\ctype_alpha($p)) {
                        ++$words;
                    }
                } elseif (\ctype_space($p)) {
                    ++$words;
                }
            }
            $p = $c;

            if (!\strchr(Binary::safeSubstr($newPassword, $i), $c)) {
                ++$chars;
            }
        }
        $classes = 0;
        if (!empty($digits)) {
            ++$classes;
        }
        if (!empty($lowers)) {
            ++$classes;
        }
        if (!empty($uppers)) {
            ++$classes;
        }
        if (!empty($others)) {
            ++$classes;
        }
        if ($unknowns && $classes <= 1 && (!$classes || $digits || $words >= 2)) {
            ++$classes;
        }
        for (; $classes > 0; --$classes) {
            switch ($classes) {
                case 4:
                    if (
                        $length + $bias >= $params->getMin(4)
                            &&
                        $chars >= self::expected_different(95, $params->getMin(4) - 1)
                    ) {
                        return true;
                    }
                    break;

                case 3:
                    if (
                        $length + $bias >= $params->getMin(4)
                        &&
                        $chars >= self::expected_different(62, $params->getMin(4) - 1)
                    ) {
                        return true;
                    }
                    break;

                case 2:
                    if (
                        $length + $bias >= $params->getMin(1)
                            &&
                        $chars >= self::expected_different(36, $params->getMin(1) - 1)
                    ) {
                        return true;
                    }
                    if (!$params->getPassphrase() || $words < $params->getPassphrase()) {
                        break;
                    }
                    if ($length + $passphraseBias >= $params->getMin(2)
                        &&
                        $chars >= self::expected_different(27, $params->getMin(2) - 1)
                    ) {
                        return true;
                    }

                    break;

                case 1:
                    return (
                        $length + $bias >= $params->getMin(0)
                            &&
                        $chars >= self::expected_different(10, $params->getMin(0) - 1)
                    );
            }
        }
        return false;
    }

    /**
     * @param Params|null $params
     * @param string $needle
     * @param string $original
     * @param bool $isReversed
     * @return bool
     */
    public static function is_word_based(
        Params $params = null,
        string $needle = '',
        string $original = '',
        bool $isReversed = false
    ): bool {
        if (empty($params)) {
            $params = static::getDefaultParams();
        }
        if ($params->getMatch() === 0) {
            return false;
        }
        $mode = $isReversed ? 0x0101 : 0x0001;

        // Reject based on wordlist:
        foreach (self::$wordList as $word) {
            if (self::is_based($params, $word, $needle, $original, $mode)) {
                return !self::reject(self::REASON_WORD);
            }
        }

        // Reject sequences:
        $mode = $isReversed ? 0x0102 : 0x0002;
        for ($i = 0; $i < \count(self::$seq); ++$i) {
            $unified = self::unify(self::$seq[$i]);
            if (self::is_based($params, $unified, $needle, $original, $mode)) {
                return !self::reject(self::REASON_SEQ);
            }
        }

        // Reject birth years:
        if ($params->getMatch() <= 4) {
            for ($i = 1900; $i <= 2039; ++$i) {
                if (self::is_based($params, (string) $i, $needle, $original, $mode)) {
                    return !self::reject(self::REASON_SEQ);
                }
            }
        }
        return false;
    }

    /**
     * Perform a passwdqc check. This is more-or-less compatible with the C
     * API.
     *
     * @param Params|null $params
     * @param string $newPassword
     * @param string $oldPassword
     * @param UserInformation|null $pw
     * @return bool
     */
    public static function passwdqc_check(
        Params $params = null,
        string $newPassword = '',
        string $oldPassword = '',
        UserInformation $pw = null
    ): bool {
        if ($params === null) {
            $params = static::getDefaultParams();
        }
        $length = Binary::safeStrlen($newPassword);

        if ($length < $params->getMin(4)) {
            return self::reject(self::REASON_SHORT);
        }

        if ($length > 10000) {
            return self::reject(self::REASON_LONG);
        }

        if ($length > $params->getMax()) {
            if ($params->getMax() === 8) {
                // Compatibility with old DES-based crypt():
                $newPassword = Binary::safeSubstr($newPassword, 0, 8);
                $length = 8;
                if ($oldPassword && \strncmp($newPassword, $oldPassword, 8) !== 0) {
                    return self::reject(self::REASON_SAME);
                }
            } else {
                return self::reject(self::REASON_LONG);
            }
        }

        if ($oldPassword && \hash_equals($newPassword, $oldPassword)) {
            return self::reject(self::REASON_SAME);
        }

        if (static::is_simple($params, $newPassword, 0, 0)) {
            if (
                $length < $params->getMin(1)
                    &&
                $params->getMin(1) <= $params->getMax()
            ) {
                return self::reject(self::REASON_SIMPLESHORT);
            }
            return self::reject(self::REASON_SIMPLE);
        }

        $u_newpass = self::unify($newPassword);
        $u_reversed = \strrev($u_newpass);
        if ($oldPassword && $params->getSimilarDeny()) {
            $u_oldpass = self::unify($oldPassword);

            if (
                self::is_based($params, $u_oldpass, $u_newpass, $newPassword, 0)
                    ||
                self::is_based($params, $u_oldpass, $u_reversed, $newPassword, 0x100)
            ) {
                return self::reject(self::REASON_SIMILAR);
            }
        }

        if ($pw instanceof UserInformation) {
            $u_name = self::unify($pw->getName());
            $u_gecos = self::unify($pw->getGecos());
            $u_dir = self::unify($pw->getDir());

            if (
                self::is_based($params, $u_name, $u_newpass, $newPassword, 0)
                    ||
                self::is_based($params, $u_name, $u_reversed, $newPassword, 0x100)
                    ||
                self::is_based($params, $u_gecos, $u_newpass, $newPassword, 0)
                    ||
                self::is_based($params, $u_gecos, $u_reversed, $newPassword, 0x100)
                    ||
                self::is_based($params, $u_dir, $u_newpass, $newPassword, 0)
                    ||
                self::is_based($params, $u_dir, $u_reversed, $newPassword, 0x100)
            ) {
                return self::reject(self::REASON_PERSONAL);
            }
        }

        $isWordBased = self::is_word_based(
            $params,
            $u_newpass,
            $newPassword
        );
        if (!$isWordBased) {
            // Let's also check the reverse:
            $isWordBased = self::is_word_based(
                $params,
                $u_reversed,
                $newPassword,
                true
            );
        }
        return !$isWordBased;
    }

    /**
     * Set the last rejection reason, then return false.
     *
     * @param string $reason
     * @return bool
     */
    protected static function reject(string $reason): bool
    {
        self::$lastReason = $reason;
        return false;
    }

    /**
     * @param string $source
     * @return string
     */
    public static function unify(string $source): string
    {
        $dst = '';
        $length = Binary::safeStrlen($source);
        for ($i = 0; $i < $length; ++$i) {
            $c = \strtolower($source[$i]);
            switch ($c) {
                case 'a':
                case '@':
                    $dst .= '4';
                    break;
                case 'e':
                    $dst .= '3';
                    break;
                /* Unfortunately, if we translate both 'i' and 'l' to '1', this would
                 * associate these two letters with each other - e.g., "mile" would
                 * match "MLLE", which is undesired.  To solve this, we'd need to test
                 * different translations separately, which is not implemented yet. */
                case 'i':
                case '|':
                    $dst .= '!';
                    break;
                case 'l':
                    $dst .= '1';
                    break;
                case 'o':
                    $dst .= '0';
                    break;
                case 's':
                case '$':
                    $dst .= '5';
                    break;
                case 't':
                case '+':
                    $dst .= '7';
                    break;
                default:
                    $dst .= $c;
            }
        }
        return $dst;
    }


    /**
     * @param string $c
     * @return bool
     */
    public static function is_ascii(string $c): bool
    {
        if (Binary::safeStrlen($c) < 1) {
            return false;
        }
        $chunk = \unpack('C', $c);
        return $chunk[1] >= 0 && $chunk[1] <= 127;
    }
}
