<?php
declare(strict_types=1);
namespace ParagonIE\Passwdqc;

/**
 * Class Passwdqc
 *
 * This class extends the compatibility layer and offers a simpler
 * interface for PHP developers to grasp.
 *
 * @package ParagonIE\Passwdqc
 */
final class Passwdqc extends Compat
{

    /**
     * @var Params
     */
    protected $params;
    
    /**
     * Passwdqc constructor.
     */
    public function __construct(Params $params = null)
    {
        if ($params === null) {
            $params = static::getDefaultParams();
        }
        $this->params = $params;
    }

    /**
     * Simplified API for passwdqc
     *
     * @param string $newPassword
     * @param string $oldPassword
     * @param UserInformation|null $pw
     * @return bool
     */
    public function check(
        string $newPassword,
        string $oldPassword = '',
        UserInformation $pw = null
    ): bool {
        return static::passwdqc_check(
            $this->params,
            $newPassword,
            $oldPassword,
            $pw
        );
    }
}
