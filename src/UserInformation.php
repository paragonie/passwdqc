<?php
declare(strict_types=1);
namespace ParagonIE\Passwdqc;

/**
 * Class UserInformation
 *
 * Encapsulates user information, such as what's provided by /etc/passwd
 *
 * @package ParagonIE\Passwdqc
 */
class UserInformation
{
    /**
     * @var string
     */
    protected $name;

    /**
     * @var string
     */
    protected $gecos;

    /**
     * @var string
     */
    protected $dir;

    /**
     * UserInformation constructor.
     *
     * @param string $name
     * @param string $gecos
     * @param string $dir
     */
    public function __construct(
        string $name,
        string $gecos = '',
        string $dir = ''
    ) {
        $this->name = $name;
        $this->gecos = $gecos;
        $this->dir = $dir;
    }

    /**
     * @return string
     */
    public function getDir(): string
    {
        return $this->dir;
    }

    /**
     * @return string
     */
    public function getGecos(): string
    {
        return $this->gecos;
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }
}
