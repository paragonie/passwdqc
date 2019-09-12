<?php
declare(strict_types=1);
namespace ParagonIE\Passwdqc\Tests;

use ParagonIE\Passwdqc\Passwdqc;
use PHPUnit\Framework\TestCase;

/**
 * Class PasswdqcTest
 * @package ParagonIE\Passwdqc\Tests
 */
class PasswdqcTest extends TestCase
{

    public function testCheck()
    {
        $passwdqc = new Passwdqc();

        $this->assertTrue(
            $passwdqc->check('o/IiJ/OI/110dA6KMN8m10pk7ff0UDR0rcJIAYhY')
        );

        $this->assertFalse(
            $passwdqc->check('123456')
        );
    }
}
