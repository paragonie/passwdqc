<?php
declare(strict_types=1);
namespace ParagonIE\Passwdqc\Tests;

use ParagonIE\Passwdqc\Passwdqc;

/**
 * Class PasswdqcTest
 * @package ParagonIE\Passwdqc\Tests
 */
class PasswdqcTest extends \PHPUnit_Framework_TestCase
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
