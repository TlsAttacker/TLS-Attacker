/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.util;

import anonymous.tlsattacker.util.MathHelper;
import java.math.BigInteger;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class MathHelperTest {

    public MathHelperTest() {
    }

    /**
     * Test of intfloordiv method, of class MathHelper.
     */
    @Test
    public void testIntfloordiv_BigInteger_BigInteger() {
    }

    /**
     * Test of intceildiv method, of class MathHelper.
     */
    @Test
    public void testIntceildiv_BigInteger_BigInteger() {
    }

    /**
     * Test of intfloordiv method, of class MathHelper.
     */
    @Test
    public void testIntfloordiv_int_int() {
    }

    /**
     * Test of intceildiv method, of class MathHelper.
     */
    @Test
    public void testIntceildiv_int_int() {
    }

    /**
     * Test of extendedEuclid method, of class MathHelper.
     */
    @Test
    public void testExtendedEuclid() {
    }

    /**
     * Test of gcd method, of class MathHelper.
     */
    @Test
    public void testGcd() {
    }

    /**
     * Test of inverseMod method, of class MathHelper.
     */
    @Test
    public void testInverseMod() {
    }

    /**
     * Test of CRT method, of class MathHelper.
     */
    @Test
    public void testCRT() {
	BigInteger[] congs = { new BigInteger("3"), new BigInteger("4"), new BigInteger("5") };
	BigInteger[] moduli = { new BigInteger("2"), new BigInteger("3"), new BigInteger("2") };
	assertEquals(4, MathHelper.CRT(congs, moduli).intValue());

	// computes:
	// x == 2 mod 3
	// x == 3 mod 4
	// x == 1 mod 5
	BigInteger[] congs2 = { new BigInteger("2"), new BigInteger("3"), new BigInteger("1") };
	BigInteger[] moduli2 = { new BigInteger("3"), new BigInteger("4"), new BigInteger("5") };
	assertEquals(11, MathHelper.CRT(congs2, moduli2).intValue());
    }

}
