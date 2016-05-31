/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.modifiablevariable.biginteger;

import anonymous.tlsattacker.modifiablevariable.biginteger.BigIntegerModificationFactory;
import anonymous.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import anonymous.tlsattacker.modifiablevariable.VariableModification;
import java.math.BigInteger;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class BigIntegerModificationTest {

    private ModifiableBigInteger start;

    private BigInteger expectedResult, result;

    public BigIntegerModificationTest() {
    }

    @Before
    public void setUp() {
	start = new ModifiableBigInteger();
	start.setOriginalValue(BigInteger.TEN);
	expectedResult = null;
	result = null;
    }

    /**
     * Test of add method, of class BigIntegerModificationFactory.
     */
    @Test
    public void testAdd() {
	VariableModification<BigInteger> modifier = BigIntegerModificationFactory.add(BigInteger.ONE);
	start.setModification(modifier);
	expectedResult = new BigInteger("11");
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);
	assertEquals(BigInteger.TEN, start.getOriginalValue());
    }

    /**
     * Test of sub method, of class BigIntegerModificationFactory.
     */
    @Test
    public void testSub() {
	VariableModification<BigInteger> modifier = BigIntegerModificationFactory.sub(BigInteger.ONE);
	start.setModification(modifier);
	expectedResult = new BigInteger("9");
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);
	assertEquals(BigInteger.TEN, start.getOriginalValue());
    }

    /**
     * Test of xor method, of class BigIntegerModificationFactory.
     */
    @Test
    public void testXor() {
	VariableModification<BigInteger> modifier = BigIntegerModificationFactory.xor(new BigInteger("2"));
	start.setModification(modifier);
	expectedResult = new BigInteger("8");
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);
	assertEquals(BigInteger.TEN, start.getOriginalValue());
    }

    /**
     * Test of explicitValue method, of class BigIntegerModificationFactory.
     */
    @Test
    public void testExplicitValue() {
	VariableModification<BigInteger> modifier = BigIntegerModificationFactory.explicitValue(new BigInteger("7"));
	start.setModification(modifier);
	expectedResult = new BigInteger("7");
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);
	assertEquals(BigInteger.TEN, start.getOriginalValue());
    }

    /**
     * Test of add method, of class BigIntegerModificationFactory.
     */
    @Test
    public void testIsOriginalValueModified() {
	assertFalse(start.isOriginalValueModified());
	VariableModification<BigInteger> modifier = BigIntegerModificationFactory.add(BigInteger.ZERO);
	start.setModification(modifier);
	assertFalse(start.isOriginalValueModified());
	modifier = BigIntegerModificationFactory.add(BigInteger.ONE);
	start.setModification(modifier);
	assertTrue(start.isOriginalValueModified());
    }

    @Test
    public void testShiftLeft() {
	VariableModification<BigInteger> modifier = BigIntegerModificationFactory.shiftLeft(2);
	start.setModification(modifier);
	expectedResult = new BigInteger("40");
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);
	assertEquals(BigInteger.TEN, start.getOriginalValue());
    }

    @Test
    public void testShiftRight() {
	VariableModification<BigInteger> modifier = BigIntegerModificationFactory.shiftRight(1);
	start.setModification(modifier);
	expectedResult = new BigInteger("5");
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);
	assertEquals(BigInteger.TEN, start.getOriginalValue());
    }
}
