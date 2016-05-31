/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.modifiablevariable.integer;

import anonymous.tlsattacker.modifiablevariable.integer.IntegerModificationFactory;
import anonymous.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import anonymous.tlsattacker.modifiablevariable.VariableModification;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * @author dev
 */
public class IntegerModificationTest {

    private ModifiableInteger start;

    private Integer expectedResult, result;

    public IntegerModificationTest() {
    }

    @Before
    public void setUp() {
	start = new ModifiableInteger();
	start.setOriginalValue(10);
	expectedResult = null;
	result = null;
    }

    /**
     * Test of add method, of class IntegerModification.
     */
    @Test
    public void testAdd() {
	VariableModification<Integer> modifier = IntegerModificationFactory.add(1);
	start.setModification(modifier);
	expectedResult = 11;
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertEquals(new Integer(10), start.getOriginalValue());
    }

    /**
     * Test of sub method, of class IntegerModification.
     */
    @Test
    public void testSub() {
	VariableModification<Integer> modifier = IntegerModificationFactory.sub(1);
	start.setModification(modifier);
	expectedResult = 9;
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertEquals(new Integer(10), start.getOriginalValue());
    }

    /**
     * Test of xor method, of class IntegerModification.
     */
    @Test
    public void testXor() {
	VariableModification<Integer> modifier = IntegerModificationFactory.xor(2);
	start.setModification(modifier);
	expectedResult = 8;
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertEquals(new Integer(10), start.getOriginalValue());
    }

    /**
     * Test of explicitValue method, of class IntegerModification.
     */
    @Test
    public void testExplicitValue() {
	VariableModification<Integer> modifier = IntegerModificationFactory.explicitValue(7);
	start.setModification(modifier);
	expectedResult = 7;
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertEquals(new Integer(10), start.getOriginalValue());
    }

    @Test
    public void testShiftLeft() {
	VariableModification<Integer> modifier = IntegerModificationFactory.shiftLeft(2);
	start.setModification(modifier);
	expectedResult = 40;
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertEquals(new Integer(10), start.getOriginalValue());
    }

    @Test
    public void testShiftRight() {
	VariableModification<Integer> modifier = IntegerModificationFactory.shiftRight(2);
	start.setModification(modifier);
	expectedResult = 2;
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertEquals(new Integer(10), start.getOriginalValue());
    }

}
