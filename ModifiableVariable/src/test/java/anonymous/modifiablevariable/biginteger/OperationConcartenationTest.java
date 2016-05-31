/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.modifiablevariable.biginteger;

import anonymous.tlsattacker.modifiablevariable.biginteger.BigIntegerModificationFactory;
import anonymous.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariable;
import anonymous.tlsattacker.modifiablevariable.VariableModification;
import java.math.BigInteger;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @author anonymous anonymous <anonymous.mainka@anonymous>
 */
public class OperationConcartenationTest {

    private ModifiableBigInteger start;

    private BigInteger expectedResult, result;

    public OperationConcartenationTest() {
    }

    @Before
    public void setUp() {
	start = new ModifiableBigInteger();
	start.setOriginalValue(BigInteger.TEN);
    }

    @Test
    public void testAddThenMultiply() {
	// (input + 4) ^ 3 = (10 + 4) ^ 3 = 13
	VariableModification<BigInteger> modifier = BigIntegerModificationFactory.add("4");
	start.setModification(modifier);
	modifier.setPostModification(BigIntegerModificationFactory.xor("3"));
	expectedResult = new BigInteger("13");
	result = start.getValue();
	assertEquals(expectedResult, result);
    }

    @Test
    public void testAddThenMultiplyWithInnerClass() {
	// (input + 4) ^ 3 = (10 + 4) ^ 3 = 13
	start.setModification(new VariableModification<BigInteger>() {

	    @Override
	    protected BigInteger modifyImplementationHook(BigInteger input) {
		return input.add(new BigInteger("4")).xor(new BigInteger("3"));
	    }
	});
	expectedResult = new BigInteger("13");
	result = start.getValue();
	assertEquals(expectedResult, result);
    }
}
