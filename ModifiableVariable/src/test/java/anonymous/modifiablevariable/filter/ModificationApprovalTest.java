/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.modifiablevariable.filter;

import anonymous.tlsattacker.modifiablevariable.filter.ModificationFilterFactory;
import anonymous.tlsattacker.modifiablevariable.ModificationFilter;
import anonymous.tlsattacker.modifiablevariable.biginteger.BigIntegerModificationFactory;
import anonymous.tlsattacker.modifiablevariable.VariableModification;
import anonymous.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import java.math.BigInteger;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ModificationApprovalTest {

    private ModifiableBigInteger start;

    private ModificationFilter filter;

    private BigInteger expectedResult, result;

    public ModificationApprovalTest() {
    }

    @Before
    public void setUp() {
	start = new ModifiableBigInteger();
	start.setOriginalValue(BigInteger.TEN);
	int[] filtered = { 1, 3 };
	filter = ModificationFilterFactory.access(filtered);
	expectedResult = null;
	result = null;
    }

    /**
     * Test filter modification. The first and third modification are filtered
     * out so that no modification is visible.
     */
    @Test
    public void testAdd() {
	VariableModification<BigInteger> modifier = BigIntegerModificationFactory.add(BigInteger.ONE);
	start.setModification(modifier);
	modifier.setModificationFilter(filter);
	expectedResult = new BigInteger("10");
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);

	expectedResult = new BigInteger("11");
	result = start.getValue();
	assertEquals(expectedResult, result);

	expectedResult = new BigInteger("10");
	result = start.getValue();
	assertEquals(expectedResult, result);
	assertNotSame(expectedResult, result);
    }

}
