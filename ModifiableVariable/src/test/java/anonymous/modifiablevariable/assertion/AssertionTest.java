/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.modifiablevariable.assertion;

import anonymous.tlsattacker.modifiablevariable.integer.IntegerModificationFactory;
import anonymous.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import anonymous.tlsattacker.modifiablevariable.VariableModification;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

public class AssertionTest {

    private ModifiableInteger mi;

    private ModifiableByteArray mba;

    public AssertionTest() {
    }

    @Before
    public void setUp() {
	mi = new ModifiableInteger();
	mi.setOriginalValue(10);
	mba = new ModifiableByteArray();
	mba.setOriginalValue(new byte[] { 0, 1 });
    }

    @Test
    public void testAssertionInteger() {
	mi.setAssertEquals(10);
	assertTrue(mi.validateAssertions());
	mi.setAssertEquals(0);
	assertFalse(mi.validateAssertions());
    }

    @Test
    public void testAddInteger() {
	VariableModification<Integer> modifier = IntegerModificationFactory.add(1);
	mi.setModification(modifier);
	mi.setAssertEquals(11);
	assertTrue(mi.validateAssertions());
    }

    @Test
    public void testAssertionByteArray() {
	mba.setAssertEquals(new byte[] { 0, 1 });
	assertTrue(mba.validateAssertions());
	mba.setAssertEquals(new byte[] { 0, 0 });
	assertFalse(mba.validateAssertions());
    }

}
