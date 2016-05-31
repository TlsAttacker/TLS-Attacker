/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.modifiablevariable;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import anonymous.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import anonymous.tlsattacker.util.ArrayConverter;
import java.math.BigInteger;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ModifiableVariableTest {

    @Test
    public void testRandomBigIntegerModification() {
	ModifiableBigInteger bigInteger = ModifiableVariableFactory.createBigIntegerModifiableVariable();
	bigInteger.setOriginalValue(BigInteger.ZERO);
	bigInteger.createRandomModificationAtRuntime();
	System.out.println("Randomly modified big integer: " + bigInteger.getValue());
	assertNotNull(bigInteger.getModification());
    }

    @Test
    public void testRandomIntegerModification() {
	ModifiableInteger integer = ModifiableVariableFactory.createIntegerModifiableVariable();
	integer.setOriginalValue(0);
	integer.createRandomModificationAtRuntime();
	System.out.println("Randomly modified integer: " + integer.getValue());
	assertNotNull(integer.getModification());
    }

    @Test
    public void testRandomByteArrayModification() {
	ModifiableByteArray array = ModifiableVariableFactory.createByteArrayModifiableVariable();
	array.setOriginalValue(new byte[] { 0, 1, 2 });
	array.createRandomModificationAtRuntime();
	System.out.println("Randomly modified byte array: " + ArrayConverter.bytesToHexString(array.getValue()));
	assertNotNull(array.getModification());
    }
}
