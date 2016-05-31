/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable.singlebyte;

import anonymous.tlsattacker.modifiablevariable.VariableModification;
import anonymous.tlsattacker.util.RandomHelper;
import java.util.Random;

/**
 * @author
 */
final public class ByteModificationFactory {

    private static final int BYTE_EXPLICIT_VALUE_MODIFICATION = 3;

    private static final int BYTE_XOR_MODIFICATION = 2;

    private static final int BYTE_SUBTRACT_MODIFICATION = 1;

    private static final int BYTE_ADD_MODIFICATION = 0;

    private static final int MODIFICATION_COUNT = 4;

    private ByteModificationFactory() {
    }

    public static ByteAddModification add(final String summand) {
	return add(new Byte(summand));
    }

    public static ByteAddModification add(final Byte summand) {
	return new ByteAddModification(summand);
    }

    public static VariableModification<Byte> sub(final String subtrahend) {
	return sub(new Byte(subtrahend));
    }

    public static VariableModification<Byte> sub(final Byte subtrahend) {
	return new ByteSubtractModification(subtrahend);
    }

    public static VariableModification<Byte> xor(final String xor) {
	return xor(new Byte(xor));
    }

    public static VariableModification<Byte> xor(final Byte xor) {
	return new ByteXorModification(xor);
    }

    public static VariableModification<Byte> explicitValue(final String value) {
	return explicitValue(new Byte(value));
    }

    public static VariableModification<Byte> explicitValue(final Byte value) {
	return new ByteExplicitValueModification(value);
    }

    public static VariableModification<Byte> createRandomModification() {
	Random random = RandomHelper.getRandom();
	int r = random.nextInt(MODIFICATION_COUNT);
	byte modification = (byte) random.nextInt(Byte.MAX_VALUE);
	VariableModification<Byte> vm = null;
	switch (r) {
	    case BYTE_ADD_MODIFICATION:
		vm = new ByteAddModification(modification);
		return vm;
	    case BYTE_SUBTRACT_MODIFICATION:
		vm = new ByteSubtractModification(modification);
		return vm;
	    case BYTE_XOR_MODIFICATION:
		vm = new ByteXorModification(modification);
		return vm;
	    case BYTE_EXPLICIT_VALUE_MODIFICATION:
		vm = new ByteExplicitValueModification(modification);
		return vm;
	}
	return vm;
    }

}
