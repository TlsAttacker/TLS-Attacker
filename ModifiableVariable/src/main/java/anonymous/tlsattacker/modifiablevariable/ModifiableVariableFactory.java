/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable;

import anonymous.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import anonymous.tlsattacker.modifiablevariable.singlebyte.ModifiableByte;
import java.math.BigInteger;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ModifiableVariableFactory {

    private ModifiableVariableFactory() {

    }

    public static ModifiableBigInteger createBigIntegerModifiableVariable() {
	return new ModifiableBigInteger();
    }

    public static ModifiableInteger createIntegerModifiableVariable() {
	return new ModifiableInteger();
    }

    public static ModifiableByte createByteModifiableVariable() {
	return new ModifiableByte();
    }

    public static ModifiableByteArray createByteArrayModifiableVariable() {
	return new ModifiableByteArray();
    }

    public static ModifiableBigInteger safelySetValue(ModifiableBigInteger mv, BigInteger value) {
	if (mv == null) {
	    mv = new ModifiableBigInteger();
	}
	mv.setOriginalValue(value);
	return mv;
    }

    public static ModifiableInteger safelySetValue(ModifiableInteger mv, Integer value) {
	if (mv == null) {
	    mv = new ModifiableInteger();
	}
	mv.setOriginalValue(value);
	return mv;
    }

    public static ModifiableByte safelySetValue(ModifiableByte mv, Byte value) {
	if (mv == null) {
	    mv = new ModifiableByte();
	}
	mv.setOriginalValue(value);
	return mv;
    }

    public static ModifiableByteArray safelySetValue(ModifiableByteArray mv, byte[] value) {
	if (mv == null) {
	    mv = new ModifiableByteArray();
	}
	mv.setOriginalValue(value);
	return mv;
    }
}
