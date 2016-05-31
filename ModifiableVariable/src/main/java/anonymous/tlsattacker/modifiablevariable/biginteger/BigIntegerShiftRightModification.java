/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable.biginteger;

import anonymous.tlsattacker.modifiablevariable.VariableModification;
import java.math.BigInteger;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

/**
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
@XmlRootElement
@XmlType(propOrder = { "shift", "modificationFilter", "postModification" })
public class BigIntegerShiftRightModification extends VariableModification<BigInteger> {

    private int shift;

    public BigIntegerShiftRightModification() {

    }

    public BigIntegerShiftRightModification(int shift) {
	this.shift = shift;
    }

    @Override
    protected BigInteger modifyImplementationHook(BigInteger input) {
	if (input == null) {
	    input = BigInteger.ZERO;
	}
	return input.shiftRight(shift);
    }

    public int getShift() {
	return shift;
    }

    public void setShift(int shift) {
	this.shift = shift;
    }
}
