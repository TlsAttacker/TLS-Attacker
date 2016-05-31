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
@XmlType(propOrder = { "subtrahend", "modificationFilter", "postModification" })
public class BigIntegerSubtractModification extends VariableModification<BigInteger> {

    private BigInteger subtrahend;

    public BigIntegerSubtractModification() {

    }

    public BigIntegerSubtractModification(BigInteger bi) {
	this.subtrahend = bi;
    }

    @Override
    protected BigInteger modifyImplementationHook(BigInteger input) {
	if (input == null) {
	    input = BigInteger.ZERO;
	}
	return input.subtract(subtrahend);
    }

    public BigInteger getSubtrahend() {
	return subtrahend;
    }

    public void setSubtrahend(BigInteger subtrahend) {
	this.subtrahend = subtrahend;
    }
}
