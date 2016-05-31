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
@XmlType(propOrder = { "xor", "modificationFilter", "postModification" })
public class BigIntegerXorModification extends VariableModification<BigInteger> {

    private BigInteger xor;

    public BigIntegerXorModification() {

    }

    public BigIntegerXorModification(BigInteger bi) {
	this.xor = bi;
    }

    @Override
    protected BigInteger modifyImplementationHook(BigInteger input) {
	if (input == null) {
	    input = BigInteger.ZERO;
	}
	return input.xor(xor);
    }

    public BigInteger getXor() {
	return xor;
    }

    public void setXor(BigInteger xor) {
	this.xor = xor;
    }
}
