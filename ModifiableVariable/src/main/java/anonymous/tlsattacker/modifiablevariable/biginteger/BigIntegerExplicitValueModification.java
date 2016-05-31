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
@XmlType(propOrder = { "explicitValue", "modificationFilter", "postModification" })
public class BigIntegerExplicitValueModification extends VariableModification<BigInteger> {

    private BigInteger explicitValue;

    public BigIntegerExplicitValueModification() {

    }

    public BigIntegerExplicitValueModification(BigInteger bi) {
	this.explicitValue = bi;
    }

    @Override
    protected BigInteger modifyImplementationHook(final BigInteger input) {
	return explicitValue;
    }

    public BigInteger getExplicitValue() {
	return explicitValue;
    }

    public void setExplicitValue(BigInteger explicitValue) {
	this.explicitValue = explicitValue;
    }
}
