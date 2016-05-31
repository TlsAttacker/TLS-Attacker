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
@XmlType(propOrder = { "summand", "modificationFilter", "postModification" })
public class BigIntegerAddModification extends VariableModification<BigInteger> {

    private BigInteger summand;

    public BigIntegerAddModification() {

    }

    public BigIntegerAddModification(BigInteger bi) {
	this.summand = bi;
    }

    @Override
    protected BigInteger modifyImplementationHook(BigInteger input) {
	return (input == null) ? summand : input.add(summand);
    }

    public BigInteger getSummand() {
	return summand;
    }

    public void setSummand(BigInteger summand) {
	this.summand = summand;
    }
}
