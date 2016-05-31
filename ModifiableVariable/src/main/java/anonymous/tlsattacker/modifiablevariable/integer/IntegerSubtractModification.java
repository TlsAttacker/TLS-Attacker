/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable.integer;

import anonymous.tlsattacker.modifiablevariable.VariableModification;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

/**
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
@XmlRootElement
@XmlType(propOrder = { "subtrahend", "modificationFilter", "postModification" })
public class IntegerSubtractModification extends VariableModification<Integer> {

    private Integer subtrahend;

    public IntegerSubtractModification() {

    }

    public IntegerSubtractModification(Integer bi) {
	this.subtrahend = bi;
    }

    @Override
    protected Integer modifyImplementationHook(final Integer input) {
	return (input == null) ? -subtrahend : input - subtrahend;
    }

    public Integer getSubtrahend() {
	return subtrahend;
    }

    public void setSubtrahend(Integer subtrahend) {
	this.subtrahend = subtrahend;
    }
}
