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
@XmlType(propOrder = { "shift", "modificationFilter", "postModification" })
public class IntegerShiftRightModification extends VariableModification<Integer> {

    private int shift;

    public IntegerShiftRightModification() {

    }

    public IntegerShiftRightModification(int shift) {
	this.shift = shift;
    }

    @Override
    protected Integer modifyImplementationHook(final Integer input) {
	return (input == null) ? 0 : input >> shift;
    }

    public int getShift() {
	return shift;
    }

    public void setShift(int shift) {
	this.shift = shift;
    }
}
