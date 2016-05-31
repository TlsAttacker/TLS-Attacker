/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable.singlebyte;

import anonymous.tlsattacker.modifiablevariable.VariableModification;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

/**
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
@XmlRootElement
@XmlType(propOrder = { "summand", "modificationFilter", "postModification" })
public class ByteAddModification extends VariableModification<Byte> {

    private Byte summand;

    public ByteAddModification() {

    }

    public ByteAddModification(Byte bi) {
	this.summand = bi;
    }

    @Override
    protected Byte modifyImplementationHook(Byte input) {
	if (input == null) {
	    input = 0;
	}
	return (byte) (input + summand);
    }

    public Byte getSummand() {
	return summand;
    }

    public void setSummand(Byte summand) {
	this.summand = summand;
    }
}
