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
@XmlType(propOrder = { "subtrahend", "modificationFilter", "postModification" })
public class ByteSubtractModification extends VariableModification<Byte> {

    private Byte subtrahend;

    public ByteSubtractModification() {

    }

    public ByteSubtractModification(Byte bi) {
	this.subtrahend = bi;
    }

    @Override
    protected Byte modifyImplementationHook(Byte input) {
	if (input == null) {
	    input = 0;
	}
	return (byte) (input - subtrahend);
    }

    public Byte getSubtrahend() {
	return subtrahend;
    }

    public void setSubtrahend(Byte subtrahend) {
	this.subtrahend = subtrahend;
    }
}
