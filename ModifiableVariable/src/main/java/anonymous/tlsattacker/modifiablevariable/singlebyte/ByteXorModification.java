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
@XmlType(propOrder = { "xor", "modificationFilter", "postModification" })
public class ByteXorModification extends VariableModification<Byte> {

    private Byte xor;

    public ByteXorModification() {

    }

    public ByteXorModification(Byte bi) {
	this.xor = bi;
    }

    @Override
    protected Byte modifyImplementationHook(Byte input) {
	if (input == null) {
	    input = 0;
	}
	return (byte) (input ^ xor);
    }

    public Byte getXor() {
	return xor;
    }

    public void setXor(Byte xor) {
	this.xor = xor;
    }
}
