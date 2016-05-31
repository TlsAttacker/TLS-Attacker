/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable.bytearray;

import anonymous.tlsattacker.modifiablevariable.VariableModification;
import anonymous.tlsattacker.util.ByteArrayAdapter;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
@XmlRootElement
@XmlType(propOrder = { "explicitValue", "modificationFilter", "postModification" })
public class ByteArrayExplicitValueModification extends VariableModification<byte[]> {

    private byte[] explicitValue;

    public ByteArrayExplicitValueModification() {

    }

    public ByteArrayExplicitValueModification(byte[] explicitValue) {
	this.explicitValue = explicitValue;
    }

    @Override
    protected byte[] modifyImplementationHook(final byte[] input) {
	return explicitValue.clone();
    }

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    public byte[] getExplicitValue() {
	return explicitValue;
    }

    public void setExplicitValue(byte[] explicitValue) {
	this.explicitValue = explicitValue;
    }
}
