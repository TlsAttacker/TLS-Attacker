/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable.bytearray;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariable;
import anonymous.tlsattacker.modifiablevariable.VariableModification;
import anonymous.tlsattacker.util.ByteArrayAdapter;
import java.io.Serializable;
import java.util.Arrays;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
@XmlRootElement
@XmlSeeAlso({ ByteArrayDeleteModification.class, ByteArrayExplicitValueModification.class,
	ByteArrayInsertModification.class, ByteArrayXorModification.class })
@XmlType(propOrder = { "originalValue", "modification", "assertEquals" })
public class ModifiableByteArray extends ModifiableVariable<byte[]> implements Serializable {

    @Override
    protected void createRandomModification() {
	VariableModification<byte[]> vm = ByteArrayModificationFactory.createRandomModification((byte[]) originalValue);
	setModification(vm);
    }

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    public byte[] getOriginalValue() {
	return originalValue;
    }

    public void setOriginalValue(byte[] value) {
	this.originalValue = value;
    }

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    public byte[] getAssertEquals() {
	return assertEquals;
    }

    public void setAssertEquals(byte[] assertEquals) {
	this.assertEquals = assertEquals;
    }

    @Override
    public boolean isOriginalValueModified() {
	return originalValue != null && !Arrays.equals(originalValue, getValue());
    }

    @Override
    public boolean validateAssertions() {
	boolean valid = true;
	if (assertEquals != null) {
	    if (!Arrays.equals(assertEquals, getValue())) {
		valid = false;
	    }
	}
	return valid;
    }
}
