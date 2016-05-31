/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable.mlong;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariable;
import anonymous.tlsattacker.modifiablevariable.VariableModification;
import anonymous.tlsattacker.util.ArrayConverter;
import java.io.Serializable;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
@XmlRootElement
@XmlSeeAlso({ LongAddModification.class, LongExplicitValueModification.class, LongSubtractModification.class,
	LongXorModification.class })
@XmlType(propOrder = { "originalValue", "modification", "assertEquals" })
public class ModifiableLong extends ModifiableVariable<Long> implements Serializable {

    @Override
    protected void createRandomModification() {
	VariableModification<Long> vm = LongModificationFactory.createRandomModification();
	setModification(vm);
    }

    public Long getOriginalValue() {
	return originalValue;
    }

    public void setOriginalValue(Long originalValue) {
	this.originalValue = originalValue;
    }

    public Long getAssertEquals() {
	return assertEquals;
    }

    public void setAssertEquals(Long assertEquals) {
	this.assertEquals = assertEquals;
    }

    @Override
    public boolean isOriginalValueModified() {
	return originalValue != null && originalValue.compareTo(getValue()) != 0;
    }

    public byte[] getByteArray(int size) {
	return ArrayConverter.longToBytes(getValue(), size);
    }

    @Override
    public boolean validateAssertions() {
	boolean valid = true;
	if (assertEquals != null) {
	    if (assertEquals.compareTo(getValue()) != 0) {
		valid = false;
	    }
	}
	return valid;
    }
}
