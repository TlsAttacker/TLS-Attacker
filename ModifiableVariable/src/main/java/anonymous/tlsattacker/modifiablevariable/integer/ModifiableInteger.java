/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable.integer;

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
@XmlSeeAlso({ IntegerAddModification.class, IntegerExplicitValueModification.class, IntegerSubtractModification.class,
	IntegerXorModification.class })
@XmlType(propOrder = { "originalValue", "modification", "assertEquals" })
public class ModifiableInteger extends ModifiableVariable<Integer> implements Serializable {

    @Override
    protected void createRandomModification() {
	VariableModification<Integer> vm = IntegerModificationFactory.createRandomModification();
	setModification(vm);
    }

    public Integer getOriginalValue() {
	return originalValue;
    }

    public void setOriginalValue(Integer originalValue) {
	this.originalValue = originalValue;
    }

    public Integer getAssertEquals() {
	return assertEquals;
    }

    public void setAssertEquals(Integer assertEquals) {
	this.assertEquals = assertEquals;
    }

    @Override
    public boolean isOriginalValueModified() {
	return originalValue != null && originalValue.compareTo(getValue()) != 0;
    }

    public byte[] getByteArray(int size) {
	return ArrayConverter.intToBytes(getValue(), size);
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
