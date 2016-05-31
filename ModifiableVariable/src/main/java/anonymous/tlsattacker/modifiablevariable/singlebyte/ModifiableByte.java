/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable.singlebyte;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariable;
import anonymous.tlsattacker.modifiablevariable.VariableModification;
import java.io.Serializable;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
@XmlRootElement
@XmlSeeAlso({ ByteAddModification.class, ByteExplicitValueModification.class, ByteSubtractModification.class,
	ByteXorModification.class })
@XmlType(propOrder = { "originalValue", "modification", "assertEquals" })
public class ModifiableByte extends ModifiableVariable<Byte> implements Serializable {

    @Override
    protected void createRandomModification() {
	VariableModification<Byte> vm = ByteModificationFactory.createRandomModification();
	setModification(vm);
    }

    public Byte getOriginalValue() {
	return originalValue;
    }

    public void setOriginalValue(Byte originalValue) {
	this.originalValue = originalValue;
    }

    public Byte getAssertEquals() {
	return assertEquals;
    }

    public void setAssertEquals(Byte assertEquals) {
	this.assertEquals = assertEquals;
    }

    @Override
    public boolean isOriginalValueModified() {
	return originalValue != null && originalValue.compareTo(getValue()) != 0;
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
