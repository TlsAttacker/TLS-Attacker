/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable.biginteger;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariable;
import anonymous.tlsattacker.modifiablevariable.VariableModification;
import anonymous.tlsattacker.util.ArrayConverter;
import java.io.Serializable;
import java.math.BigInteger;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlType;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
@XmlRootElement
@XmlSeeAlso({ BigIntegerAddModification.class, BigIntegerExplicitValueModification.class,
	BigIntegerSubtractModification.class, BigIntegerXorModification.class })
@XmlType(propOrder = { "originalValue", "modification", "assertEquals" })
public class ModifiableBigInteger extends ModifiableVariable<BigInteger> implements Serializable {

    @Override
    protected void createRandomModification() {
	VariableModification<BigInteger> vm = BigIntegerModificationFactory.createRandomModification();
	setModification(vm);
    }

    public BigInteger getOriginalValue() {
	return originalValue;
    }

    public void setOriginalValue(BigInteger value) {
	this.originalValue = value;
    }

    public BigInteger getAssertEquals() {
	return assertEquals;
    }

    public void setAssertEquals(BigInteger assertEquals) {
	this.assertEquals = assertEquals;
    }

    @Override
    public boolean isOriginalValueModified() {
	return originalValue != null && (originalValue.compareTo(getValue()) != 0);
    }

    public byte[] getByteArray() {
	return ArrayConverter.bigIntegerToByteArray(getValue());
    }

    public byte[] getByteArray(int size) {
	return ArrayConverter.bigIntegerToByteArray(getValue(), size, true);
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
