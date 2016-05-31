/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable;

import javax.xml.bind.annotation.XmlAnyElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

/**
 * The base abstract class for modifiable variables, including the getValue
 * function.
 * 
 * The class needs to be defined transient to allow propOrder definition in
 * subclasses, see:
 * http://blog.bdoughan.com/2011/06/ignoring-inheritance-with-xmltransient.html
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @param <E>
 */
@XmlRootElement
@XmlTransient
public abstract class ModifiableVariable<E> {

    protected E originalValue;

    private VariableModification<E> modification = null;

    private boolean createRandomModification;

    protected E assertEquals;

    public ModifiableVariable() {

    }

    public void setModification(VariableModification<E> modification) {
	this.modification = modification;
    }

    @XmlAnyElement(lax = true)
    public VariableModification<E> getModification() {
	return modification;
    }

    public E getValue() {
	if (createRandomModification) {
	    createRandomModification();
	    createRandomModification = false;
	}

	if (modification != null) {
	    return modification.modify(originalValue);
	}
	return originalValue;
    }

    protected abstract void createRandomModification();

    public void createRandomModificationAtRuntime() {
	createRandomModification = true;
    }

    public abstract boolean isOriginalValueModified();

    public abstract boolean validateAssertions();

    public boolean containsAssertion() {
	return (assertEquals != null);
    }
}
