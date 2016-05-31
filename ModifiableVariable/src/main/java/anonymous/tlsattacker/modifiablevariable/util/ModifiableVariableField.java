/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable.util;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariable;
import java.lang.reflect.Field;

/**
 * Represents an object with its modifiable variable field.
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class ModifiableVariableField {

    private Object object;

    private Field field;

    public ModifiableVariableField() {

    }

    public ModifiableVariableField(Object o, Field f) {
	this.object = o;
	this.field = f;
    }

    public Object getObject() {
	return object;
    }

    public void setObject(Object object) {
	this.object = object;
    }

    public Field getField() {
	return field;
    }

    public void setField(Field field) {
	this.field = field;
    }

    public ModifiableVariable getModifiableVariable() throws IllegalArgumentException, IllegalAccessException {
	field.setAccessible(true);
	return (ModifiableVariable) field.get(object);
    }

}
