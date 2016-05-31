/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariable;
import anonymous.tlsattacker.util.RandomHelper;
import anonymous.tlsattacker.util.ReflectionHelper;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.LinkedList;
import java.util.List;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public abstract class ModifiableVariableHolder implements Serializable {

    /**
     * Lists all the modifiable variables declared in the class
     * 
     * @return
     */
    public List<Field> getAllModifiableVariableFields() {
	return ReflectionHelper.getFieldsUpTo(this.getClass(), null, ModifiableVariable.class);
    }

    /**
     * Returns a random field representing a modifiable variable from this class
     * 
     * @return
     */
    public Field getRandomModifiableVariableField() {
	List<Field> fields = getAllModifiableVariableFields();
	int randomField = RandomHelper.getRandom().nextInt(fields.size());
	return fields.get(randomField);
    }

    /**
     * Returns a list of all the modifiable variable holders in the object,
     * including this instance
     * 
     * @return
     */
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
	List<ModifiableVariableHolder> holders = new LinkedList<>();
	holders.add(this);
	return holders;
    }

    /**
     * Returns a random modifiable variable holder
     * 
     * @return
     */
    public ModifiableVariableHolder getRandomModifiableVariableHolder() {
	List<ModifiableVariableHolder> holders = getAllModifiableVariableHolders();
	int randomHolder = RandomHelper.getRandom().nextInt(holders.size());
	return holders.get(randomHolder);
    }
}
