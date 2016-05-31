/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.fuzzer.config.converters;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import java.util.Arrays;

/**
 * Converts a Property Format string to a PropertyFormat (for command line
 * purposes).
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class PropertyFormatConverter implements IStringConverter<ModifiableVariableProperty.Format> {

    @Override
    public ModifiableVariableProperty.Format convert(String value) {

	try {
	    return ModifiableVariableProperty.Format.valueOf(value);
	} catch (IllegalArgumentException e) {
	    throw new ParameterException("Value " + value + " cannot be converted to a VariablePropertyFormat. "
		    + "Available values are: " + Arrays.toString(ModifiableVariableProperty.Format.values()));
	}
    }
}
