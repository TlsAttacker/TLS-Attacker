/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.config.converters;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import anonymous.tlsattacker.tls.constants.NamedCurve;
import java.util.Arrays;

/**
 * Converts a string named curve to a NamedCurve type (for command line
 * purposes).
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class NamedCurveConverter implements IStringConverter<NamedCurve> {

    @Override
    public NamedCurve convert(String value) {

	try {
	    return NamedCurve.valueOf(value);
	} catch (IllegalArgumentException e) {
	    throw new ParameterException("Value " + value + " cannot be converted to a NamedCurve. "
		    + "Available values are: " + Arrays.toString(NamedCurve.values()));
	}
    }
}
