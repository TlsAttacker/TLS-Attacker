/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.config;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import anonymous.tlsattacker.tls.constants.CompressionMethod;
import java.util.Arrays;

/**
 * Converts a string with a compression method to a compression method (for
 * command line purposes).
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class CompressionMethodConverter implements IStringConverter<CompressionMethod> {

    @Override
    public CompressionMethod convert(String value) {

	try {
	    return CompressionMethod.valueOf(value);
	} catch (IllegalArgumentException e) {
	    throw new ParameterException("Value " + value + " cannot be converted to a compression method. "
		    + "Available values are: " + Arrays.toString(CompressionMethod.values()));
	}
    }
}
