/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.config.converters;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import anonymous.tlsattacker.tls.constants.CipherSuite;
import java.util.Arrays;

/**
 * Converts a ciphersuite string to a CipherSuite (for command line purposes).
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class CipherSuiteConverter implements IStringConverter<CipherSuite> {

    @Override
    public CipherSuite convert(String value) {

	try {
	    return CipherSuite.valueOf(value);
	} catch (IllegalArgumentException e) {
	    throw new ParameterException("Value " + value + " cannot be converted to a ciphersuite. "
		    + "Available values are: " + Arrays.toString(CipherSuite.values()));
	}
    }
}
