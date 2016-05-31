/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.config.converters;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import anonymous.tlsattacker.transport.TransportHandlerType;

/**
 * Converts a transport handler type string to a TransportHandlerType value (for
 * command line purposes).
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class TransportHandlerTypeConverter implements IStringConverter<TransportHandlerType> {

    @Override
    public TransportHandlerType convert(String value) {
	try {
	    return TransportHandlerType.valueOf(value);
	} catch (IllegalArgumentException e) {
	    throw new ParameterException("Value " + value + " cannot be converted to TransportHandlerType.");
	}
    }
}
