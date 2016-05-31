/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.config.converters;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import anonymous.tlsattacker.tls.constants.ProtocolVersion;

/**
 * Converts a protocol version string to a protocol Version enum (for command
 * line purposes).
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ProtocolVersionConverter implements IStringConverter<ProtocolVersion> {

    @Override
    public ProtocolVersion convert(String value) {
	try {
	    return ProtocolVersion.fromString(value);
	} catch (IllegalArgumentException ex) {
	    throw new ParameterException(ex);
	}
    }
}
