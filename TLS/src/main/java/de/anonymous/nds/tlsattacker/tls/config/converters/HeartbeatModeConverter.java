/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.config.converters;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.ParameterException;
import anonymous.tlsattacker.tls.constants.HeartbeatMode;
import java.util.Arrays;

/**
 * Converts a heartbeat mode string to a HeartbeatMode (for command line
 * purposes).
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class HeartbeatModeConverter implements IStringConverter<HeartbeatMode> {

    @Override
    public HeartbeatMode convert(String value) {

	try {
	    return HeartbeatMode.valueOf(value);
	} catch (IllegalArgumentException e) {
	    throw new ParameterException("Value " + value + " cannot be converted to a HeartbeatMode. "
		    + "Available values are: " + Arrays.toString(HeartbeatMode.values()));
	}
    }
}
