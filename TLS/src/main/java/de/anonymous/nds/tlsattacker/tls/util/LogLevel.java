/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.util;

import org.apache.logging.log4j.Level;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class LogLevel {

    /**
     * This log level is used to inform about important results of TLS
     * evaluations. For example, to present a final result of an executed
     * attack.
     */
    public static final Level CONSOLE_OUTPUT = Level.forName("CONSOLE", 150);
}
