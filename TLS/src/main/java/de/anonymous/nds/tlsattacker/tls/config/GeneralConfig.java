/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.config;

import anonymous.tlsattacker.tls.config.converters.LogLevelConverter;
import com.beust.jcommander.Parameter;
import org.apache.logging.log4j.Level;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class GeneralConfig {
    @Parameter(names = { "-h", "-help" }, help = true, description = "Prints usage for all the existing commands.")
    private boolean help;

    @Parameter(names = "-debug", description = "Show extra debug output (sets logLevel to DEBUG)")
    private boolean debug;

    @Parameter(names = "-quiet", description = "No output (sets logLevel to NONE)")
    private boolean quiet;

    @Parameter(names = "-loglevel", description = "Set Log4j log level.", converter = LogLevelConverter.class)
    private Level logLevel;

    public boolean isHelp() {
	return help;
    }

    public void setHelp(boolean help) {
	this.help = help;
    }

    public boolean isDebug() {
	return debug;
    }

    public void setDebug(boolean debug) {
	this.debug = debug;
    }

    public boolean isQuiet() {
	return quiet;
    }

    public void setQuiet(boolean quiet) {
	this.quiet = quiet;
    }

    public Level getLogLevel() {
	return logLevel;
    }

    public void setLogLevel(Level logLevel) {
	this.logLevel = logLevel;
    }
}
