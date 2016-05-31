/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.fuzzer.config;

import com.beust.jcommander.Parameter;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class MultiFuzzerConfig {

    public static final String COMMAND = "multi_fuzzer";

    @Parameter(names = { "-h", "-help" }, help = true, description = "Prints help")
    protected boolean help;

    @Parameter(names = "-startup_command_file", required = true, description = "XML file that is used for starting the server and the fuzzer.")
    String startupCommandFile;

    public MultiFuzzerConfig() {

    }

    public String getStartupCommandFile() {
	return startupCommandFile;
    }

    public void setStartupCommandFile(String startupCommandFile) {
	this.startupCommandFile = startupCommandFile;
    }

    public boolean isHelp() {
	return help;
    }

    public void setHelp(boolean help) {
	this.help = help;
    }
}
