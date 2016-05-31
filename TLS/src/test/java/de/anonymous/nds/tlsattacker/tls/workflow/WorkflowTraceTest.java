/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.workflow;

import anonymous.tlsattacker.tls.config.ClientCommandConfig;
import anonymous.tlsattacker.tls.config.ConfigHandler;
import anonymous.tlsattacker.tls.config.ConfigHandlerFactory;
import anonymous.tlsattacker.tls.config.GeneralConfig;
import anonymous.tlsattacker.util.UnoptimizedDeepCopy;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class WorkflowTraceTest {

    WorkflowTrace trace;

    public WorkflowTraceTest() {
	ConfigHandler configHandler = ConfigHandlerFactory.createConfigHandler("client");
	configHandler.initialize(new GeneralConfig());
	ClientCommandConfig ccc = new ClientCommandConfig();
	TlsContext tlsContext = configHandler.initializeTlsContext(ccc);
	trace = tlsContext.getWorkflowTrace();
    }

    @Test
    public void testDeepCopy() {
	WorkflowTrace copy = (WorkflowTrace) UnoptimizedDeepCopy.copy(trace);
	assertEquals("The number of messages in both traces has to be equal", trace.getProtocolMessages().size(), copy
		.getProtocolMessages().size());
    }

}
