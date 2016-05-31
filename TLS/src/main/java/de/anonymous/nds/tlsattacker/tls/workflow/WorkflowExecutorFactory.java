/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.workflow;

import anonymous.tlsattacker.dtls.workflow.Dtls12WorkflowExecutor;
import anonymous.tlsattacker.transport.TransportHandler;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class WorkflowExecutorFactory {

    public static WorkflowExecutor createWorkflowExecutor(TransportHandler transportHandler, TlsContext tlsContext) {
	WorkflowExecutor we;
	switch (tlsContext.getProtocolVersion()) {
	    case TLS10:
	    case TLS11:
	    case TLS12:
		we = new GenericWorkflowExecutor(transportHandler, tlsContext);
		return we;
	    case DTLS12:
		we = new Dtls12WorkflowExecutor(transportHandler, tlsContext);
		return we;
	    default:
		throw new UnsupportedOperationException("not yet implemented");
	}
    }
}
