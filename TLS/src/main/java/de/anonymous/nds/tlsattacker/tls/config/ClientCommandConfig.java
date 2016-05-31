/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.config;

import com.beust.jcommander.Parameter;
import anonymous.tlsattacker.tls.workflow.WorkflowTraceType;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ClientCommandConfig extends CommandConfig {

    public static final String COMMAND = "client";

    @Parameter(names = "-connect", description = "who to connect to")
    protected String connect = "localhost:4433";

    @Parameter(names = "-workflow_trace_type", description = "Type of the workflow trace (FULL or HANDSHAKE)")
    protected WorkflowTraceType workflowTraceType = WorkflowTraceType.FULL;

    public String getConnect() {
	return connect;
    }

    public void setConnect(String connect) {
	this.connect = connect;
    }

    public WorkflowTraceType getWorkflowTraceType() {
	return workflowTraceType;
    }

    public void setWorkflowTraceType(WorkflowTraceType workflowTraceType) {
	this.workflowTraceType = workflowTraceType;
    }
}
