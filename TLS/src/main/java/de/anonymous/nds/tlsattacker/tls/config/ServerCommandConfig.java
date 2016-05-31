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
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ServerCommandConfig extends CommandConfig {

    public static final String COMMAND = "server";

    @Parameter(names = "-port", description = "ServerPort")
    protected String port = "4433";

    @Parameter(names = "-workflow_trace_type", description = "Type of the workflow trace (FULL or HANDSHAKE)")
    protected WorkflowTraceType workflowTraceType = WorkflowTraceType.HANDSHAKE;

    @Parameter(names = "-servername_fatal", description = "On mismatch in the server name the server sends a fatal "
	    + "alert")
    boolean serverNameFatal;

    public String getPort() {
	return port;
    }

    public void setPort(String port) {
	this.port = port;
    }

    public WorkflowTraceType getWorkflowTraceType() {
	return workflowTraceType;
    }

    public void setWorkflowTraceType(WorkflowTraceType workflowTraceType) {
	this.workflowTraceType = workflowTraceType;
    }

    public boolean isServerNameFatal() {
	return serverNameFatal;
    }

    public void setServerNameFatal(boolean serverNameFatal) {
	this.serverNameFatal = serverNameFatal;
    }

}
