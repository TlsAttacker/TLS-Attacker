/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import anonymous.tlsattacker.tls.config.ClientCommandConfig;
import anonymous.tlsattacker.tls.constants.HeartbeatMode;
import anonymous.tlsattacker.tls.workflow.WorkflowTraceType;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class HeartbleedCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "heartbleed";

    @Parameter(names = "-payload_length", description = "Payload length sent in the client heartbeat message")
    Integer payloadLength;

    public HeartbleedCommandConfig() {
	workflowTraceType = WorkflowTraceType.FULL;
	payloadLength = 20000;
	heartbeatMode = HeartbeatMode.PEER_ALLOWED_TO_SEND;
    }

    public Integer getPayloadLength() {
	return payloadLength;
    }

    public void setPayloadLength(Integer payloadLength) {
	this.payloadLength = payloadLength;
    }
}
