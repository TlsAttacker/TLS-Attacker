/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import anonymous.tlsattacker.tls.config.ClientCommandConfig;
import anonymous.tlsattacker.tls.constants.ProtocolVersion;
import anonymous.tlsattacker.tls.constants.CipherSuite;
import anonymous.tlsattacker.tls.workflow.WorkflowTraceType;
import anonymous.tlsattacker.transport.TransportHandlerType;
import java.util.ArrayList;
import java.util.List;

/**
 * @author anonymous Pfützenreuter <anonymous.pfuetzenreuter@anonymous>
 */
public class DtlsPaddingOracleAttackCommandConfig extends ClientCommandConfig {

    public static final String ATTACK_COMMAND = "dtls_potest";

    @Parameter(names = "-messagespertrain", description = "Number of messages per train")
    int messagesPerTrain = 10;

    @Parameter(names = "-trainmessagesize", description = "Message size of each trains messages")
    int trainMessageSize = 1450;

    @Parameter(names = "-rounds", description = "Number of attack rounds")
    int nrOfRounds = 20;

    @Parameter(names = "-resultfile", description = "Save the response times in the specified file")
    String resultFilePath = null;

    @Parameter(names = "-messagewaitnanos", description = "Wait for this amount of nanoseconds between sending two messages of any given train (rate limiting)")
    long messageWaitNanos = 0;

    public DtlsPaddingOracleAttackCommandConfig() {
	// Just to be sure
	transportHandlerType = TransportHandlerType.UDP;
	protocolVersion = ProtocolVersion.DTLS12;
	workflowTraceType = WorkflowTraceType.HANDSHAKE;

	// Until all dtls workflow factories are adapted, this is to make sure
	// the right workflow factory is used
	List<CipherSuite> cs = new ArrayList<>();
	cs.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
	cipherSuites = cs;
    }

    public int getMessagesPerTrain() {
	return messagesPerTrain;
    }

    public int getTrainMessageSize() {
	return trainMessageSize;
    }

    public int getNrOfRounds() {
	return nrOfRounds;
    }

    public String getResultFilePath() {
	return resultFilePath;
    }

    public long getMessageWaitNanos() {
	return messageWaitNanos;
    }

    public void setMessagesPerTrain(int messagesPerTrain) {
	this.messagesPerTrain = messagesPerTrain;
    }

    public void setTrainMessageSize(int trainMessageSize) {
	this.trainMessageSize = trainMessageSize;
    }

    public void setNrOfRounds(int nrOfRounds) {
	this.nrOfRounds = nrOfRounds;
    }

    public void setResultFilePath(String resultFilePath) {
	this.resultFilePath = resultFilePath;
    }

    public void setMessageWaitNanos(long messageWaitNanos) {
	this.messageWaitNanos = messageWaitNanos;
    }
}