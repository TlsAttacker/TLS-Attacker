/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.impl;

import anonymous.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import anonymous.tlsattacker.tls.Attacker;
import anonymous.tlsattacker.modifiablevariable.VariableModification;
import anonymous.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.tls.config.ConfigHandler;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.exceptions.WorkflowExecutionException;
import anonymous.tlsattacker.tls.protocol.ProtocolMessage;
import anonymous.tlsattacker.tls.protocol.alert.AlertMessage;
import anonymous.tlsattacker.tls.protocol.application.ApplicationMessage;
import anonymous.tlsattacker.tls.record.Record;
import anonymous.tlsattacker.tls.util.LogLevel;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.workflow.WorkflowExecutor;
import anonymous.tlsattacker.tls.workflow.WorkflowTrace;
import anonymous.tlsattacker.transport.TransportHandler;
import anonymous.tlsattacker.util.ArrayConverter;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Executes a padding oracle attack check. It logs an error in case the tested
 * server is vulnerable to poodle.
 * 
 * @author anonymous anonymous (anonymous.anonymous@anonymous)
 */
public class PaddingOracleAttack extends Attacker<PaddingOracleCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger(PaddingOracleAttack.class);

    private final List<ProtocolMessage> lastMessages;

    public PaddingOracleAttack(PaddingOracleCommandConfig config) {
	super(config);
	lastMessages = new LinkedList<>();
    }

    @Override
    public void executeAttack(ConfigHandler configHandler) {
	List<Record> records = new LinkedList<>();
	records.addAll(createRecordsWithPlainData());
	records.addAll(createRecordsWithModifiedMac());
	records.addAll(createRecordsWithModifiedPadding());

	for (Record record : records) {
	    executeAttackRound(configHandler, record);

	}

	LOGGER.info("All the attack runs executed. The following messages arrived at the ends of the connections");
	LOGGER.info("If there are different messages, this could indicate the server does not process padding correctly");

	LinkedHashSet<ProtocolMessage> pmSet = new LinkedHashSet();
	for (int i = 0; i < lastMessages.size(); i++) {
	    ProtocolMessage pm = lastMessages.get(i);
	    pmSet.add(pm);
	    Record r = records.get(i);
	    LOGGER.info("----- NEXT TLS CONNECTION WITH MODIFIED APPLICATION DATA RECORD -----");
	    if (r.getPlainRecordBytes() != null) {
		LOGGER.info("Plain record bytes of the modified record: ");
		LOGGER.info(ArrayConverter.bytesToHexString(r.getPlainRecordBytes().getValue()));
		LOGGER.info("Last protocol message in the protocol flow");
	    }
	    LOGGER.info(pm.toString());
	}
	List<ProtocolMessage> pmSetList = new LinkedList<>(pmSet);

	if (pmSet.size() == 1) {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "{}, NOT vulnerable, one message found: {}", config.getConnect(),
		    pmSetList);

	} else {
	    LOGGER.log(LogLevel.CONSOLE_OUTPUT, "{}, Vulnerable (?), more messages found, recheck in debug mode: {}",
		    config.getConnect(), pmSetList);
	}
    }

    public void executeAttackRound(ConfigHandler configHandler, Record record) {
	TransportHandler transportHandler = configHandler.initializeTransportHandler(config);
	TlsContext tlsContext = configHandler.initializeTlsContext(config);
	WorkflowExecutor workflowExecutor = configHandler.initializeWorkflowExecutor(transportHandler, tlsContext);

	WorkflowTrace trace = tlsContext.getWorkflowTrace();

	ApplicationMessage applicationMessage = new ApplicationMessage(ConnectionEnd.CLIENT);
	applicationMessage.addRecord(record);

	AlertMessage allertMessage = new AlertMessage(ConnectionEnd.SERVER);

	trace.getProtocolMessages().add(applicationMessage);
	trace.getProtocolMessages().add(allertMessage);

	try {
	    workflowExecutor.executeWorkflow();
	} catch (WorkflowExecutionException ex) {
	    LOGGER.info("Not possible to finalize the defined workflow: {}", ex.getLocalizedMessage());
	}

	lastMessages.add(trace.getLastProtocolMesssage());
	tlsContexts.add(tlsContext);

	transportHandler.closeConnection();
    }

    private List<Record> createRecordsWithPlainData() {
	List<Record> records = new LinkedList();
	for (int i = 0; i < 64; i++) {
	    byte[] padding = createPaddingBytes(i);
	    int messageSize = config.getBlockSize() - (padding.length % config.getBlockSize());
	    byte[] message = new byte[messageSize];
	    byte[] plain = ArrayConverter.concatenate(message, padding);
	    Record r = createRecordWithPlainData(plain);
	    records.add(r);
	}
	Record r = createRecordWithPlainData(new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
		(byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
		(byte) 255, (byte) 255, (byte) 255 });
	records.add(r);

	r = createRecordWithPlainData(new byte[] { (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
		(byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
		(byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
		(byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255, (byte) 255,
		(byte) 255, (byte) 255, (byte) 255 });
	records.add(r);

	return records;
    }

    private Record createRecordWithPlainData(byte[] plain) {
	Record r = new Record();
	ModifiableByteArray plainData = new ModifiableByteArray();
	VariableModification<byte[]> modifier = ByteArrayModificationFactory.explicitValue(plain);
	plainData.setModification(modifier);
	r.setPlainRecordBytes(plainData);
	return r;
    }

    private List<Record> createRecordsWithModifiedPadding() {
	List<Record> records = new LinkedList();

	Record r = new Record();
	ModifiableByteArray padding = new ModifiableByteArray();
	VariableModification<byte[]> modifier = ByteArrayModificationFactory.xor(new byte[] { 1 }, 0);
	padding.setModification(modifier);
	r.setPadding(padding);
	records.add(r);

	return records;
    }

    private List<Record> createRecordsWithModifiedMac() {
	List<Record> records = new LinkedList();

	Record r = new Record();
	ModifiableByteArray mac = new ModifiableByteArray();
	VariableModification<byte[]> modifier = ByteArrayModificationFactory.xor(new byte[] { 1, 1, 1 }, 0);
	mac.setModification(modifier);
	r.setMac(mac);
	records.add(r);

	return records;
    }

    private byte[] createPaddingBytes(int padding) {
	byte[] paddingBytes = new byte[padding + 1];
	for (int i = 0; i < paddingBytes.length; i++) {
	    paddingBytes[i] = (byte) padding;
	}
	return paddingBytes;
    }

}
