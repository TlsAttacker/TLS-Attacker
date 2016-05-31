/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.workflow;

import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.exceptions.CryptoException;
import anonymous.tlsattacker.tls.constants.ProtocolMessageType;
import anonymous.tlsattacker.tls.exceptions.WorkflowExecutionException;
import anonymous.tlsattacker.tls.protocol.ProtocolMessage;
import anonymous.tlsattacker.tls.record.RecordHandler;
import anonymous.tlsattacker.tls.protocol.ProtocolMessageHandler;
import anonymous.tlsattacker.tls.constants.AlertLevel;
import anonymous.tlsattacker.tls.protocol.alert.AlertMessage;
import anonymous.tlsattacker.tls.record.Record;
import anonymous.tlsattacker.transport.TransportHandler;
import anonymous.tlsattacker.util.ArrayConverter;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class GenericWorkflowExecutor implements WorkflowExecutor {

    private static final Logger LOGGER = LogManager.getLogger(GenericWorkflowExecutor.class);

    /**
     * indicates if the workflow was already executed
     */
    protected boolean executed = false;

    /**
     * indicates if the peer requests renegotiation
     */
    protected boolean renegotiation = false;

    protected RecordHandler recordHandler;

    protected final TlsContext tlsContext;

    protected final TransportHandler transportHandler;

    MessageBytesCollector messageBytesCollector;

    protected WorkflowContext workflowContext;

    public GenericWorkflowExecutor(TransportHandler transportHandler, TlsContext tlsContext) {
	this.tlsContext = tlsContext;
	this.transportHandler = transportHandler;
	this.recordHandler = new RecordHandler(tlsContext);
	tlsContext.setRecordHandler(recordHandler);
	this.messageBytesCollector = new MessageBytesCollector();
	this.workflowContext = new WorkflowContext();
    }

    @Override
    public void executeWorkflow() throws WorkflowExecutionException {
	if (executed) {
	    throw new IllegalStateException("The workflow has already been" + " executed. Create a new Workflow.");
	}
	executed = true;

	List<ProtocolMessage> protocolMessages = tlsContext.getWorkflowTrace().getProtocolMessages();
	ensureMyLastProtocolMessagesHaveRecords(protocolMessages);
	try {
	    while (workflowContext.getProtocolMessagePointer() < protocolMessages.size()
		    && workflowContext.isProceedWorkflow()) {
		ProtocolMessage pm = protocolMessages.get(workflowContext.getProtocolMessagePointer());
		if (pm.getMessageIssuer() == tlsContext.getMyConnectionEnd()) {
		    handleMyProtocolMessage(protocolMessages);
		} else {
		    handleProtocolMessagesFromPeer(protocolMessages);
		}
	    }
	} catch (WorkflowExecutionException | CryptoException | IOException e) {
	    throw new WorkflowExecutionException(e.getLocalizedMessage(), e);
	} finally {
	    // remove all unused protocol messages
	    this.removeNextProtocolMessages(protocolMessages, workflowContext.getProtocolMessagePointer());
	}
    }

    private void handleMyProtocolMessage(List<ProtocolMessage> protocolMessages) throws IOException {
	ProtocolMessage pm = protocolMessages.get(workflowContext.getProtocolMessagePointer());
	prepareMyProtocolMessageBytes(pm);
	prepareMyRecordsIfNeeded(pm);
	sendDataIfMyLastMessage(protocolMessages);
	workflowContext.incrementProtocolMessagePointer();
    }

    /**
     * Uses protocol message handler to prepare raw protocol message bytes
     * 
     * @param pm
     */
    protected void prepareMyProtocolMessageBytes(ProtocolMessage pm) {
	LOGGER.debug("Preparing the following protocol message to send: {}", pm.getClass());
	ProtocolMessageHandler handler = pm.getProtocolMessageHandler(tlsContext);
	byte[] pmBytes = handler.prepareMessage();
	if (LOGGER.isDebugEnabled()) {
	    LOGGER.debug(pm.toString());
	}
	// append the prepared protocol message bytes
	if (pm.isGoingToBeSent()) {
	    messageBytesCollector.appendProtocolMessageBytes(pmBytes);
	}
    }

    /**
     * Prepares records for a given protocol message if this protocol message
     * contains a list of records
     * 
     * @param pm
     */
    protected void prepareMyRecordsIfNeeded(ProtocolMessage pm) {
	if (pm.getRecords() != null && !pm.getRecords().isEmpty()) {
	    byte[] records = recordHandler.wrapData(messageBytesCollector.getProtocolMessageBytes(),
		    pm.getProtocolMessageType(), pm.getRecords());
	    messageBytesCollector.appendRecordBytes(records);
	    messageBytesCollector.flushProtocolMessageBytes();
	}
    }

    /**
     * This function buffers all the collected records and sends them when the
     * last protocol message should be sent.
     * 
     * @param protocolMessages
     * @throws IOException
     */
    protected void sendDataIfMyLastMessage(List<ProtocolMessage> protocolMessages) throws IOException {
	if (handlingMyLastProtocolMessage(protocolMessages, workflowContext.getProtocolMessagePointer())
		&& messageBytesCollector.getRecordBytes().length != 0) {
	    LOGGER.debug("Records going to be sent: {}",
		    ArrayConverter.bytesToHexString(messageBytesCollector.getRecordBytes()));
	    transportHandler.sendData(messageBytesCollector.getRecordBytes());
	    messageBytesCollector.flushRecordBytes();
	}
    }

    /**
     * 
     * @param protocolMessages
     * @throws IOException
     */
    protected void handleProtocolMessagesFromPeer(List<ProtocolMessage> protocolMessages) throws IOException {
	List<Record> records = fetchRecords();
	List<List<Record>> recordsOfSameContentList = createListsOfRecordsOfTheSameContentType(records);

	for (List<Record> recordsOfSameContent : recordsOfSameContentList) {
	    byte[] rawProtocolMessageBytes = getRawProtocolBytesFromRecords(recordsOfSameContent);
	    ProtocolMessageType protocolMessageType = ProtocolMessageType.getContentType(recordsOfSameContent.get(0)
		    .getContentType().getValue());
	    parseRawBytesIntoProtocolMessages(rawProtocolMessageBytes, protocolMessages, protocolMessageType);
	    if (!renegotiation) {
		ProtocolMessage pm = protocolMessages.get(workflowContext.getProtocolMessagePointer() - 1);
		pm.setRecords(recordsOfSameContent);
	    } else {
		handleRenegotiation();
	    }
	}
    }

    /**
     * 
     * @param rawProtocolMessageBytes
     * @param protocolMessages
     * @param protocolMessageType
     */
    protected void parseRawBytesIntoProtocolMessages(byte[] rawProtocolMessageBytes,
	    List<ProtocolMessage> protocolMessages, ProtocolMessageType protocolMessageType) {
	int dataPointer = 0;
	while (dataPointer != rawProtocolMessageBytes.length && workflowContext.isProceedWorkflow()) {
	    ProtocolMessageHandler pmh = protocolMessageType.getProtocolMessageHandler(
		    rawProtocolMessageBytes[dataPointer], tlsContext);
	    if (Arrays.equals(rawProtocolMessageBytes,
		    new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 })) {
		renegotiation = true;
	    } else {
		identifyCorrectProtocolMessage(protocolMessages, pmh);

		dataPointer = pmh.parseMessage(rawProtocolMessageBytes, dataPointer);
		if (LOGGER.isDebugEnabled()) {
		    LOGGER.debug("The following message was parsed: {}", pmh.getProtocolMessage().toString());
		}
		handleIncomingAlert(pmh);
		workflowContext.incrementProtocolMessagePointer();
	    }
	}
    }

    /**
     * 
     * @param pmh
     */
    private void handleIncomingAlert(ProtocolMessageHandler pmh) {
	if (pmh.getProtocolMessage().getProtocolMessageType() == ProtocolMessageType.ALERT) {
	    AlertMessage am = (AlertMessage) pmh.getProtocolMessage();
	    am.setMessageIssuer(ConnectionEnd.SERVER);
	    if (AlertLevel.getAlertLevel(am.getLevel().getValue()) == AlertLevel.FATAL) {
		LOGGER.debug("The workflow execution is stopped because of a FATAL error");
		workflowContext.setProceedWorkflow(false);
	    }
	}
    }

    /**
     * 
     * @param protocolMessages
     * @param pmh
     */
    private void identifyCorrectProtocolMessage(List<ProtocolMessage> protocolMessages, ProtocolMessageHandler pmh) {
	ProtocolMessage pm = null;
	if (workflowContext.getProtocolMessagePointer() < protocolMessages.size()) {
	    pm = protocolMessages.get(workflowContext.getProtocolMessagePointer());
	}
	if (pm != null && pmh.isCorrectProtocolMessage(pm)) {
	    pmh.setProtocolMessage(pm);
	} else {
	    // the configured message is not the same as
	    // the message being parsed, we clean the
	    // next protocol messages
	    LOGGER.debug("The configured protocol message is not equal to "
		    + "the message being parsed or the message was not found.");
	    this.removeNextProtocolMessages(protocolMessages, workflowContext.getProtocolMessagePointer());
	    pmh.initializeProtocolMessage();
	    pm = pmh.getProtocolMessage();
	    protocolMessages.add(pm);
	}
    }

    /**
     * 
     * @param records
     * @return
     */
    protected byte[] getRawProtocolBytesFromRecords(List<Record> records) {
	byte[] result = new byte[0];
	for (Record r : records) {
	    result = ArrayConverter.concatenate(result, r.getProtocolMessageBytes().getValue());
	}
	return result;
    }

    /**
     * Creates a list of records of the same content type
     * 
     * @param records
     * @return
     */
    protected List<List<Record>> createListsOfRecordsOfTheSameContentType(List<Record> records) {
	List<List<Record>> result = new LinkedList();
	int recordPointer = 0;
	Record record = records.get(recordPointer);
	List<Record> currentRecords = new LinkedList<>();
	currentRecords.add(record);
	result.add(currentRecords);
	recordPointer++;
	while (recordPointer < records.size()) {
	    ProtocolMessageType previousMessageType = ProtocolMessageType.getContentType(record.getContentType()
		    .getValue());
	    record = records.get(recordPointer);
	    ProtocolMessageType currentMessageType = ProtocolMessageType.getContentType(record.getContentType()
		    .getValue());
	    if (currentMessageType == previousMessageType) {
		currentRecords.add(record);
	    } else {
		currentRecords = new LinkedList<>();
		currentRecords.add(record);
		result.add(currentRecords);
	    }
	    recordPointer++;
	}
	return result;
    }

    /**
     * Fetches a list of records from the server
     * 
     * @return
     * @throws IOException
     */
    protected List<Record> fetchRecords() throws IOException {
	List<Record> records;
	// parse stored Finished bytes into a record
	if (recordHandler.getFinishedBytes() != null) {
	    records = recordHandler.parseRecords(recordHandler.getFinishedBytes());
	    recordHandler.setFinishedBytes(null);
	} else {
	    byte[] rawResponse = transportHandler.fetchData();
	    while ((records = recordHandler.parseRecords(rawResponse)) == null) {
		rawResponse = ArrayConverter.concatenate(rawResponse, transportHandler.fetchData());
	    }
	    if (records.isEmpty()) {
		throw new WorkflowExecutionException("The configured protocol message was not found, "
			+ "the TLS peer does not send any data.");
	    }
	}
	return records;
    }

    /**
     * In a case the protocol message received was not equal to the messages in
     * our protocol message list, we have to clear our protocol message list.
     * 
     * @param protocolMessages
     * @param fromIndex
     */
    protected void removeNextProtocolMessages(List<ProtocolMessage> protocolMessages, int fromIndex) {
	for (int i = protocolMessages.size() - 1; i >= fromIndex; i--) {
	    protocolMessages.remove(i);
	}
    }

    /**
     * In case we are handling last protocol message, this protocol message has
     * to be flushed out. The reasons for flushing out the message can be
     * following: 1) it is the last protocol message 2) the next protocol
     * message should come from the different peer 3) the next protocol message
     * has a different content type
     * 
     * @param protocolMessages
     * @param pointer
     * @return
     */
    protected boolean handlingMyLastProtocolMessageWithContentType(List<ProtocolMessage> protocolMessages, int pointer) {
	ProtocolMessage currentProtocolMessage = protocolMessages.get(pointer);
	return ((protocolMessages.size() == (pointer + 1))
		|| (protocolMessages.get(pointer + 1).getMessageIssuer() != tlsContext.getMyConnectionEnd()) || currentProtocolMessage
		    .getProtocolMessageType() != (protocolMessages.get(pointer + 1).getProtocolMessageType()));
    }

    /**
     * In case we are handling last record message, this record message has to
     * be flushed out. The reasons for flushing out the record messages can be
     * following: 1) it is the last record message 2) the next record message
     * should come from the different peer
     * 
     * @param protocolMessages
     * @param pointer
     * @return
     */
    protected boolean handlingMyLastProtocolMessage(List<ProtocolMessage> protocolMessages, int pointer) {
	return ((protocolMessages.size() == (pointer + 1)) || (protocolMessages.get(pointer + 1).getMessageIssuer() != tlsContext
		.getMyConnectionEnd()));
    }

    /**
     * Every last protocol message that is going to be sent from my peer has to
     * have a record.
     * 
     * @param protocolMessages
     */
    protected void ensureMyLastProtocolMessagesHaveRecords(List<ProtocolMessage> protocolMessages) {
	for (int pmPointer = 0; pmPointer < protocolMessages.size(); pmPointer++) {
	    ProtocolMessage pm = protocolMessages.get(pmPointer);
	    if (handlingMyLastProtocolMessageWithContentType(protocolMessages, pmPointer)) {
		if (pm.getRecords() == null || pm.getRecords().isEmpty()) {
		    pm.addRecord(new Record());
		}
	    }
	}
    }

    /**
     * Handles a renegotiation request.
     */
    protected void handleRenegotiation() {
	workflowContext.setProtocolMessagePointer(0);
	tlsContext.getDigest().reset();

	/*
	 * if there is no keystore file we can not authenticate per certificate
	 * and if isClientauthentication is true, we do not need to change the
	 * WorkflowTrace
	 */
	if (tlsContext.getKeyStore() != null && !tlsContext.isClientAuthentication()) {
	    tlsContext.setClientAuthentication(true);
	    RenegotiationWorkflowConfiguration reneWorkflowConfig = new RenegotiationWorkflowConfiguration(tlsContext);
	    reneWorkflowConfig.createWorkflow();
	} else if (tlsContext.getKeyStore() == null && tlsContext.isSessionResumption()) {
	    RenegotiationWorkflowConfiguration reneWorkflowConfig = new RenegotiationWorkflowConfiguration(tlsContext);
	    reneWorkflowConfig.createWorkflow();
	}

	tlsContext.setSessionResumption(false);
	renegotiation = false;
	executed = false;
	executeWorkflow();
    }
}
