/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol;

import anonymous.tlsattacker.dtls.record.DtlsRecord;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.constants.ProtocolMessageType;
import anonymous.tlsattacker.tls.record.Record;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.util.RandomHelper;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * TLS Protocol message is the message included in the Record message.
 * 
 * @author anonymous
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
@XmlRootElement
public abstract class ProtocolMessage extends ModifiableVariableHolder implements ProtocolMessageHandlerBearer,
	Serializable {

    /**
     * content type
     */
    protected ProtocolMessageType protocolMessageType;

    /**
     * describes if the messages are coming from the client or the server.
     */
    protected ConnectionEnd messageIssuer;

    /**
     * List of preconfigured records for this protocol message
     */
    protected List<Record> records;

    /**
     * Defines if the message should be sent during the workflow. Using this
     * flag it is possible to omit a message is sent during the handshake while
     * it is executed to initialize specific variables.
     */
    private boolean goingToBeSent = true;
    /**
     * Defines if the message should not be parsed and only forwarded during the
     * MitMworkflow.
     */
    private boolean goingToBeParsed = true;
    /**
     * Defines if the message should be modified during a workflow execution
     * with MitMworkflowExecutor
     */
    private boolean goingToBeModified = false;
    /**
     * resulting message
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PLAIN_PROTOCOL_MESSAGE)
    protected ModifiableByteArray completeResultingMessage;

    @Override
    public abstract ProtocolMessageHandler getProtocolMessageHandler(TlsContext tlsContext);

    public ProtocolMessageType getProtocolMessageType() {
	return protocolMessageType;
    }

    public ConnectionEnd getMessageIssuer() {
	return messageIssuer;
    }

    public void setMessageIssuer(ConnectionEnd messageIssuer) {
	this.messageIssuer = messageIssuer;
    }

    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = Record.class, name = "Record"),
	    @XmlElement(type = DtlsRecord.class, name = "DtlsRecord") })
    public List<Record> getRecords() {
	return records;
    }

    public void setRecords(List<Record> records) {
	this.records = records;
    }

    public void addRecord(Record record) {
	if (this.records == null) {
	    this.records = new LinkedList<>();
	}
	this.records.add(record);
    }

    public boolean isGoingToBeSent() {
	return goingToBeSent;
    }

    public void setGoingToBeSent(boolean goingToBeSent) {
	this.goingToBeSent = goingToBeSent;
    }

    public boolean isGoingToBeParsed() {
	return goingToBeParsed;
    }

    public void setGoingToBeParsed(boolean goingToBeParsed) {
	this.goingToBeParsed = goingToBeParsed;
    }

    public boolean isGoingToBeModified() {
	return goingToBeModified;
    }

    public void setGoingToBeModified(boolean goingToBeModified) {
	this.goingToBeModified = goingToBeModified;
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
	List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
	if (records != null) {
	    for (Record r : records) {
		holders.add(r);
	    }
	}
	return holders;
    }

    @Override
    public Field getRandomModifiableVariableField() {
	List<Field> fields = getAllModifiableVariableFields();
	int randomField = RandomHelper.getRandom().nextInt(fields.size());
	return fields.get(randomField);
    }

    public ModifiableByteArray getCompleteResultingMessage() {
	return completeResultingMessage;
    }

    public void setCompleteResultingMessage(ModifiableByteArray completeResultingMessage) {
	this.completeResultingMessage = completeResultingMessage;
    }

    public void setCompleteResultingMessage(byte[] completeResultingMessage) {
	this.completeResultingMessage = ModifiableVariableFactory.safelySetValue(this.completeResultingMessage,
		completeResultingMessage);
    }

    public abstract String toCompactString();

}
