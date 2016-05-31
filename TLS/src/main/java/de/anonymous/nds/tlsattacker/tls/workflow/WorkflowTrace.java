/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.workflow;

import anonymous.tlsattacker.dtls.protocol.handshake.ClientHelloDtlsMessage;
import anonymous.tlsattacker.dtls.protocol.handshake.HelloVerifyRequestMessage;
import anonymous.tlsattacker.modifiablevariable.HoldsModifiableVariable;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.protocol.ProtocolMessage;
import anonymous.tlsattacker.tls.protocol.alert.AlertMessage;
import anonymous.tlsattacker.tls.protocol.application.ApplicationMessage;
import anonymous.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.tls.protocol.handshake.HandshakeMessage;
import anonymous.tlsattacker.tls.constants.ProtocolMessageType;
import anonymous.tlsattacker.tls.constants.ProtocolVersion;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateRequestMessage;
import anonymous.tlsattacker.tls.protocol.handshake.CertificateVerifyMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import anonymous.tlsattacker.tls.protocol.handshake.DHClientKeyExchangeMessage;
import anonymous.tlsattacker.tls.protocol.handshake.DHEServerKeyExchangeMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ECDHClientKeyExchangeMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ECDHEServerKeyExchangeMessage;
import anonymous.tlsattacker.tls.protocol.handshake.FinishedMessage;
import anonymous.tlsattacker.tls.protocol.handshake.RSAClientKeyExchangeMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloDoneMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import anonymous.tlsattacker.tls.protocol.heartbeat.HeartbeatMessage;
import java.io.Serializable;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * A wrapper class over a list of protocol messages maintained in the TLS
 * context.
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class WorkflowTrace implements Serializable {

    /**
     * Workflow
     */
    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElements(value = { @XmlElement(type = ProtocolMessage.class, name = "ProtocolMessage"),
	    @XmlElement(type = CertificateMessage.class, name = "Certificate"),
	    @XmlElement(type = CertificateVerifyMessage.class, name = "CertificateVerify"),
	    @XmlElement(type = CertificateRequestMessage.class, name = "CertificateRequest"),
	    @XmlElement(type = ClientHelloMessage.class, name = "ClientHello"),
	    @XmlElement(type = ClientHelloDtlsMessage.class, name = "DtlsClientHello"),
	    @XmlElement(type = HelloVerifyRequestMessage.class, name = "HelloVerifyRequest"),
	    @XmlElement(type = DHClientKeyExchangeMessage.class, name = "DHClientKeyExchange"),
	    @XmlElement(type = DHEServerKeyExchangeMessage.class, name = "DHEServerKeyExchange"),
	    @XmlElement(type = ECDHClientKeyExchangeMessage.class, name = "ECDHClientKeyExchange"),
	    @XmlElement(type = ECDHEServerKeyExchangeMessage.class, name = "ECDHEServerKeyExchange"),
	    @XmlElement(type = FinishedMessage.class, name = "Finished"),
	    @XmlElement(type = RSAClientKeyExchangeMessage.class, name = "RSAClientKeyExchange"),
	    @XmlElement(type = ServerHelloDoneMessage.class, name = "ServerHelloDone"),
	    @XmlElement(type = ServerHelloMessage.class, name = "ServerHello"),
	    @XmlElement(type = AlertMessage.class, name = "Alert"),
	    @XmlElement(type = ApplicationMessage.class, name = "Application"),
	    @XmlElement(type = ChangeCipherSpecMessage.class, name = "ChangeCipherSpec"),
	    @XmlElement(type = HeartbeatMessage.class, name = "Heartbeat") })
    private List<ProtocolMessage> protocolMessages;

    private String name;

    private ProtocolVersion protocolVersion;

    /**
     * Initializes the workflow trace with an empty list of protocol messages
     */
    public WorkflowTrace() {
	this.protocolMessages = new LinkedList<>();
    }

    /**
     * Adds protocol message to the list
     * 
     * @param pm
     * @return Returns true if the list was changed
     */
    public boolean add(ProtocolMessage pm) {
	return protocolMessages.add(pm);
    }

    public ProtocolMessage remove(int index) {
	return protocolMessages.remove(index);
    }

    public List<ProtocolMessage> getProtocolMessages() {
	return protocolMessages;
    }

    public void setProtocolMessages(List<ProtocolMessage> protocolMessages) {
	this.protocolMessages = protocolMessages;
    }

    /**
     * Returns a list of protocol messages of a specific type
     * 
     * @param type
     * @return
     */
    public List<Integer> getProtocolMessagePositions(ProtocolMessageType type) {
	List<Integer> positions = new LinkedList<>();
	int position = 0;
	for (ProtocolMessage pm : protocolMessages) {
	    if (pm.getProtocolMessageType() == type) {
		positions.add(position);
	    }
	    position++;
	}
	return positions;
    }

    public boolean containsProtocolMessage(ProtocolMessageType type) {
	return !getProtocolMessagePositions(type).isEmpty();
    }

    /**
     * Returns the first protocol message of a specified type, which is
     * contained in the list of protocol messages. Throws an
     * IllegalArgumentException if no message is found.
     * 
     * @param type
     * @return
     */
    public ProtocolMessage getFirstProtocolMessage(ProtocolMessageType type) {
	for (ProtocolMessage pm : protocolMessages) {
	    if (pm.getProtocolMessageType() == type) {
		return pm;
	    }
	}
	throw new IllegalArgumentException("The Workflow does not contain any " + type);
    }

    /**
     * Returns a list of handshake messages of a given type.
     * 
     * @param type
     * @return
     */
    public List<Integer> getHandshakeMessagePositions(HandshakeMessageType type) {
	List<Integer> positions = new LinkedList<>();
	int position = 0;
	for (ProtocolMessage pm : protocolMessages) {
	    if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
		HandshakeMessage hm = (HandshakeMessage) pm;
		if (hm.getHandshakeMessageType() == type) {
		    positions.add(position);
		}
	    }
	    position++;
	}
	return positions;
    }

    public boolean containsHandshakeMessage(HandshakeMessageType type) {
	return !getHandshakeMessagePositions(type).isEmpty();
    }

    /**
     * Returns the first handshake message of a specified type, which is
     * contained in the list of protocol messages. Throws an
     * IllegalArgumentException if no message is found.
     * 
     * @param type
     * @return
     */
    public HandshakeMessage getFirstHandshakeMessage(HandshakeMessageType type) {
	for (ProtocolMessage pm : protocolMessages) {
	    if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
		HandshakeMessage hm = (HandshakeMessage) pm;
		if (hm.getHandshakeMessageType() == type) {
		    return hm;
		}
	    }
	}
	throw new IllegalArgumentException("The Workflow does not contain any " + type);
    }

    public ProtocolMessage getLastProtocolMesssage() {
	int size = protocolMessages.size();
	return protocolMessages.get(size - 1);
    }

    private List<ProtocolMessage> getMessages(ConnectionEnd peer) {
	List<ProtocolMessage> messages = new LinkedList<>();
	for (ProtocolMessage pm : protocolMessages) {
	    if (pm.getMessageIssuer() == peer) {
		messages.add(pm);
	    }
	}
	return messages;
    }

    public List<ProtocolMessage> getClientMessages() {
	return getMessages(ConnectionEnd.CLIENT);
    }

    public List<ProtocolMessage> getServerMessages() {
	return getMessages(ConnectionEnd.SERVER);
    }

    private boolean containsFinishedMessage(ConnectionEnd peer) {
	for (ProtocolMessage pm : protocolMessages) {
	    if (pm.getProtocolMessageType() == ProtocolMessageType.HANDSHAKE) {
		HandshakeMessage hm = (HandshakeMessage) pm;
		if (hm.getHandshakeMessageType() == HandshakeMessageType.FINISHED) {
		    if (hm.getMessageIssuer() == peer) {
			return true;
		    }
		}
	    }
	}
	return false;
    }

    public boolean containsClientFinished() {
	return containsFinishedMessage(ConnectionEnd.CLIENT);
    }

    public boolean containsServerFinished() {
	return containsFinishedMessage(ConnectionEnd.SERVER);
    }

    public String getName() {
	return name;
    }

    public void setName(String name) {
	this.name = name;
    }

    public ProtocolVersion getProtocolVersion() {
	return protocolVersion;
    }

    public void setProtocolVersion(ProtocolVersion protocolVersion) {
	this.protocolVersion = protocolVersion;
    }
}
