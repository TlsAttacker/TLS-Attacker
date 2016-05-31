/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.workflow;

import anonymous.tlsattacker.modifiablevariable.bytearray.ByteArrayModificationFactory;
import anonymous.tlsattacker.modifiablevariable.bytearray.ModifiableByteArray;
import anonymous.tlsattacker.modifiablevariable.integer.IntegerModificationFactory;
import anonymous.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import anonymous.tlsattacker.tls.config.ClientCommandConfig;
import anonymous.tlsattacker.tls.constants.ConnectionEnd;
import anonymous.tlsattacker.tls.protocol.ProtocolMessage;
import anonymous.tlsattacker.tls.protocol.alert.AlertMessage;
import anonymous.tlsattacker.tls.protocol.application.ApplicationMessage;
import anonymous.tlsattacker.tls.protocol.ccs.ChangeCipherSpecMessage;
import anonymous.tlsattacker.tls.constants.ProtocolMessageType;
import anonymous.tlsattacker.tls.constants.HandshakeMessageType;
import anonymous.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import anonymous.tlsattacker.tls.record.Record;
import java.util.LinkedList;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class TlsContextAnalyzerTest {

    public TlsContextAnalyzerTest() {
    }

    /**
     * Test of getNextProtocolMessageFromPeer method, of class
     * TlsContextAnalyzer.
     */
    @Test
    public void testGetNextProtocolMessageFromPeer() {
	WorkflowConfigurationFactory factory = WorkflowConfigurationFactory.createInstance(new ClientCommandConfig());
	TlsContext context = factory.createFullTlsContext();
	context.setMyConnectionEnd(ConnectionEnd.CLIENT);

	ProtocolMessage pm = TlsContextAnalyzer.getNextProtocolMessageFromPeer(context, 1);
	assertEquals(ProtocolMessageType.HANDSHAKE, pm.getProtocolMessageType());

	pm = TlsContextAnalyzer.getNextProtocolMessageFromPeer(context, 4);
	assertEquals(ProtocolMessageType.CHANGE_CIPHER_SPEC, pm.getProtocolMessageType());
    }

    /**
     * Test of wasAlertAfterModifiedMessageSent method, of class
     * TlsContextAnalyzer.
     */
    @Test
    public void testContainsAlertAfterModifiedMessage() {
	WorkflowConfigurationFactory factory = WorkflowConfigurationFactory.createInstance(new ClientCommandConfig());
	TlsContext context = factory.createFullTlsContext();
	context.setMyConnectionEnd(ConnectionEnd.CLIENT);

	ApplicationMessage am = (ApplicationMessage) context.getWorkflowTrace().getFirstProtocolMessage(
		ProtocolMessageType.APPLICATION_DATA);
	ModifiableByteArray data = new ModifiableByteArray();
	data.setOriginalValue(new byte[0]);
	data.setModification(ByteArrayModificationFactory.explicitValue(new byte[] { 1 }));
	am.setData(data);

	assertEquals("There is no alert after modification.", TlsContextAnalyzer.AnalyzerResponse.NO_ALERT,
		TlsContextAnalyzer.containsAlertAfterModifiedMessage(context));

	context.getWorkflowTrace().getProtocolMessages().add(new AlertMessage(ConnectionEnd.SERVER));
	assertEquals("There is an alert after modification.", TlsContextAnalyzer.AnalyzerResponse.ALERT,
		TlsContextAnalyzer.containsAlertAfterModifiedMessage(context));
    }

    /**
     * Test of wasAlertAfterMissingMessageSent method, of class
     * TlsContextAnalyzer.
     */
    @Test
    public void testContainsAlertAfterMissingMessage() {
	WorkflowConfigurationFactory factory = WorkflowConfigurationFactory.createInstance(new ClientCommandConfig());
	TlsContext context = factory.createFullTlsContext();
	context.setMyConnectionEnd(ConnectionEnd.CLIENT);

	assertEquals("There is no missing message", TlsContextAnalyzer.AnalyzerResponse.NO_MODIFICATION,
		TlsContextAnalyzer.containsAlertAfterMissingMessage(context));

	ProtocolMessage pm = context.getWorkflowTrace().getFirstProtocolMessage(ProtocolMessageType.CHANGE_CIPHER_SPEC);
	pm.setGoingToBeSent(false);

	assertEquals("There is no alert after a missing message.", TlsContextAnalyzer.AnalyzerResponse.NO_ALERT,
		TlsContextAnalyzer.containsAlertAfterMissingMessage(context));

	context.getWorkflowTrace().getProtocolMessages().add(new AlertMessage(ConnectionEnd.SERVER));
	assertEquals("There is no alert after a missing message (alert is sent at the end).",
		TlsContextAnalyzer.AnalyzerResponse.NO_ALERT,
		TlsContextAnalyzer.containsAlertAfterMissingMessage(context));

	int finishedPosition = context.getWorkflowTrace().getHandshakeMessagePositions(HandshakeMessageType.FINISHED)
		.get(0);
	context.getWorkflowTrace().getProtocolMessages()
		.add(finishedPosition + 1, new AlertMessage(ConnectionEnd.SERVER));
	assertEquals("There is an alert after a missing message.", TlsContextAnalyzer.AnalyzerResponse.ALERT,
		TlsContextAnalyzer.containsAlertAfterMissingMessage(context));
    }

    /**
     * Test of wasAlertAfterUnexpectedMessageSent method, of class
     * TlsContextAnalyzer.
     */
    @Test
    public void testContainsAlertAfterUnexpectedMessage() {
	WorkflowConfigurationFactory factory = WorkflowConfigurationFactory.createInstance(new ClientCommandConfig());
	TlsContext context = factory.createFullTlsContext();
	context.setMyConnectionEnd(ConnectionEnd.CLIENT);

	assertEquals("There is no unexpected message", TlsContextAnalyzer.AnalyzerResponse.NO_MODIFICATION,
		TlsContextAnalyzer.containsAlertAfterUnexpectedMessage(context));

	int position = context.getWorkflowTrace().getProtocolMessagePositions(ProtocolMessageType.CHANGE_CIPHER_SPEC)
		.get(0);
	context.getWorkflowTrace().getProtocolMessages()
		.add(position, new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));

	assertEquals("There is no alert after an unexpected message.", TlsContextAnalyzer.AnalyzerResponse.NO_ALERT,
		TlsContextAnalyzer.containsAlertAfterUnexpectedMessage(context));

	context.getWorkflowTrace().getProtocolMessages().add(new AlertMessage(ConnectionEnd.SERVER));
	assertEquals("There is no alert after an unexpected message (alert is sent at the end).",
		TlsContextAnalyzer.AnalyzerResponse.NO_ALERT,
		TlsContextAnalyzer.containsAlertAfterUnexpectedMessage(context));

	context.getWorkflowTrace().getProtocolMessages().add(position + 2, new AlertMessage(ConnectionEnd.SERVER));
	assertEquals("There is an alert after an unexpected message.", TlsContextAnalyzer.AnalyzerResponse.ALERT,
		TlsContextAnalyzer.containsAlertAfterUnexpectedMessage(context));

	context.getWorkflowTrace().getProtocolMessages().add(1, new AlertMessage(ConnectionEnd.SERVER));
	assertEquals("There is an alert after an unexpected message.", TlsContextAnalyzer.AnalyzerResponse.ALERT,
		TlsContextAnalyzer.containsAlertAfterUnexpectedMessage(context));

	context.getWorkflowTrace().setProtocolMessages(context.getWorkflowTrace().getProtocolMessages().subList(0, 2));
	assertEquals("There is an alert after a ClientHello message.",
		TlsContextAnalyzer.AnalyzerResponse.NO_MODIFICATION,
		TlsContextAnalyzer.containsAlertAfterUnexpectedMessage(context));
    }

    /**
     * Test of testContainsModifiedMessage method, of class TlsContextAnalyzer.
     */
    @Test
    public void testContainsModifiedMessage() {
	WorkflowConfigurationFactory factory = WorkflowConfigurationFactory.createInstance(new ClientCommandConfig());
	TlsContext context = factory.createFullTlsContext();
	context.setMyConnectionEnd(ConnectionEnd.CLIENT);

	assertFalse("There is no modification.", TlsContextAnalyzer.containsModifiedMessage(context));

	ApplicationMessage am = (ApplicationMessage) context.getWorkflowTrace().getFirstProtocolMessage(
		ProtocolMessageType.APPLICATION_DATA);
	ModifiableByteArray data = new ModifiableByteArray();
	data.setOriginalValue(new byte[] { 1 });
	data.setModification(ByteArrayModificationFactory.explicitValue(new byte[0]));
	am.setData(data);

	assertTrue("There is a modification.", TlsContextAnalyzer.containsModifiedMessage(context));
    }

    /**
     * Test of testContainsMissingMessage method, of class TlsContextAnalyzer.
     */
    @Test
    public void testContainsMissingMessage() {
	WorkflowConfigurationFactory factory = WorkflowConfigurationFactory.createInstance(new ClientCommandConfig());
	TlsContext context = factory.createFullTlsContext();
	context.setMyConnectionEnd(ConnectionEnd.CLIENT);

	assertFalse("There is no missing message", TlsContextAnalyzer.containsMissingMessage(context));

	ProtocolMessage pm = context.getWorkflowTrace().getFirstProtocolMessage(ProtocolMessageType.CHANGE_CIPHER_SPEC);
	pm.setGoingToBeSent(false);

	assertTrue("There is a missing message.", TlsContextAnalyzer.containsMissingMessage(context));
    }

    /**
     * Test of testContainsUnexpectedMessage method, of class
     * TlsContextAnalyzer.
     */
    @Test
    public void testContainsUnexpectedMessage() {
	WorkflowConfigurationFactory factory = WorkflowConfigurationFactory.createInstance(new ClientCommandConfig());
	TlsContext context = factory.createFullTlsContext();
	context.setMyConnectionEnd(ConnectionEnd.CLIENT);

	assertFalse("There is no unexpected message", TlsContextAnalyzer.containsUnexpectedMessage(context));

	int position = context.getWorkflowTrace().getProtocolMessagePositions(ProtocolMessageType.CHANGE_CIPHER_SPEC)
		.get(0);
	context.getWorkflowTrace().getProtocolMessages()
		.add(position, new ChangeCipherSpecMessage(ConnectionEnd.CLIENT));

	assertTrue("There is an unexpected message.", TlsContextAnalyzer.containsUnexpectedMessage(context));
    }

    /**
     * Test of containsModifiableVariableModification method, of class
     * TlsContextAnalyzer.
     */
    @Test
    public void testContainsModifiableVariableModification() {
	ClientHelloMessage ch = new ClientHelloMessage();
	assertFalse("This ClientHello message contains no modification",
		TlsContextAnalyzer.containsModifiableVariableModification(ch));
	ch.setCipherSuiteLength(2);
	assertFalse("This ClientHello message contains no modification",
		TlsContextAnalyzer.containsModifiableVariableModification(ch));
	ModifiableInteger length = new ModifiableInteger();
	length.setOriginalValue(2);
	length.setModification(IntegerModificationFactory.add(1));
	ch.setCipherSuiteLength(length);
	assertTrue("This ClientHello message contains a modification in the CipherSuite Length variable",
		TlsContextAnalyzer.containsModifiableVariableModification(ch));

	ch = new ClientHelloMessage();
	List<Record> records = new LinkedList<>();
	Record r = new Record();
	r.setLength(length);
	records.add(r);
	ch.setRecords(records);
	assertTrue("This ClientHello message contains a modification in the record Length variable",
		TlsContextAnalyzer.containsModifiableVariableModification(ch));
    }

}
