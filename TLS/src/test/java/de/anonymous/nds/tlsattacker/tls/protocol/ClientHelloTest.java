/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.protocol;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariable;
import anonymous.tlsattacker.modifiablevariable.ModificationFilter;
import anonymous.tlsattacker.modifiablevariable.VariableModification;
import anonymous.tlsattacker.modifiablevariable.integer.IntegerAddModification;
import anonymous.tlsattacker.tls.config.ClientCommandConfig;
import anonymous.tlsattacker.tls.protocol.extension.ExtensionMessage;
import anonymous.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.workflow.WorkflowTrace;
import anonymous.tlsattacker.tls.workflow.WorkflowConfigurationFactory;
import anonymous.tlsattacker.util.ByteArrayAdapter;
import java.io.StringReader;
import java.io.StringWriter;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class ClientHelloTest {

    private final StringWriter writer;

    private final JAXBContext context;

    private final Marshaller m;

    private Unmarshaller um;

    public ClientHelloTest() throws Exception {
	writer = new StringWriter();
	context = JAXBContext.newInstance(ExtensionMessage.class, WorkflowTrace.class, ClientHelloMessage.class,
		ModificationFilter.class, IntegerAddModification.class, VariableModification.class,
		ModifiableVariable.class);
	m = context.createMarshaller();
	m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
	m.setAdapter(new ByteArrayAdapter());
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
    }

    @After
    public void tearDown() {
    }

    @Test
    public void simpleSerialization() throws JAXBException {
	ClientHelloMessage cl = new ClientHelloMessage();
	cl.setCipherSuiteLength(3);
	// cl.setCipherSuiteLength(new ModifiableInteger());
	cl.getCipherSuiteLength().setModification(new IntegerAddModification(2));
	m.marshal(cl, writer);

	String xmlString = writer.toString();
	System.out.println(xmlString);

	um = context.createUnmarshaller();
	ClientHelloMessage clu = (ClientHelloMessage) um.unmarshal(new StringReader(xmlString));

	writer.append("abcd");
	m.marshal(clu, writer);
	xmlString = writer.toString();
	System.out.println(xmlString);
    }

    @Test
    public void simpleSerialization2() throws Exception {
	ClientCommandConfig config = new ClientCommandConfig();
	WorkflowConfigurationFactory cf = WorkflowConfigurationFactory.createInstance(config);
	TlsContext context = cf.createHandshakeTlsContext();

	m.marshal(context.getWorkflowTrace(), writer);

	String xmlString = writer.toString();
	System.out.println(xmlString);
    }
}
