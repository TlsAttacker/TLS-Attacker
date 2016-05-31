/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.config;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariable;
import anonymous.tlsattacker.modifiablevariable.ModificationFilter;
import anonymous.tlsattacker.modifiablevariable.VariableModification;
import anonymous.tlsattacker.tls.protocol.ProtocolMessage;
import anonymous.tlsattacker.tls.protocol.extension.ExtensionMessage;
import anonymous.tlsattacker.tls.workflow.WorkflowTrace;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public final class WorkflowTraceSerializer {

    /** context initialization is expensive, we need to do that only once */
    private static JAXBContext context;

    private WorkflowTraceSerializer() {

    }

    /**
     * Returns an initialized JaxbContext
     * 
     * @return
     * @throws JAXBException
     * @throws IOException
     */
    private static JAXBContext getJAXBContext() throws JAXBException, IOException {
	if (context == null) {
	    context = JAXBContext.newInstance(ExtensionMessage.class, WorkflowTrace.class, ProtocolMessage.class,
		    ModificationFilter.class, VariableModification.class, ModifiableVariable.class);
	}
	return context;
    }

    /**
     * 
     * @param outputStream
     * @param workflowTrace
     * @throws JAXBException
     * @throws IOException
     */
    public static void write(OutputStream outputStream, WorkflowTrace workflowTrace) throws JAXBException, IOException {
	context = getJAXBContext();
	Marshaller m = context.createMarshaller();
	m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

	m.marshal(workflowTrace, outputStream);
	outputStream.close();
    }

    /**
     * 
     * @param inputStream
     * @return
     * @throws JAXBException
     * @throws IOException
     * @throws XMLStreamException
     */
    public static WorkflowTrace read(InputStream inputStream) throws JAXBException, IOException, XMLStreamException {
	context = getJAXBContext();
	Unmarshaller m = context.createUnmarshaller();

	XMLInputFactory xif = XMLInputFactory.newFactory();
	xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
	xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
	XMLStreamReader xsr = xif.createXMLStreamReader(inputStream);

	WorkflowTrace wt = (WorkflowTrace) m.unmarshal(xsr);
	inputStream.close();
	return wt;
    }
}
