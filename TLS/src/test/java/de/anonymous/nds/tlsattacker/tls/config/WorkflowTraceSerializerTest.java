/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.config;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import anonymous.tlsattacker.modifiablevariable.VariableModification;
import anonymous.tlsattacker.modifiablevariable.integer.IntegerModificationFactory;
import anonymous.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import anonymous.tlsattacker.tls.protocol.ProtocolMessage;
import anonymous.tlsattacker.tls.record.Record;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.workflow.WorkflowTrace;
import anonymous.tlsattacker.tls.workflow.WorkflowConfigurationFactory;
import anonymous.tlsattacker.util.RandomHelper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.junit.Test;

/**
 * 
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class WorkflowTraceSerializerTest {

    private static Logger LOGGER = LogManager.getLogger(WorkflowTraceSerializerTest.class);

    /**
     * Test of write method, of class WorkflowTraceSerializer.
     * 
     * @throws java.lang.Exception
     */
    @Test
    public void testWriteRead() throws Exception {
	WorkflowConfigurationFactory factory = WorkflowConfigurationFactory.createInstance(new ClientCommandConfig());
	TlsContext context = factory.createFullTlsContext();

	// pick random protocol message and initialize a record with modifiable
	// variable
	List<ProtocolMessage> pms = context.getWorkflowTrace().getProtocolMessages();
	int random = RandomHelper.getRandom().nextInt(pms.size());
	List<Record> records = new LinkedList<>();
	Record r = new Record();
	ModifiableInteger mv = ModifiableVariableFactory.createIntegerModifiableVariable();
	VariableModification<Integer> iam = IntegerModificationFactory.createRandomModification();
	iam.setPostModification(IntegerModificationFactory.explicitValue(random));
	mv.setModification(iam);
	r.setLength(mv);
	records.add(r);
	pms.get(random).setRecords(records);

	ByteArrayOutputStream os = new ByteArrayOutputStream();
	WorkflowTraceSerializer.write(os, context.getWorkflowTrace());

	String serializedWorkflow = new String(os.toByteArray());

	LOGGER.debug(serializedWorkflow);

	ByteArrayInputStream bis = new ByteArrayInputStream(serializedWorkflow.getBytes());
	WorkflowTrace wt = WorkflowTraceSerializer.read(bis);

	os = new ByteArrayOutputStream();
	WorkflowTraceSerializer.write(os, wt);

	Assert.assertArrayEquals("The serialized workflows have to be equal", serializedWorkflow.getBytes(),
		os.toByteArray());
    }

}
