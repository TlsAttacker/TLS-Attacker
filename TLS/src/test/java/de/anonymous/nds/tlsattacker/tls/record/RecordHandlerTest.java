/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.record;

import anonymous.tlsattacker.tls.record.RecordHandler;
import anonymous.tlsattacker.tls.config.ClientCommandConfig;
import anonymous.tlsattacker.tls.constants.ProtocolMessageType;
import anonymous.tlsattacker.tls.record.Record;
import anonymous.tlsattacker.tls.workflow.TlsContext;
import anonymous.tlsattacker.tls.workflow.WorkflowConfigurationFactory;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public class RecordHandlerTest {

    RecordHandler recordHandler;

    public RecordHandlerTest() {
	Security.addProvider(new BouncyCastleProvider());
	ClientCommandConfig config = new ClientCommandConfig();
	WorkflowConfigurationFactory factory = WorkflowConfigurationFactory.createInstance(config);
	TlsContext context = factory.createHandshakeTlsContext();
	context.setRecordHandler(new RecordHandler(context));
	recordHandler = context.getRecordHandler();
    }

    /**
     * Test of wrapData method, of class RecordHandler.
     */
    @Test
    public void testWrapData() {
	byte[] data = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	byte[] result;
	List<Record> records = new LinkedList<>();
	records.add(new Record());
	result = recordHandler.wrapData(data, ProtocolMessageType.HANDSHAKE, records);

	byte[] expectedResult = { 22, 3, 3, 0, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

	assertEquals(records.size(), 1);
	assertArrayEquals(expectedResult, result);

	Record preconfiguredRecord = new Record();
	preconfiguredRecord.setMaxRecordLengthConfig(2);
	records.clear();
	records.add(preconfiguredRecord);

	result = recordHandler.wrapData(data, ProtocolMessageType.HANDSHAKE, records);
	assertEquals(2, records.size());
	assertEquals(20, result.length);

	records.clear();
	preconfiguredRecord = new Record();
	preconfiguredRecord.setMaxRecordLengthConfig(2);
	records.add(preconfiguredRecord);
	records.add(preconfiguredRecord);

	result = recordHandler.wrapData(data, ProtocolMessageType.HANDSHAKE, records);
	assertEquals(3, records.size());
	assertEquals(25, result.length);

	records = recordHandler.parseRecords(result);
	assertEquals(3, records.size());
    }
}
