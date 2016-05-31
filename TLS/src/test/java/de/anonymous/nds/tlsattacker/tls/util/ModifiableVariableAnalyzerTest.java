/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.tls.util;

import anonymous.tlsattacker.modifiablevariable.util.ModifiableVariableAnalyzer;
import anonymous.tlsattacker.eap.ClientHello;
import anonymous.tlsattacker.tls.protocol.handshake.ClientHelloMessage;
import java.lang.reflect.Field;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class ModifiableVariableAnalyzerTest {

    public ModifiableVariableAnalyzerTest() {
    }

    /**
     * Test of getAllModifiableVariableFields method, of class
     * ModifiableVariableAnalyzer.
     * 
     */
    @Test
    public void testGetAllModifiableVariableFields() {
	ClientHelloMessage chm = new ClientHelloMessage();
	String[] fieldNames = { "compressionLength", "cipherSuiteLength", "cipherSuites", "compressions",
		"protocolVersion", "unixTime", "random", "sessionIdLength", "sessionId", "type",
		"completeResultingMessage" };
	List<Field> fields = ModifiableVariableAnalyzer.getAllModifiableVariableFields(chm);
	for (String fn : fieldNames) {
	    assertTrue(containsFieldName(fn, fields));
	}
	assertFalse(containsFieldName("somename", fields));
    }

    /**
     * Test of getRandomModifiableVariableField method, of class
     * ModifiableVariableAnalyzer.
     */
    @Test
    public void testGetRandomModifiableVariableField() {
    }

    private boolean containsFieldName(String name, List<Field> list) {
	for (Field f : list) {
	    if (f.getName().equals(name)) {
		return true;
	    }
	}
	return false;
    }

}
