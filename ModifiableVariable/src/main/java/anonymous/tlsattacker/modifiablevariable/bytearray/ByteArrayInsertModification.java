/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable.bytearray;

import anonymous.tlsattacker.util.ArrayConverter;
import anonymous.tlsattacker.modifiablevariable.VariableModification;
import anonymous.tlsattacker.util.ByteArrayAdapter;
import java.util.Arrays;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
@XmlRootElement
@XmlType(propOrder = { "bytesToInsert", "startPosition", "modificationFilter", "postModification" })
public class ByteArrayInsertModification extends VariableModification<byte[]> {

    private byte[] bytesToInsert;

    private int startPosition;

    public ByteArrayInsertModification() {

    }

    public ByteArrayInsertModification(byte[] bytesToInsert, int startPosition) {
	this.bytesToInsert = bytesToInsert;
	this.startPosition = startPosition;
    }

    @Override
    protected byte[] modifyImplementationHook(byte[] input) {
	if (input == null) {
	    input = new byte[0];
	}
	byte[] result = input.clone();
	int start = startPosition;
	if (start < 0) {
	    start += input.length;
	    if (start < 0) {
		throw new IllegalArgumentException("Trying to insert from too negative Startposition. start = "
			+ startPosition);
	    }
	}
	if (startPosition > input.length) {
	    throw new ArrayIndexOutOfBoundsException("Trying to insert behind the Array. ArraySize:" + input.length
		    + " Insert Position:" + startPosition);
	}
	byte[] ret1 = Arrays.copyOf(input, start);
	byte[] ret3 = null;
	if ((start) < input.length) {
	    ret3 = Arrays.copyOfRange(input, start, input.length);
	}
	return ArrayConverter.concatenate(ret1, bytesToInsert, ret3);
    }

    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    public byte[] getBytesToInsert() {
	return bytesToInsert;
    }

    public void setBytesToInsert(byte[] bytesToInsert) {
	this.bytesToInsert = bytesToInsert;
    }

    public int getStartPosition() {
	return startPosition;
    }

    public void setStartPosition(int startPosition) {
	this.startPosition = startPosition;
    }
}
