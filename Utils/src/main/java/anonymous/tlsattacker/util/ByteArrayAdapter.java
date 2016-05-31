/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.util;

import javax.xml.bind.annotation.adapters.XmlAdapter;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class ByteArrayAdapter extends XmlAdapter<String, byte[]> {

    @Override
    public byte[] unmarshal(String value) {
	value = value.replaceAll("\\s", "");
	return ArrayConverter.hexStringToByteArray(value);
    }

    @Override
    public String marshal(byte[] value) {
	return ArrayConverter.bytesToHexString(value);
    }

}
