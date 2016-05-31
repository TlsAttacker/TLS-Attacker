/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.transport;

import java.io.IOException;

/**
 * @author anonymous anonymous <anonymous.anonymous@anonymous>
 */
public interface TransportHandler {

    void closeConnection();

    byte[] fetchData() throws IOException;

    void initialize(String address, int port) throws IOException;

    void sendData(byte[] data) throws IOException;

}
