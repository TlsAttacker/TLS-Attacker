/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.transport;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.DatagramPacket;
import java.net.SocketException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @author anonymous Pfützenreuter <anonymous.Pfuetzenreuter@anonymous>
 */
public class UDPTransportHandler implements TransportHandler {

    private static final Logger LOGGER = LogManager.getLogger(UDPTransportHandler.class);

    private static final int DEFAULT_TLS_TIMEOUT = 3000;

    private int tlsTimeout = DEFAULT_TLS_TIMEOUT;

    private DatagramSocket datagramSocket;

    private final DatagramPacket receivedPacket = new DatagramPacket(new byte[65527], 65527);

    private DatagramPacket sentPacket;

    private long responseNanos = -1;

    @Override
    public void initialize(String remoteAddress, int remotePort) throws IOException {
	datagramSocket = new DatagramSocket();
	datagramSocket.setSoTimeout(DEFAULT_TLS_TIMEOUT);
	datagramSocket.connect(InetAddress.getByName(remoteAddress), remotePort);

	sentPacket = new DatagramPacket(new byte[0], 0, datagramSocket.getInetAddress(), datagramSocket.getPort());

	if (LOGGER.isDebugEnabled()) {
	    StringBuilder logOut = new StringBuilder();
	    logOut.append("Socket bound to \"");
	    logOut.append(datagramSocket.getLocalAddress().getCanonicalHostName());
	    logOut.append(":");
	    logOut.append(datagramSocket.getLocalPort());
	    logOut.append("\". Specified remote host and port: \"");
	    logOut.append(datagramSocket.getInetAddress().getCanonicalHostName());
	    logOut.append(":");
	    logOut.append(datagramSocket.getPort());
	    logOut.append("\".");
	    LOGGER.debug(logOut.toString());
	}
    }

    @Override
    public void sendData(byte[] data) throws IOException {
	sentPacket.setData(data, 0, data.length);
	datagramSocket.send(sentPacket);
    }

    @Override
    public byte[] fetchData() throws IOException {
	responseNanos = System.nanoTime();
	datagramSocket.receive(receivedPacket);
	responseNanos = System.nanoTime() - responseNanos;
	return Arrays.copyOfRange(receivedPacket.getData(), 0, receivedPacket.getLength());
    }

    @Override
    public void closeConnection() {
	datagramSocket.close();
	LOGGER.debug("Socket closed.");
    }

    public int getTlsTimeout() {
	return tlsTimeout;
    }

    public void setTlsTimeout(int tlsTimeout) {
	this.tlsTimeout = tlsTimeout;
	if (datagramSocket != null) {
	    try {
		datagramSocket.setSoTimeout(this.tlsTimeout);
	    } catch (SocketException e) {
		LOGGER.debug("Failed to set socket timeout. Exception:\n{}", e.getMessage());
	    }
	}
    }

    public int getLocalPort() {
	return datagramSocket.getLocalPort();
    }

    public InetAddress getLocalAddress() {
	return datagramSocket.getLocalAddress();
    }

    public int getRemotePort() {
	return datagramSocket.getPort();
    }

    public InetAddress getRemoteAddress() {
	return datagramSocket.getInetAddress();
    }

    public long getResponseTimeNanos() {
	return responseNanos;
    }
}