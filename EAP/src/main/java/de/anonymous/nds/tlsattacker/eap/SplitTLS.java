/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.eap;

import java.nio.ByteBuffer;

/**
 * Split the TLS-Packets from TLS-Attacker for Fragmentation
 * 
 * @author anonymous Lange <flx.lange@gmail.com>
 */
public class SplitTLS {

    byte[] sslraw;

    byte[][] clientresponse;

    private static SplitTLS splittls = new SplitTLS();

    private SplitTLS() {
    }

    public static SplitTLS getInstance() {
	return splittls;
    }

    public byte[][] split(byte[] sslraw) {

	int i, fragmentsize = 1024;
	this.sslraw = sslraw;

	i = (sslraw.length / fragmentsize) + 1;
	clientresponse = new byte[i][];

	for (int y = 0; y < i; y++) {

	    if (y < (i - 1)) {

		clientresponse[y] = new byte[fragmentsize];
		System.arraycopy(sslraw, y * fragmentsize, clientresponse[y], 0, fragmentsize);

	    } else {

		clientresponse[y] = new byte[sslraw.length - (y * fragmentsize)];
		System.arraycopy(sslraw, y * fragmentsize, clientresponse[y], 0, sslraw.length - (y * fragmentsize));

	    }

	}

	return clientresponse;

    }

    public byte[] getFragment(int count) {

	return clientresponse[count];

    }

    public byte[] getSize() {

	int size = 0;

	size = sslraw.length;

	return intToBytes(size);

    }

    public int getSizeInt() {

	int size = 0;

	size = sslraw.length;

	return size;

    }

    public int getCountPacket() {

	int size = 0;

	size = clientresponse.length;

	return size;

    }

    public byte[] intToBytes(final int i) {
	ByteBuffer bb = ByteBuffer.allocate(4);
	bb.putInt(i);
	return bb.array();
    }

}
