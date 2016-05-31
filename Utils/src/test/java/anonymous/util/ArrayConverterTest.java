/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.util;

import anonymous.tlsattacker.util.ArrayConverter;
import java.math.BigInteger;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 * @author anonymous Pfützenreuter <anonymous.Pfuetzenreuter@anonymous>
 */
public class ArrayConverterTest {

    /**
     * Test of longToUint64Bytes method, of class ArrayConverter.
     */
    @Test
    public void testLongToUint64Bytes() {
    }

    /**
     * Test of longToUint32Bytes method, of class ArrayConverter.
     */
    @Test
    public void testLongToUint32Bytes() {
    }

    /**
     * Test of intToBytes method, of class ArrayConverter.
     */
    @Test
    public void testIntToBytes() {
    }

    /**
     * Test of bytesToInt method, of class ArrayConverter.
     */
    @Test
    public void testBytesToInt() {
	byte[] toParse = { 0x16, 0x55 };
	int result = ArrayConverter.bytesToInt(toParse);
	assertEquals("The conversion result of {0x16, 0x55} should be 5717", 5717, result);
    }

    /**
     * Test of bytesToLong method, of class ArrayConverter.
     */
    @Test
    public void testBytesToLong() {
    }

    /**
     * Test of bytesToHexString method, of class ArrayConverter.
     */
    @Test
    public void testBytesToHexString_byteArr() {
    }

    /**
     * Test of bytesToHexString method, of class ArrayConverter.
     */
    @Test
    public void testBytesToHexString_byteArr_int() {
    }

    /**
     * Test of bytesToHexString method, of class ArrayConverter.
     */
    @Test
    public void testBytesToHexString_byteArr_boolean() {
    }

    /**
     * Test of bytesToHexString method, of class ArrayConverter.
     */
    @Test
    public void testBytesToHexString_3args() {
    }

    /**
     * Test of concatenate method, of class ArrayConverter.
     */
    @Test
    public void testConcatenate_GenericType() {
    }

    /**
     * Test of concatenate method, of class ArrayConverter.
     */
    @Test
    public void testConcatenate_byteArrArr() {
    }

    /**
     * Test of makeArrayNonZero method, of class ArrayConverter.
     */
    @Test
    public void testMakeArrayNonZero() {
    }

    /**
     * Test of bigIntegerToByteArray method, of class ArrayConverter.
     */
    @Test
    public void testBigIntegerToByteArray_3args() {
    }

    /**
     * Test of bigIntegerToByteArray method, of class ArrayConverter.
     */
    @Test
    public void testBigIntegerToByteArray_BigInteger() {
    }

    /**
     * Test of convertListToArray method, of class ArrayConverter.
     */
    @Test
    public void testConvertListToArray() {
    }

    /**
     * Test of hexStringToByteArray method, of class ArrayConverter.
     */
    @Test
    public void testHexStringToByteArray() {
	String hex = "01";
	assertArrayEquals("Testing simple one byte hex value", new byte[] { 0x01 },
		ArrayConverter.hexStringToByteArray(hex));
	hex = "FF";
	assertArrayEquals("Testing one byte hex value > 0x7f", new byte[] { (byte) 0xff },
		ArrayConverter.hexStringToByteArray(hex));
	hex = "FFFFFF";
	assertArrayEquals("Testing one byte hex value > 0x7f", new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff },
		ArrayConverter.hexStringToByteArray(hex));
    }

    @Test
    public void testBigIntegerToNullPaddedByteArray() {
	BigInteger test = new BigInteger("1D42C86F7923DFEC", 16);

	assertArrayEquals("Check zero output size", new byte[0],
		ArrayConverter.bigIntegerToNullPaddedByteArray(test, 0));
	assertArrayEquals("Check check output size smaller than input", new byte[] { (byte) 0xEC },
		ArrayConverter.bigIntegerToNullPaddedByteArray(test, 1));
	assertArrayEquals("Check output size bigger than input size",
		ArrayConverter.hexStringToByteArray("0000000000000000000000001D42C86F7923DFEC"),
		ArrayConverter.bigIntegerToNullPaddedByteArray(test, 20));
    }

    @Test
    public void testLongToUint48Bytes() {
	long testValue = 0x0000123456789ABCL;
	byte[] expectedResult = ArrayConverter.hexStringToByteArray("123456789ABC");

	assertArrayEquals("Assert correct output", expectedResult, ArrayConverter.longToUint48Bytes(testValue));

	testValue = 0x0000000000000001L;
	expectedResult = ArrayConverter.hexStringToByteArray("000000000001");

	assertArrayEquals("Assert correct output", expectedResult, ArrayConverter.longToUint48Bytes(testValue));
    }
}
