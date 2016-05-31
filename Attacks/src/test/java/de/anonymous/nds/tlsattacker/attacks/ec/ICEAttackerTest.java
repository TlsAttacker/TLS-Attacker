/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.attacks.ec;

import anonymous.tlsattacker.attacks.ec.oracles.TestECOracle;
import anonymous.tlsattacker.attacks.ec.oracles.TestECSunOracle;
import java.math.BigInteger;
import java.util.Arrays;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Ignore;

/**
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
public class ICEAttackerTest {

    public ICEAttackerTest() {
    }

    /**
     * Test of attack method, of class ICEAttacker.
     */
    @Ignore("Takes too long")
    @Test()
    public void testAttack() {
	TestECOracle oracle = new TestECOracle("secp256r1");
	ICEAttacker attacker = new ICEAttacker(oracle);
	attacker.attack();
	BigInteger result = attacker.getResult();

	System.out.println(result);
	System.out.println(oracle.getComputer().getSecret());

	assertEquals(oracle.getComputer().getSecret(), result);
    }

    /**
     * Test of attack method, of class ICEAttacker.
     */
    @Ignore("Takes too long")
    @Test
    public void testSunAttack() {
	TestECSunOracle oracle = new TestECSunOracle("secp256r1");
	ICEAttacker attacker = new ICEAttacker(oracle, ICEAttacker.ServerType.ORACLE, 4);
	attacker.attack();
	BigInteger result = attacker.getResult();

	System.out.println(result);
	System.out.println(oracle.getComputer().getSecret());

	assertEquals(oracle.getComputer().getSecret(), result);
    }

    // @Ignore("Just a probability computation for our paper")
    @Test
    public void computeProbability() {
	double probability = 0.98;
	int results = 53;
	double result = Math.pow(probability, results)
		+ (results * (1 - probability) * Math.pow(probability, results - 1))
		+ (190 * Math.pow(1 - probability, 2) * Math.pow(probability, results - 2))
		+ (1140 * Math.pow(1 - probability, 3) * Math.pow(probability, results - 3));
	System.out.println(result);
    }

}
