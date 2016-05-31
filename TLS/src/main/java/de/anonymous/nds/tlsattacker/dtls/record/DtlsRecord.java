/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.dtls.record;

import anonymous.tlsattacker.modifiablevariable.ModifiableVariableFactory;
import anonymous.tlsattacker.modifiablevariable.ModifiableVariableProperty;
import anonymous.tlsattacker.modifiablevariable.biginteger.ModifiableBigInteger;
import anonymous.tlsattacker.modifiablevariable.integer.ModifiableInteger;
import anonymous.tlsattacker.tls.record.Record;
import java.math.BigInteger;

/**
 * @author anonymous Pfützenreuter <anonymous.Pfuetzenreuter@anonymous>
 */
public class DtlsRecord extends Record {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableInteger epoch;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableBigInteger sequenceNumber;

    public ModifiableInteger getEpoch() {
	return epoch;
    }

    public ModifiableBigInteger getSequenceNumber() {
	return sequenceNumber;
    }

    public void setEpoch(int epoch) {
	this.epoch = ModifiableVariableFactory.safelySetValue(this.epoch, epoch);
    }

    public void setEpoch(ModifiableInteger epoch) {
	this.epoch = epoch;
    }

    public void setSequenceNumber(BigInteger sequenceNumber) {
	this.sequenceNumber = ModifiableVariableFactory.safelySetValue(this.sequenceNumber, sequenceNumber);
    }

    public void setSequenceNumber(ModifiableBigInteger sequenceNumber) {
	this.sequenceNumber = sequenceNumber;
    }
}
