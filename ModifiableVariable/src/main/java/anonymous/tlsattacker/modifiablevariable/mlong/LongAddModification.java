/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable.mlong;

import anonymous.tlsattacker.modifiablevariable.VariableModification;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

/**
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
@XmlRootElement
@XmlType(propOrder = { "summand", "modificationFilter", "postModification" })
public class LongAddModification extends VariableModification<Long> {

    private Long summand;

    public LongAddModification() {

    }

    public LongAddModification(Long bi) {
	this.summand = bi;
    }

    @Override
    protected Long modifyImplementationHook(final Long input) {
	return (input == null) ? summand : input + summand;
    }

    public Long getSummand() {
	return summand;
    }

    public void setSummand(Long summand) {
	this.summand = summand;
    }
}
