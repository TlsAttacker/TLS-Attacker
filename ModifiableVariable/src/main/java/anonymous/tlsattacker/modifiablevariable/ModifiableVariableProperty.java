/**
 * TLS-Attacker - Anonymous submission
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package anonymous.tlsattacker.modifiablevariable;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation interface for modifiable variables.
 * 
 * @author anonymous anonymous - anonymous.anonymous@anonymous
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
public @interface ModifiableVariableProperty {

    public enum Type {

	LENGTH,
	COUNT,
	PADDING,
	/** variable presenting one or more (array of) TLS constants */
	TLS_CONSTANT,
	SIGNATURE,
	CIPHERTEXT,
	HMAC,
	PUBLIC_KEY,
	PRIVATE_KEY,
	KEY_MATERIAL,
	CERTIFICATE,
	/** plain protocol message, always in a decrypted state */
	PLAIN_PROTOCOL_MESSAGE,
	COOKIE,
	NONE
    }

    public enum Format {

	ASN1,
	PKCS1,
	NONE
    }

    Type type() default Type.NONE;

    Format format() default Format.NONE;

}
