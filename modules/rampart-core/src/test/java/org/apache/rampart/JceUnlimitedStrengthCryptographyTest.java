package org.apache.rampart;

import javax.crypto.Cipher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JceUnlimitedStrengthCryptographyTest {

  @DisplayName("Test JCE unlimited-strength cryptography is enabled.")
  @Test
  public void unlimitedStrengthCryptographyIsEnabled() throws Exception {

    final int maxKeyLength = Cipher.getMaxAllowedKeyLength("AES");

    assertEquals(maxKeyLength, Integer.MAX_VALUE);

  }


}
