/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.rahas;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("HttpUrlsUsage")
public class TokenRequestDispatcherConfigTest {

  @DisplayName("with valid configuration file")
  @Test
  public void testWithConfigFile() throws Exception {
    TokenRequestDispatcherConfig config = TokenRequestDispatcherConfig
      .load("test-resources/trust/dispatcher.config.xml");

    final String tokenType = "http://example.org/mySpecialToken1";

    assertEquals("org.apache.rahas.TempIssuer",
                 config.getDefaultIssuerName(),
                 "Incorrect default issuer class name");

    final TokenIssuer issuer = config.getIssuer(tokenType);

    assertEquals(TempIssuer.class.getName(),
                 issuer.getClass().getName(),
                 "Incorrect issuer for token type : " + tokenType);
  }

  @DisplayName("with default issuer not specified")
  @Test
  public void testInvalidCOnfigWithMissingDefaultIssuer() {

    TrustException thrown =
      assertThrows(TrustException.class,
                   () -> TokenRequestDispatcherConfig.load("test-resources/trust/dispatcher.config.invalid.1.xml"));

    assertEquals(TrustException.getMessage("defaultIssuerMissing", null),
                 thrown.getMessage(),
                 "Incorrect error message");

  }

  @DisplayName("with missing token type")
  @Test
  public void testInvalidRequestTypeDef() {

    TrustException thrown =
      assertThrows(TrustException.class,
                   () -> TokenRequestDispatcherConfig.load("test-resources/trust/dispatcher.config.invalid.2.xml"));

    assertEquals(TrustException.getMessage("invalidTokenTypeDefinition", new String[] { "Issuer", TempIssuer.class.getName() }),
                 thrown.getMessage(),
                 "Incorrect error");
  }

}
