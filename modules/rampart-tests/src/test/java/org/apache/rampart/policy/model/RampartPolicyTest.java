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

package org.apache.rampart.policy.model;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMXMLBuilderFactory;
import org.apache.axiom.om.OMXMLParserWrapper;
import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.junit.jupiter.api.Test;

import javax.xml.namespace.QName;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class RampartPolicyTest {

  public final static QName RAMPART_CONFIG_NAME = new QName(RampartConfig.NS,RampartConfig.RAMPART_CONFIG_LN);
  public final static QName CRYPTO_CONFIG_NAME = new QName(RampartConfig.NS,CryptoConfig.CRYPTO_LN);

  @Test
  public void testLoadPolicy() throws Exception {

    String xmlPath = "test-resources/policy/rampart-policy-1.xml";

    OMXMLParserWrapper builder = OMXMLBuilderFactory.createOMBuilder(Files.newInputStream(Paths.get(xmlPath)));

    OMElement elem = builder.getDocumentElement();

    Policy policy = PolicyEngine.getPolicy(elem);

    Assertion assertion = (Assertion)policy.getAssertions().get(0);

    assertEquals(RAMPART_CONFIG_NAME.getNamespaceURI(),
                 assertion.getName().getNamespaceURI(),
                 "Incorrect namespace in RampartConfig");

    assertEquals(RAMPART_CONFIG_NAME.getLocalPart(),
                 assertion.getName().getLocalPart(),
                 "Incorrect localname in RampartConfig");

    RampartConfig config = (RampartConfig) assertion;

    CryptoConfig sigCryptoConfig = config.getSigCryptoConfig();

    assertNotNull(sigCryptoConfig, "Signature Crypto missing");

    assertEquals(CRYPTO_CONFIG_NAME.getNamespaceURI(),
                 sigCryptoConfig.getName().getNamespaceURI(),
                 "Incorrect namespace in SignatureCrypto");

    assertEquals(CRYPTO_CONFIG_NAME.getLocalPart(),
                 sigCryptoConfig.getName().getLocalPart(),
                 "Incorrect localname in SignatureCrypto");

    assertEquals("org.apache.ws.security.components.crypto.Merlin",
                 sigCryptoConfig.getProvider(),
                 "Incorrect provider value");

    Properties prop = sigCryptoConfig.getProp();
    assertEquals(3,
                 prop.size(),
                 "Incorrect number of properties");

    assertEquals("JKS",
                 prop.getProperty("keystoreType"),
                 "Incorrect property value");

    assertEquals("/path/to/file.jks",
                 prop.getProperty("keystoreFile"),
                 "Incorrect property value");

    assertEquals("password",
                 prop.getProperty("keystorePassword"),
                 "Incorrect property value");

  }

}