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

package org.apache.ws.secpolicy.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.neethi.PolicyComponent;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.SPConstants;

public class SignedEncryptedElements extends AbstractSecurityAssertion {

  private final List<String> xPathExpressions = new ArrayList<>();

  private final Map<String, String> declaredNamespaces = new HashMap<>();

  private String xPathVersion;

  /**
   * Just a flag to identify whether this holds sign element info or encr
   * elements info
   */
  private final boolean signedElemets;

  public SignedEncryptedElements(boolean signedElements, int version) {
    this.signedElemets = signedElements;
    setVersion(version);
  }

  /**
   * @return Returns the xPathExpressions.
   */
  public List<String> getXPathExpressions() {
    return xPathExpressions;
  }

  public void addXPathExpression(String expr) {
    this.xPathExpressions.add(expr);
  }

  /**
   * @return Returns the xPathVersion.
   */
  public String getXPathVersion() {
    return xPathVersion;
  }

  /**
   * @param pathVersion
   *            The xPathVersion to set.
   */
  public void setXPathVersion(String pathVersion) {
    xPathVersion = pathVersion;
  }

  /**
   * @return Returns the signedElemets.
   */
  public boolean isSignedElemets() {
    return signedElemets;
  }

  public Map<String, String> getDeclaredNamespaces () {
    return declaredNamespaces;
  }

  public void addDeclaredNamespaces(String uri, String prefix ) {
    declaredNamespaces.put(prefix, uri);
  }

  public void serialize(XMLStreamWriter writer) throws XMLStreamException {

    String prefix = getName().getPrefix();
    String localName = getName().getLocalPart();
    String namespaceURI = getName().getNamespaceURI();

    // <sp:SignedElements> | <sp:EncryptedElements>
    writeStartElement(writer, prefix, localName, namespaceURI);

    if (xPathVersion != null) {
      writeAttribute(writer, prefix, namespaceURI, SPConstants.XPATH_VERSION, xPathVersion);
    }

    for (String xPathExpression : xPathExpressions) {
      // <sp:XPath ..>
      writeStartElement(writer, prefix, SPConstants.XPATH_EXPR, namespaceURI);

      for (String declaredPrefix : declaredNamespaces.keySet()) {
        final String declaredNamespaceURI = declaredNamespaces.get(declaredPrefix);
        writer.writeNamespace(declaredPrefix, declaredNamespaceURI);
      }

      writer.writeCharacters(xPathExpression);
      writer.writeEndElement();
    }

    // </sp:SignedElements> | </sp:EncryptedElements>
    writer.writeEndElement();
  }

  public QName getName() {
    if (signedElemets) {
      if (version == SPConstants.SP_V12) {
        return SP12Constants.SIGNED_ELEMENTS;
      } else {
        return SP11Constants.SIGNED_ELEMENTS;
      }

    }

    if (version == SPConstants.SP_V12) {
      return SP12Constants.ENCRYPTED_ELEMENTS;
    } else {
      return SP11Constants.ENCRYPTED_ELEMENTS;
    }
  }

  public PolicyComponent normalize() {
    return this;
  }
}
