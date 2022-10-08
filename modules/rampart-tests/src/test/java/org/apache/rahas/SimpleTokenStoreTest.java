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

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

public class SimpleTokenStoreTest {

  @Test
  public void testAdd() {

    final String tokenID = "id-1";

    final SimpleTokenStore store = new SimpleTokenStore();

    try {
      store.add(getTestToken(tokenID));
    } catch (TrustException e) {
      fail("Adding a new token to an empty store should not fail, " + "message : " + e.getMessage());
    }

    TrustException thrown =
      assertThrows(TrustException.class,
                   () -> store.add(getTestToken(tokenID)));

    assertEquals(TrustException.getMessage("tokenAlreadyExists", new String[]{ tokenID }),
                 thrown.getMessage(),
                 "Incorrect exception message");

  }

  @Test
  public void testGetTokenIdentifiers() {
    SimpleTokenStore store = new SimpleTokenStore();
    try {
      String[] ids = store.getTokenIdentifiers();
      assertEquals(0, ids.length, "There should not be any token ids at this point");
    } catch (TrustException e) {
      fail(e.getMessage());
    }
    try {
      store.add(getTestToken("id-1"));
      store.add(getTestToken("id-2"));
      store.add(getTestToken("id-3"));
      String[] ids = store.getTokenIdentifiers();
      assertEquals(3, ids.length, "Incorrect number fo token ids");
    } catch (TrustException e) {
      fail(e.getMessage());
    }
  }

  @Test
  public void testUpdate() throws Exception {

    SimpleTokenStore store = new SimpleTokenStore();
    final Token token1 = getTestToken("id-1");

    TrustException thrown =
      assertThrows(TrustException.class,
                   () -> store.update(token1));

    assertEquals(TrustException.getMessage("noTokenToUpdate", new String[]{token1.getId()}),
                 thrown.getMessage(),
                 "Incorrect exception message");

    store.add(token1);
    store.add(getTestToken("id-2"));
    store.add(getTestToken("id-3"));
    token1.setState(Token.EXPIRED);
    store.update(token1);

  }

  @Test
  public void testGetValidExpiredRenewedTokens() throws TrustException {

    SimpleTokenStore store = new SimpleTokenStore();

    Token token1 = getTestToken("id-1", new Date(System.currentTimeMillis() + 10000));
    Token token2 = getTestToken("id-2", new Date(System.currentTimeMillis() + 10000));
    Token token3 = getTestToken("id-3", new Date(System.currentTimeMillis() + 10000));
    Token token4 = getTestToken("id-4", new Date(System.currentTimeMillis() + 10000));
    Token token5 = getTestToken("id-5", new Date(System.currentTimeMillis() + 10000));
    Token token6 = getTestToken("id-6", new Date(System.currentTimeMillis() + 10000));
    Token token7 = getTestToken("id-7", new Date(System.currentTimeMillis() + 10000));

    token1.setState(Token.ISSUED);
    token2.setState(Token.ISSUED);
    token3.setState(Token.ISSUED);
    token4.setState(Token.RENEWED);
    token5.setState(Token.RENEWED);
    token6.setState(Token.EXPIRED);
    token7.setState(Token.CANCELLED);

    store.add(token1);
    store.add(token2);
    store.add(token3);
    store.add(token4);
    store.add(token5);
    store.add(token6);
    store.add(token7);

    assertEquals(5, store.getValidTokens().length,     "Incorrect number of valid tokens");
    assertEquals(1, store.getExpiredTokens().length,   "Incorrect number of expired tokens");
    assertEquals(2, store.getRenewedTokens().length,   "Incorrect number of newed tokens");
    assertEquals(1, store.getCancelledTokens().length, "Incorrect number of newed tokens");

  }

  @Test
  public void testSerialize() throws ClassNotFoundException, IOException, TrustException {

    OMFactory factory = OMAbstractFactory.getOMFactory();
    OMNamespace ns1 = factory.createOMNamespace("bar", "x");
    OMElement elt11 = factory.createOMElement("foo1", ns1);

    final Token t = new Token("#1232122", elt11, new Date(), new Date());

    final SimpleTokenStore store = new SimpleTokenStore();
    store.add(t);

    final ByteArrayOutputStream baos = new ByteArrayOutputStream();

    try (ObjectOutputStream out = new ObjectOutputStream(baos)) {
      out.writeObject(store);
    }

    final SimpleTokenStore store2;
    try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
      store2 = (SimpleTokenStore) in.readObject();

    }

    assertEquals(store.getToken("#1232122").getId(), store2.getToken("#1232122").getId());
    assertEquals(store.getToken("#1232122").getCreated(), store2.getToken("#1232122").getCreated());

  }


  private Token getTestToken(String tokenId)
    throws TrustException {
    return getTestToken(tokenId, new Date());
  }

  private Token getTestToken(String tokenId, Date expiry) throws TrustException {
    OMFactory factory = OMAbstractFactory.getMetaFactory(OMAbstractFactory.FEATURE_DOM).getOMFactory();
    OMElement tokenEle = factory.createOMElement("testToken", "", "");
    Token token = new Token(tokenId, tokenEle, new Date(), expiry);
    token.setAttachedReference(tokenEle);
    token.setPreviousToken(tokenEle);
    token.setState(Token.ISSUED);
    token.setSecret("Top secret!".getBytes());
    return token;
  }

}
