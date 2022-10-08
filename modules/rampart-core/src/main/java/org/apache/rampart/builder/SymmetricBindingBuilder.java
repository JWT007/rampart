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

package org.apache.rampart.builder;

import org.apache.axiom.om.OMElement;
import org.apache.axis2.context.MessageContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.rahas.EncryptedKeyToken;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.TrustException;
import org.apache.rampart.RampartConstants;
import org.apache.rampart.RampartException;
import org.apache.rampart.RampartMessageData;
import org.apache.rampart.policy.RampartPolicyData;
import org.apache.rampart.util.RampartUtil;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.model.AlgorithmSuite;
import org.apache.ws.secpolicy.model.IssuedToken;
import org.apache.ws.secpolicy.model.SecureConversationToken;
import org.apache.ws.secpolicy.model.SupportingToken;
import org.apache.ws.secpolicy.model.Token;
import org.apache.ws.secpolicy.model.X509Token;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.ConversationConstants;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.handler.WSHandlerResult;
import org.apache.ws.security.message.WSSecDKEncrypt;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecEncryptedKey;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.util.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;


public class SymmetricBindingBuilder extends BindingBuilder {

  public static final Logger LOGGER = LogManager.getLogger(SymmetricBindingBuilder.class);

  public static final Logger TIME_LOGGER = LogManager.getLogger(RampartConstants.TIME_LOG);

  public void build(RampartMessageData rmd) throws RampartException {

    LOGGER.debug("SymmetricBindingBuilder build invoked");

    RampartPolicyData rpd = rmd.getPolicyData();
    if(rpd.isIncludeTimestamp()) {
      this.addTimestamp(rmd);
    }

    if(rmd.isInitiator()) {
      //Setup required tokens
      initializeTokens(rmd);
    }


    if(SPConstants.ENCRYPT_BEFORE_SIGNING.equals(rpd.getProtectionOrder())) {
      this.doEncryptBeforeSig(rmd);
    } else {
      this.doSignBeforeEncrypt(rmd);
    }

    LOGGER.debug("SymmetricBindingBuilder build invoked : DONE");

  }

  private void doEncryptBeforeSig(RampartMessageData rmd) throws RampartException {

    RampartPolicyData rpd = rmd.getPolicyData();

    List<byte[]> signatureValues = new ArrayList<byte[]>();

    final long t0 = System.currentTimeMillis();

    Token encryptionToken = rpd.getEncryptionToken();
    List<WSEncryptionPart> encrParts = RampartUtil.getEncryptedParts(rmd);

    List<WSEncryptionPart> sigParts = RampartUtil.getSignedParts(rmd);

    if(encryptionToken == null && encrParts.size() > 0) {
      throw new RampartException("encryptionTokenMissing");
    }

    if(encryptionToken != null && encrParts.size() > 0) {
      //The encryption token can be an IssuedToken or a
      //SecureConversationToken
      String tokenId = null;
      org.apache.rahas.Token tok = null;

      if(encryptionToken instanceof IssuedToken) {
        tokenId = rmd.getIssuedEncryptionTokenId();
        LOGGER.debug("Issued EncryptionToken Id : " + tokenId);
      } else if(encryptionToken instanceof SecureConversationToken) {
        tokenId = rmd.getSecConvTokenId();
        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug("SCT Id : " + tokenId);
        }
      } else if (encryptionToken instanceof X509Token) {
        if (rmd.isInitiator()) {
          tokenId = setupEncryptedKey(rmd, encryptionToken);
        } else {
          tokenId = getEncryptedKey(rmd);
        }
      } //TODO SAMLToken

      if(tokenId == null || tokenId.length() == 0) {
        throw new RampartException("noSecurityToken");
      }

      //Hack to handle reference id issues
      //TODO Need a better fix
      if(tokenId.startsWith("#")) {
        tokenId = tokenId.substring(1);
      }

      /*
       * Get hold of the token from the token storage
       */
      tok = this.getToken(rmd, tokenId);

      /*
       * Attach the token into the message based on token inclusion
       * values
       */
      boolean attached = false;
      Element encrTokenElement = null;
      Element refList = null;
      WSSecDKEncrypt dkEncr = null;
      WSSecEncrypt encr = null;
      Element encrDKTokenElem = null;

      if(SPConstants.INCLUDE_TOEKN_ALWAYS == encryptionToken.getInclusion() ||
         SPConstants.INCLUDE_TOKEN_ONCE == encryptionToken.getInclusion() ||
         (rmd.isInitiator() && SPConstants.INCLUDE_TOEKN_ALWAYS_TO_RECIPIENT == encryptionToken.getInclusion())) {
        encrTokenElement = RampartUtil.appendChildToSecHeader(rmd, tok.getToken());
        attached = true;
      } else if(encryptionToken instanceof X509Token && rmd.isInitiator()) {
        encrTokenElement = RampartUtil.appendChildToSecHeader(rmd, tok.getToken());
      }

      Document doc = rmd.getDocument();

      AlgorithmSuite algorithmSuite = rpd.getAlgorithmSuite();
      if(encryptionToken.isDerivedKeys()) {
        LOGGER.debug("Use drived keys");

        dkEncr = new WSSecDKEncrypt();

        if(attached && tok.getAttachedReference() != null) {

          dkEncr.setExternalKey(tok.getSecret(), (Element) doc
            .importNode((Element) tok.getAttachedReference(),
                        true));

        } else if(tok.getUnattachedReference() != null) {
          dkEncr.setExternalKey(tok.getSecret(), (Element) doc
            .importNode((Element) tok.getUnattachedReference(),
                        true));
        } else {
          dkEncr.setExternalKey(tok.getSecret(), tok.getId());
        }
        try {
          dkEncr.setSymmetricEncAlgorithm(algorithmSuite.getEncryption());
          dkEncr.setDerivedKeyLength(algorithmSuite.getEncryptionDerivedKeyLength()/8);
          dkEncr.prepare(doc);
          encrDKTokenElem = dkEncr.getdktElement();
          RampartUtil.appendChildToSecHeader(rmd, encrDKTokenElem);

          refList = dkEncr.encryptForExternalRef(null, encrParts);

        } catch (WSSecurityException | ConversationException e) {
          throw new RampartException("errorInDKEncr");
        }
      } else {
        LOGGER.debug("NO derived keys, use the shared secret");
        encr = new WSSecEncrypt();

        encr.setWsConfig(rmd.getConfig());
        encr.setEncKeyId(tokenId);
        RampartUtil.setEncryptionUser(rmd, encr);
        encr.setEphemeralKey(tok.getSecret());
        encr.setDocument(doc);
        encr.setSymmetricEncAlgorithm(algorithmSuite.getEncryption());
        // SymmKey is already encrypted, no need to do it again
        encr.setEncryptSymmKey(false);
        if (!rmd.isInitiator() && tok instanceof EncryptedKeyToken) {
          // TODO was encr.setUseKeyIdentifier(true); - verify
          encr.setEncKeyIdDirectId(true);
          encr.setCustomReferenceValue(((EncryptedKeyToken)tok).getSHA1());
          encr.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        }

        try {
          encr.prepare(doc, RampartUtil.getEncryptionCrypto(rpd.getRampartConfig(), rmd.getCustomClassLoader()));
          //Encrypt, get hold of the ref list and add it
          refList = encr.encryptForRef(null, encrParts);
        } catch (WSSecurityException e) {
          throw new RampartException("errorInEncryption", e);
        }
      }

      this.mainRefListElement = RampartUtil.appendChildToSecHeader(rmd, refList);

      final long t1 = System.currentTimeMillis();

      // Sometimes encryption token is not included in the the message
      if (encrTokenElement != null) {
        this.setInsertionLocation(encrTokenElement);
      } else if (timestampElement != null) {
        this.setInsertionLocation(timestampElement);
      }

      RampartUtil.handleEncryptedSignedHeaders(encrParts, sigParts, doc);

      Map<Token, Object> sigSuppTokMap = null;
      Map<Token, Object> endSuppTokMap = null;
      Map<Token, Object> sgndEndSuppTokMap = null;
      Map<Token, Object> sgndEncSuppTokMap = null;
      Map<Token, Object> endEncSuppTokMap = null;
      Map<Token, Object> sgndEndEncSuppTokMap = null;


      if(this.timestampElement != null){
        sigParts.add(new WSEncryptionPart(RampartUtil
                                            .addWsuIdToElement((OMElement) this.timestampElement)));
      }

      if(rmd.isInitiator()) {

        // Now add the supporting tokens
        SupportingToken sgndSuppTokens = rpd.getSignedSupportingTokens();
        sigSuppTokMap = this.handleSupportingTokens(rmd, sgndSuppTokens);

        SupportingToken endSuppTokens = rpd.getEndorsingSupportingTokens();
        endSuppTokMap = this.handleSupportingTokens(rmd, endSuppTokens);

        SupportingToken sgndEndSuppTokens = rpd.getSignedEndorsingSupportingTokens();
        sgndEndSuppTokMap = this.handleSupportingTokens(rmd, sgndEndSuppTokens);

        SupportingToken sgndEncryptedSuppTokens = rpd.getSignedEncryptedSupportingTokens();
        sgndEncSuppTokMap = this.handleSupportingTokens(rmd, sgndEncryptedSuppTokens);

        SupportingToken endorsingEncryptedSuppTokens = rpd.getEndorsingEncryptedSupportingTokens();
        endEncSuppTokMap = this.handleSupportingTokens(rmd, endorsingEncryptedSuppTokens);

        SupportingToken sgndEndEncSuppTokens = rpd.getSignedEndorsingEncryptedSupportingTokens();
        sgndEndEncSuppTokMap = this.handleSupportingTokens(rmd, sgndEndEncSuppTokens);

        List<SupportingToken> supportingToks = rpd.getSupportingTokensList();
        for (SupportingToken supportingTok : supportingToks) {
          this.handleSupportingTokens(rmd, supportingTok);
        }

        SupportingToken encryptedSupportingToks = rpd.getEncryptedSupportingTokens();
        this.handleSupportingTokens(rmd, encryptedSupportingToks);

        //Setup signature parts
        sigParts = addSignatureParts(sigSuppTokMap, sigParts);
        sigParts = addSignatureParts(sgndEncSuppTokMap, sigParts);
        sigParts = addSignatureParts(sgndEndSuppTokMap, sigParts);
        sigParts = addSignatureParts(sgndEndEncSuppTokMap, sigParts);

      } else {
        addSignatureConfirmation(rmd, sigParts);
      }


      //Sign the message
      //We should use the same key in the case of EncryptBeforeSig
      if ( sigParts.size() > 0) {
        signatureValues.add(this.doSymmSignature(rmd, encryptionToken, tok, sigParts));
        this.mainSigId = RampartUtil.addWsuIdToElement((OMElement)this.getInsertionLocation());
      }

      if(rmd.isInitiator()) {

        endSuppTokMap.putAll(endEncSuppTokMap);
        //Do endorsed signatures
        List<byte[]> endSigVals = this.doEndorsedSignatures(rmd, endSuppTokMap);
        signatureValues.addAll(endSigVals);

        sgndEndSuppTokMap.putAll(sgndEndEncSuppTokMap);
        //Do signed endorsing signatures
        List<byte[]> sigEndSigVals = this.doEndorsedSignatures(rmd, sgndEndSuppTokMap);
        signatureValues.addAll(sigEndSigVals);
      }

      final long t2 = System.currentTimeMillis();
      TIME_LOGGER.debug("Encryption took: {}, Signature took: {}",
                        () -> (t1 - t0),
                        () -> (t2 - t1));

      //Check for signature protection and encryption of UsernameToken
      if(rpd.isSignatureProtection() && this.mainSigId != null ||
         encryptedTokensIdList.size() > 0 && rmd.isInitiator()) {

        final long t3 = System.currentTimeMillis();

        LOGGER.debug("Signature protection");
        List<WSEncryptionPart> secondEncrParts = new ArrayList<WSEncryptionPart>();

        //Now encrypt the signature using the above token
        if(rpd.isSignatureProtection()) {
          secondEncrParts.add(new WSEncryptionPart(this.mainSigId, "Element"));
        }

        if(rmd.isInitiator()) {
          for (String anEncryptedTokensIdList : encryptedTokensIdList) {
            secondEncrParts.add(new WSEncryptionPart(anEncryptedTokensIdList, "Element"));
          }
        }

        Element secondRefList = null;

        if(encryptionToken.isDerivedKeys()) {
          try {
            secondRefList = dkEncr.encryptForExternalRef(null, secondEncrParts);
            RampartUtil.insertSiblingAfter(
              rmd,
              encrDKTokenElem,
              secondRefList);
          } catch (WSSecurityException e) {
            throw new RampartException("errorInDKEncr");
          }
        } else {
          try {
            //Encrypt, get hold of the ref list and add it
            secondRefList = encr.encryptForRef(null, encrParts);
            RampartUtil.insertSiblingAfter(
              rmd,
              encrTokenElement,
              secondRefList);
          } catch (WSSecurityException e) {
            throw new RampartException("errorInEncryption", e);
          }
        }

        final long t4 = System.currentTimeMillis();

        TIME_LOGGER.debug("Signature protection took: {}", () -> (t4 - t3));

      }

    } else {
      throw new RampartException("encryptionTokenMissing");
    }
  }


  private void doSignBeforeEncrypt(RampartMessageData rmd) throws RampartException {

    RampartPolicyData rpd = rmd.getPolicyData();
    Document doc = rmd.getDocument();

    final long t0 = System.currentTimeMillis();

    Token sigToken = rpd.getSignatureToken();

    String encrTokId = null;
    String sigTokId = null;

    org.apache.rahas.Token encrTok = null;
    org.apache.rahas.Token sigTok = null;

    Element sigTokElem = null;

    List<byte[]> signatureValues = new ArrayList<byte[]>();

    if(sigToken != null) {
      if(sigToken instanceof SecureConversationToken) {
        sigTokId = rmd.getSecConvTokenId();
      } else if(sigToken instanceof IssuedToken) {
        sigTokId = rmd.getIssuedSignatureTokenId();
      } else if(sigToken instanceof X509Token) {
        if (rmd.isInitiator()) {
          sigTokId = setupEncryptedKey(rmd, sigToken);
        } else {
          sigTokId = getEncryptedKey(rmd);
        }
      }
    } else {
      throw new RampartException("signatureTokenMissing");
    }

    if(sigTokId == null || sigTokId.length() == 0) {
      throw new RampartException("noSecurityToken");
    }

    sigTok = this.getToken(rmd, sigTokId);

    if(SPConstants.INCLUDE_TOEKN_ALWAYS == sigToken.getInclusion() ||
       SPConstants.INCLUDE_TOKEN_ONCE == sigToken.getInclusion() ||
       (rmd.isInitiator() &&
        SPConstants.INCLUDE_TOEKN_ALWAYS_TO_RECIPIENT == sigToken.getInclusion())) {
      sigTokElem = RampartUtil.appendChildToSecHeader(rmd,
                                                      sigTok.getToken());
      this.setInsertionLocation(sigTokElem);
    } else if ((rmd.isInitiator() && sigToken instanceof X509Token)
               || sigToken instanceof SecureConversationToken) {
      sigTokElem = RampartUtil.appendChildToSecHeader(rmd, sigTok.getToken());

      //Set the insertion location
      this.setInsertionLocation(sigTokElem);
    }


    Map<Token, Object> sigSuppTokMap = null;
    Map<Token, Object> endSuppTokMap = null;
    Map<Token, Object> sgndEndSuppTokMap = null;
    Map<Token, Object> sgndEncSuppTokMap = null;
    Map<Token, Object> endEncSuppTokMap = null;
    Map<Token, Object> sgndEndEncSuppTokMap = null;

    List<WSEncryptionPart> sigParts = RampartUtil.getSignedParts(rmd);

    if(this.timestampElement != null){
      sigParts.add(new WSEncryptionPart(RampartUtil
                                          .addWsuIdToElement((OMElement) this.timestampElement)));
    }

    if(rmd.isInitiator()) {
      //      Now add the supporting tokens
      SupportingToken sgndSuppTokens = rpd.getSignedSupportingTokens();
      sigSuppTokMap = this.handleSupportingTokens(rmd, sgndSuppTokens);

      SupportingToken endSuppTokens = rpd.getEndorsingSupportingTokens();
      endSuppTokMap = this.handleSupportingTokens(rmd, endSuppTokens);

      SupportingToken sgndEndSuppTokens = rpd.getSignedEndorsingSupportingTokens();
      sgndEndSuppTokMap = this.handleSupportingTokens(rmd, sgndEndSuppTokens);

      SupportingToken sgndEncryptedSuppTokens = rpd.getSignedEncryptedSupportingTokens();
      sgndEncSuppTokMap = this.handleSupportingTokens(rmd, sgndEncryptedSuppTokens);

      SupportingToken endorsingEncryptedSuppTokens = rpd.getEndorsingEncryptedSupportingTokens();
      endEncSuppTokMap = this.handleSupportingTokens(rmd, endorsingEncryptedSuppTokens);

      SupportingToken sgndEndEncSuppTokens = rpd.getSignedEndorsingEncryptedSupportingTokens();
      sgndEndEncSuppTokMap = this.handleSupportingTokens(rmd, sgndEndEncSuppTokens);

      List<SupportingToken> supportingToks = rpd.getSupportingTokensList();
      for (SupportingToken supportingTok : supportingToks) {
        this.handleSupportingTokens(rmd, supportingTok);
      }

      SupportingToken encryptedSupportingToks = rpd.getEncryptedSupportingTokens();
      this.handleSupportingTokens(rmd, encryptedSupportingToks);

      //Setup signature parts
      sigParts = addSignatureParts(sigSuppTokMap, sigParts);
      sigParts = addSignatureParts(sgndEncSuppTokMap, sigParts);
      sigParts = addSignatureParts(sgndEndSuppTokMap, sigParts);
      sigParts = addSignatureParts(sgndEndEncSuppTokMap, sigParts);

    } else {
      addSignatureConfirmation(rmd, sigParts);
    }

    if (sigParts.size() > 0 ) {
      //Sign the message
      signatureValues.add(this.doSymmSignature(rmd, sigToken, sigTok, sigParts));

      this.mainSigId = RampartUtil.addWsuIdToElement((OMElement)this.getInsertionLocation());

    }

    if(rmd.isInitiator()) {
      // Adding the endorsing encrypted supporting tokens to endorsing supporting tokens
      endSuppTokMap.putAll(endEncSuppTokMap);
      //Do endorsed signatures
      List<byte[]> endSigVals = this.doEndorsedSignatures(rmd, endSuppTokMap);
      signatureValues.addAll(endSigVals);

      //Adding the signed endorsed encrypted tokens to signed endorsed supporting tokens
      sgndEndSuppTokMap.putAll(sgndEndEncSuppTokMap);
      //Do signed endorsing signatures
      List<byte[]> sigEndSigVals = this.doEndorsedSignatures(rmd, sgndEndSuppTokMap);
      signatureValues.addAll(sigEndSigVals);
    }

    final long t1 = System.currentTimeMillis();

    //Encryption
    Token encrToken = rpd.getEncryptionToken();
    Element encrTokElem = null;
    if(sigToken.equals(encrToken)) {
      //Use the same token
      encrTokId = sigTokId;
      encrTok = sigTok;
      encrTokElem = sigTokElem;
    } else {
      encrTokId = rmd.getIssuedEncryptionTokenId();
      encrTok = this.getToken(rmd, encrTokId);

      if(SPConstants.INCLUDE_TOEKN_ALWAYS == encrToken.getInclusion() ||
         SPConstants.INCLUDE_TOKEN_ONCE == encrToken.getInclusion() ||
         (rmd.isInitiator() && SPConstants.INCLUDE_TOEKN_ALWAYS_TO_RECIPIENT == encrToken.getInclusion())) {
        encrTokElem = (Element)encrTok.getToken();

        //Add the encrToken element before the sigToken element
        RampartUtil.insertSiblingBefore(rmd, sigTokElem, encrTokElem);
      }

    }

    List<WSEncryptionPart> encrParts = RampartUtil.getEncryptedParts(rmd);

    //Check for signature protection
    if(rpd.isSignatureProtection() && this.mainSigId != null) {
      //Now encrypt the signature using the above token
      encrParts.add(new WSEncryptionPart(this.mainSigId, "Element"));
    }

    if(rmd.isInitiator()) {
      for (String anEncryptedTokensIdList : encryptedTokensIdList) {
        encrParts.add(new WSEncryptionPart(anEncryptedTokensIdList, "Element"));
      }
    }

    Element refList = null;
    if(encrParts.size() > 0) {
      //The sec conv token can be used without derived keys
      if(encrToken.isDerivedKeys()) {

        try {
          WSSecDKEncrypt dkEncr = new WSSecDKEncrypt();

          //Check whether it is security policy 1.2 and use the secure conversation accordingly
          if (SPConstants.SP_V12 == encrToken.getVersion()) {
            dkEncr.setWscVersion(ConversationConstants.VERSION_05_12);
          }

          if(encrTokElem != null && encrTok.getAttachedReference() != null) {

            dkEncr.setExternalKey(encrTok.getSecret(), (Element) doc
              .importNode((Element) encrTok.getAttachedReference(),
                          true));
          } else if(encrTok.getUnattachedReference() != null) {
            dkEncr.setExternalKey(encrTok.getSecret(), (Element) doc
              .importNode((Element) encrTok.getUnattachedReference(),
                          true));
          } else if (!rmd.isInitiator() && encrToken.isDerivedKeys()) {

            // If the Encrypted key used to create the derived key is not
            // attached use key identifier as defined in WSS1.1 section
            // 7.7 Encrypted Key reference
            SecurityTokenReference tokenRef = new SecurityTokenReference(doc);
            if(encrTok instanceof EncryptedKeyToken) {
              tokenRef.setKeyIdentifierEncKeySHA1(((EncryptedKeyToken)encrTok).getSHA1());
            }
            dkEncr.setExternalKey(encrTok.getSecret(), tokenRef.getElement());
            tokenRef.addTokenType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);  // TODO check this

          } else {
            dkEncr.setExternalKey(encrTok.getSecret(), encrTok.getId());
          }

          if(encrTok instanceof EncryptedKeyToken) {
            dkEncr.setCustomValueType(WSConstants.SOAPMESSAGE_NS11 + "#"
                                      + WSConstants.ENC_KEY_VALUE_TYPE);
          }

          dkEncr.setSymmetricEncAlgorithm(rpd.getAlgorithmSuite().getEncryption());
          dkEncr.setDerivedKeyLength(rpd.getAlgorithmSuite().getEncryptionDerivedKeyLength()/8);
          dkEncr.prepare(doc);
          Element encrDKTokenElem = null;
          encrDKTokenElem = dkEncr.getdktElement();
          if(encrTokElem != null) {
            RampartUtil.insertSiblingAfter(rmd, encrTokElem, encrDKTokenElem);
          } else if (timestampElement != null){
            RampartUtil.insertSiblingAfter(rmd, this.timestampElement, encrDKTokenElem);
          } else {
            RampartUtil.insertSiblingBefore(rmd, this.getInsertionLocation(), encrDKTokenElem);
          }

          refList = dkEncr.encryptForExternalRef(null, encrParts);

          RampartUtil.insertSiblingAfter(rmd,
                                         encrDKTokenElem,
                                         refList);

        } catch (WSSecurityException | ConversationException e) {
          throw new RampartException("errorInDKEncr");
        }
      } else {
        try {

          WSSecEncrypt encr = new WSSecEncrypt();

          encr.setWsConfig(rmd.getConfig());
          //Hack to handle reference id issues
          //TODO Need a better fix
          if(encrTokId.startsWith("#")) {
            encrTokId = encrTokId.substring(1);
          }
          encr.setEncKeyId(encrTokId);

          encr.setEphemeralKey(encrTok.getSecret());
          RampartUtil.setEncryptionUser(rmd, encr);
          encr.setDocument(doc);
          encr.setEncryptSymmKey(false);
          encr.setSymmetricEncAlgorithm(rpd.getAlgorithmSuite().getEncryption());
          // Use key identifier in the KeyInfo in server side
          if (!rmd.isInitiator()) {
            if(encrTok instanceof EncryptedKeyToken) {
              // TODO was encr.setUseKeyIdentifier(true); verify
              encr.setEncKeyIdDirectId(true);
              encr.setCustomReferenceValue(((EncryptedKeyToken)encrTok).getSHA1());
              encr.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
            }
          }
          encr.prepare(doc, RampartUtil.getEncryptionCrypto(rpd
                                                              .getRampartConfig(), rmd.getCustomClassLoader()));

          //Encrypt, get hold of the ref list and add it
          refList = encr.encryptForRef(null, encrParts);

          if(encrTokElem != null) {
            RampartUtil.insertSiblingAfter(rmd,
                                           encrTokElem,
                                           refList);
          } else {
            RampartUtil.insertSiblingBeforeOrPrepend(rmd,
                                                     this.getInsertionLocation(),
                                                     refList);
          }

        } catch (WSSecurityException e) {
          throw new RampartException("errorInEncryption", e);
        }
      }
    }

    final long t2 = System.currentTimeMillis();
    TIME_LOGGER.debug("Signature took: {}, Encryption took: {}",
                      () -> (t1 - t0),
                      () -> (t2 - t1));

  }

  /**
   * @param rmd the rampart message-data
   * @param sigToken the token
   * @return the encrypted key
   * @throws RampartException on error
   */
  private String setupEncryptedKey(RampartMessageData rmd, Token sigToken)
    throws RampartException {
    try {
      WSSecEncryptedKey encrKey = this.getEncryptedKeyBuilder(rmd,
                                                              sigToken);
      String id = encrKey.getId();
      byte[] secret = encrKey.getEphemeralKey();
      //Create a rahas token from this info and store it so we can use
      //it in the next steps

      Date created = new Date();
      Date expires = new Date();
      //TODO make this lifetime configurable ???
      expires.setTime(System.currentTimeMillis() + 300000);
      org.apache.rahas.EncryptedKeyToken tempTok = new org.apache.rahas.EncryptedKeyToken(
        id,
        (OMElement) encrKey.getEncryptedKeyElement(),
        created,
        expires);


      tempTok.setSecret(secret);

      // Set the SHA1 value of the encrypted key, this is used when the encrypted
      // key is referenced via a key identifier of type EncryptedKeySHA1
      tempTok.setSHA1(getSHA1(encrKey.getEncryptedEphemeralKey()));

      rmd.getTokenStorage().add(tempTok);

      String bstTokenId = encrKey.getBSTTokenId();
      //If direct ref is used to refer to the cert
      //then add the cert to the sec header now
      if(bstTokenId != null && bstTokenId.length() > 0) {
        RampartUtil.appendChildToSecHeader(rmd,
                                           encrKey.getBinarySecurityTokenElement());
      }

      return id;

    } catch (TrustException e) {
      throw new RampartException("errorInAddingTokenIntoStore");
    }
  }

  private String getSHA1(byte[] input) throws RampartException{

    MessageDigest sha = null;
    try {
      sha = MessageDigest.getInstance("SHA-1");
    } catch (NoSuchAlgorithmException e1) {
      throw new RampartException("noSHA1availabe", e1);
    }
    sha.reset();
    sha.update(input);
    byte[] data = sha.digest();

    return Base64.encode(data);
  }

  private String getEncryptedKey(RampartMessageData rmd) throws RampartException {

    List<WSHandlerResult> results
      = (List<WSHandlerResult>) rmd.getMsgContext().getProperty(WSHandlerConstants.RECV_RESULTS);

    for (WSHandlerResult result : results) {

      List<WSSecurityEngineResult> wsSecEngineResults = result.getResults();

      for (WSSecurityEngineResult wsSecEngineResult : wsSecEngineResults) {
        Integer actInt = (Integer) wsSecEngineResult.get(WSSecurityEngineResult.TAG_ACTION);
        if (actInt == WSConstants.ENCR) {

          if (wsSecEngineResult.get(WSSecurityEngineResult.TAG_ID) != null &&
              ((String) wsSecEngineResult.get(WSSecurityEngineResult.TAG_ID)).length() != 0) {

            try {

              String encryptedKeyID = (String) wsSecEngineResult.get(WSSecurityEngineResult.TAG_ID);

              Date created = new Date();
              Date expires = new Date();
              expires.setTime(System.currentTimeMillis() + 300000);
              EncryptedKeyToken tempTok = new EncryptedKeyToken(encryptedKeyID, created, expires);
              tempTok.setSecret((byte[]) wsSecEngineResult.get(WSSecurityEngineResult.TAG_SECRET));
              tempTok.setSHA1(getSHA1((byte[]) wsSecEngineResult.
                get(WSSecurityEngineResult.TAG_ENCRYPTED_EPHEMERAL_KEY)));
              rmd.getTokenStorage().add(tempTok);

              return encryptedKeyID;

            } catch (TrustException e) {
              throw new RampartException("errorInAddingTokenIntoStore");
            }

          }
        }
      }
    }
    return null;
  }


  /**
   * Set up the required tokens.
   * @param rmd the rampart message-data
   * @throws RampartException on error
   */
  private void initializeTokens(RampartMessageData rmd) throws RampartException {

    RampartPolicyData rpd = rmd.getPolicyData();

    MessageContext msgContext = rmd.getMsgContext();
    if(rpd.isSymmetricBinding() && !msgContext.isServerSide()) {
      LOGGER.debug("Processing symmetric binding: Setting up encryption token and signature token");
      //Setting up encryption token and signature token

      Token sigTok = rpd.getSignatureToken();
      Token encrTok = rpd.getEncryptionToken();
      if(sigTok instanceof IssuedToken) {
        LOGGER.debug("SignatureToken is an IssuedToken");
        if(rmd.getIssuedSignatureTokenId() == null) {
          LOGGER.debug("No IssuedToken found, requesting a new token");

          IssuedToken issuedToken = (IssuedToken)sigTok;

          String id = RampartUtil.getIssuedToken(rmd,
                                                 issuedToken);
          rmd.setIssuedSignatureTokenId(id);

        }

      } else if(sigTok instanceof SecureConversationToken) {

        LOGGER.debug("SignatureToken is a SecureConversationToken");

        //TODO check for an existing token and use it

        String secConvTokenId = rmd.getSecConvTokenId();

        //The RSTR has to be secured with the cancelled token
        String action = msgContext.getOptions().getAction();
        boolean cancelReqResp = action.equals(RahasConstants.WST_NS_05_02 + RahasConstants.RSTR_ACTION_CANCEL_SCT) ||
                                action.equals(RahasConstants.WST_NS_05_02 + RahasConstants.RSTR_ACTION_CANCEL_SCT) ||
                                action.equals(RahasConstants.WST_NS_05_02 + RahasConstants.RST_ACTION_CANCEL_SCT) ||
                                action.equals(RahasConstants.WST_NS_05_02 + RahasConstants.RST_ACTION_CANCEL_SCT);

        //In the case of the cancel req or resp we should mark the token as cancelled
        if(secConvTokenId != null && cancelReqResp) {
          try {
            rmd.getTokenStorage().getToken(secConvTokenId).setState(org.apache.rahas.Token.CANCELLED);
            msgContext.setProperty(RampartMessageData.SCT_ID, secConvTokenId);

            //remove from the local map of contexts
            String contextIdentifierKey = RampartUtil.getContextIdentifierKey(msgContext);
            RampartUtil.getContextMap(msgContext).remove(contextIdentifierKey);
          } catch (TrustException e) {
            throw new RampartException("errorExtractingToken");
          }
        }

        if (secConvTokenId == null || !RampartUtil.isTokenValid(rmd, secConvTokenId) && !cancelReqResp) {

          LOGGER.debug("No SecureConversationToken found, requesting a new token");

          SecureConversationToken secConvTok =
            (SecureConversationToken) sigTok;

          try {

            String id = RampartUtil.getSecConvToken(rmd, secConvTok);
            rmd.setSecConvTokenId(id);

          } catch (TrustException e) {
            throw new RampartException("errorInObtainingSct", e);
          }
        }
      }

      //If it was the ProtectionToken assertion then sigTok is the
      //same as encrTok
      if(sigTok.equals(encrTok) && sigTok instanceof IssuedToken) {

        LOGGER.debug("Symmetric binding uses a ProtectionToken, both SignatureToken and EncryptionToken are the same");

        rmd.setIssuedEncryptionTokenId(rmd.getIssuedEncryptionTokenId());

      } else {
        //Now we'll have to obtain the encryption token as well :-)
        //ASSUMPTION: SecureConversationToken is used as a
        //ProtectionToken therefore we only have to process a issued
        //token here

        LOGGER.debug("Obtaining the Encryption Token");

        if(rmd.getIssuedEncryptionTokenId() != null) {

          LOGGER.debug("EncryptionToken not already set");

          IssuedToken issuedToken = (IssuedToken)encrTok;

          String id = RampartUtil.getIssuedToken(rmd, issuedToken);

          rmd.setIssuedEncryptionTokenId(id);

        }

      }
    }

    //TODO : Support processing IssuedToken and SecConvToken assertoins
    //in supporting tokens, right now we only support UsernameTokens and
    //X.509 Tokens
  }



}
