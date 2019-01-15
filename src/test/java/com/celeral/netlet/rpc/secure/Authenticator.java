package com.celeral.netlet.rpc.secure;

import java.security.PublicKey;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

public interface Authenticator
{
  /**
   * Introduce the client to the server using the publickey and id to assist with fast identification.
   *
   * @param client introduction of the caller
   * @return introduction of the callee if it recognizes the caller and wants to chat with it
   */
  Introduction getPublicKey(Introduction client);
  /**
   * Prove the identity of the client to the server and vice a versa thus establishing trust and creating a secure session for communication.
   * The client sends the server a payload which is encrypted by the
   *
   * @param challenge serialized bytes of object of type {@link Challenge}
   * @return serialized bytes of object of type {@link Response}
   */
  Response establishSession(@NotNull Challenge challenge);

  /**
   * Objects of this type are presented by the entity wishing to establish a trusted secure session
   * with other entities. The serialized bytes of this object are encrypted with the public key of
   * the entity on the other end. This way the other entity will only be able to decrypt the secret
   * if it has the private key for the public key it previously presented.
   */
  interface Challenge
  {
    /**
     * Gets the id of the entity which wishes to establish the session. This id is used to locate
     * the public key of the client so that the response to the client can be encrypted.
     *
     * @return id of the entity initiating request for the session
     */
    String getId();

    /**
     * Randomly generated secret either 16 bytes long or 32 bytes long which
     *
     * @return random sequence of bytes
     */
    @Size(min = 16, max = 32)
    byte[] getSecret();

    byte[] getInitializationVector();
  }

  /**
   * Objects of this type are presented by the entity entering into a trusted secure session
   * with the entities which expressed interest to create such a session. The serialized bytes of this
   * object are encrypted with the public key of the entity on the other end. This way the other entity
   * will only be able to decrypt the secret if has the private key for the public key it previously
   * presented to introduce itself.
   */
  interface Response
  {
    /**
     * Decrypted tokens
     *
     * @return
     */
    byte[] getSecret();

    int getSessionId();
  }

  interface Introduction
  {
    /**
     * Id of the entity which is being introduced using this object.
     *
     * @return the id of the entity represented
     */
    String getId();

    /**
     * The semantic version of the protocol the entity can talk.
     *
     * @return a version string in semver format
     */
    String getVersion();

    /**
     * Public key of the entity.
     * By presenting the public key, it's being claimed that the data encrypted with the public key
     * can be decrypted by the entity which presents this public key. With the current limitations
     * of the technology it means that the entity possesses the corresponding private key as well.
     *
     * @return
     */
    PublicKey getKey();
  }

}
