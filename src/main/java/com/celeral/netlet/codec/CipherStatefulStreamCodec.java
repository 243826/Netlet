/*
 * Copyright 2019 Celeral.
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
package com.celeral.netlet.codec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.celeral.utils.Throwables;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.celeral.netlet.util.Slice;

/**
 * @author Chetan Narsude <chetan@celeral.com>
 */
public class CipherStatefulStreamCodec<T> implements StatefulStreamCodec<T>
{
  public static final String AES_CBC_PKCS_5_PADDING = "AES/CBC/PKCS5PADDING";
  private static final String RSAECBOAEP_WITH_SHA1_AND_MGF1_PADDING = "RSA/ECB/OAEPWithSHA1AndMGF1Padding";
  public static SecureRandom random = new SecureRandom();

  public static byte[] getRandomBytes(int size)
  {
    byte[] bytes = new byte[size];
    random.nextBytes(bytes);
    return bytes;
  }

  private Cipher encryption;
  private Cipher decryption;
  private final StatefulStreamCodec<T> codec;

  public CipherStatefulStreamCodec(StatefulStreamCodec<T> codec, Cipher encryption, Cipher decryption)
  {
    this.codec = codec;
    initCipher(encryption, decryption);
  }

  public final void initCipher(Cipher encryption, Cipher decryption)
  {
    this.encryption = encryption;
    this.decryption = decryption;
  }

  public static Slice doFinal(Cipher cipher, Slice slice, byte[]... prepends) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
  {
    int newBufferlength = 0;
    if (prepends != null) {
      for (byte[] bytes : prepends) {
        if (bytes != null) {
          newBufferlength += bytes.length;
        }
      }
    }

    newBufferlength += cipher.getOutputSize(slice.length);
    byte[] newBuffer = new byte[newBufferlength];

    int newOffset = 0;
    if (prepends != null) {
      for (byte[] bytes : prepends) {
        if (bytes != null) {
          System.arraycopy(bytes, 0, newBuffer, newOffset, bytes.length);
          newOffset += bytes.length;
        }
      }
    }

    newOffset += cipher.doFinal(slice.buffer, slice.offset, slice.length, newBuffer, newOffset);

    slice.buffer = newBuffer;
    slice.offset = 0;
    slice.length = newOffset;
    return slice;
  }

  public static Slice doFinal(int mode, Cipher cipher, Slice slice) throws IllegalBlockSizeException, BadPaddingException, ShortBufferException
  {
    if (cipher == null) {
      return slice;
    }

    final byte[] preservedBytes = new byte[]{slice.buffer[slice.offset]};
    final int preservedLength = preservedBytes.length;

    final String algorithm = cipher.getAlgorithm();
    if (AES_CBC_PKCS_5_PADDING.equals(algorithm)) {
      slice.offset += preservedLength;
      slice.length -= preservedLength;
      return CipherStatefulStreamCodec.doFinal(cipher, slice, preservedBytes);
    }
    else if (RSAECBOAEP_WITH_SHA1_AND_MGF1_PADDING.equals(algorithm)) {
      if (mode == Cipher.ENCRYPT_MODE) {
        byte[] secretIV = CipherStatefulStreamCodec.getRandomBytes(32);
        SecretKey key = new SecretKeySpec(secretIV, 0, 16, "AES");
        AlgorithmParameterSpec spec = new IvParameterSpec(secretIV, 16, 16);
        Cipher aes = CipherStatefulStreamCodec.getCipher(mode, key, spec);

        byte[] encryptedSecretIV = cipher.doFinal(secretIV);

        slice.offset += preservedLength;
        slice.length -= preservedLength;
        return CipherStatefulStreamCodec.doFinal(aes, slice, preservedBytes, encryptedSecretIV);
      }
      else if (mode == Cipher.DECRYPT_MODE) {
        int encryptedSecretIVSize = cipher.getOutputSize(32);
        byte[] secretIV = cipher.doFinal(slice.buffer, slice.offset + preservedLength, encryptedSecretIVSize);
        SecretKey key = new SecretKeySpec(secretIV, 0, 16, "AES");
        AlgorithmParameterSpec spec = new IvParameterSpec(secretIV, 16, 16);
        Cipher aes = CipherStatefulStreamCodec.getCipher(mode, key, spec);

        slice.offset += preservedLength + encryptedSecretIVSize;
        slice.length -= preservedLength + encryptedSecretIVSize;
        return CipherStatefulStreamCodec.doFinal(aes, slice, preservedBytes);
      }
    }

    return null;
  }

  @Override
  public DataStatePair toDataStatePair(T o)
  {
    try {
      DataStatePair pair = codec.toDataStatePair(o);
      //CipherStatefulStreamCodec.logPair("clr", pair);
      pair.data = CipherStatefulStreamCodec.doFinal(Cipher.ENCRYPT_MODE, encryption, pair.data);
      if (pair.state != null) {
        pair.state = CipherStatefulStreamCodec.doFinal(Cipher.ENCRYPT_MODE, encryption, pair.state);
      }
      //CipherStatefulStreamCodec.logPair("enc", pair);
      return pair;
    }
    catch (IllegalBlockSizeException | BadPaddingException | ShortBufferException ex) {
      throw new RuntimeException(ex);
    }
  }

  private static void logPair(String annotation, DataStatePair pair)
  {
    logger.info("{} pair = {}, data = {}-{}, state = {}-{}",
                annotation, pair,
                pair.data.buffer[pair.data.offset + 1], pair.data.buffer[pair.data.offset + pair.data.length - 1],
                pair.state == null ? null : pair.state.buffer[pair.state.offset + 1],
                pair.state == null ? null : pair.state.buffer[pair.state.offset + pair.state.length - 1]);
  }

  @Override
  public Object fromDataStatePair(DataStatePair pair)
  {
    //CipherStatefulStreamCodec.logPair("enc", pair);

    try {
      pair.data = CipherStatefulStreamCodec.doFinal(Cipher.DECRYPT_MODE, decryption, pair.data);
      if (pair.state != null) {
        pair.state = CipherStatefulStreamCodec.doFinal(Cipher.DECRYPT_MODE, decryption, pair.state);
      }
      //CipherStatefulStreamCodec.logPair("clr", pair);

      return codec.fromDataStatePair(pair);
    }
    catch (IllegalBlockSizeException | BadPaddingException | ShortBufferException ex) {
      throw new RuntimeException(ex);
    }
  }

  @Override
  public void resetState()
  {
    codec.resetState();
  }

  public static Cipher getCipher(int mode, SecretKey key, AlgorithmParameterSpec iv)
  {
    try {
      final Cipher cipher = Cipher.getInstance(AES_CBC_PKCS_5_PADDING);
      cipher.init(mode, key, iv);
      return cipher;
    }
    catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException ex) {
      throw Throwables.throwFormatted(ex, RuntimeException.class, "Unable to create {} mode instance of Cipher for key {}", mode, key);
    }
  }

  public static Cipher getCipher(int mode, Key key)
  {
    if (key == null) {
      return null;
    }

    try {
      Cipher instance = Cipher.getInstance(RSAECBOAEP_WITH_SHA1_AND_MGF1_PADDING);
      instance.init(mode, key);
      return instance;
    }
    catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException ex) {
      throw Throwables.throwFormatted(ex, RuntimeException.class, "Unable to create {} mode instance of Cipher for key {}", mode, key);
    }
  }

  private static final Logger logger = LoggerFactory.getLogger(CipherStatefulStreamCodec.class);
}
