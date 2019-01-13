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

import com.celeral.netlet.util.Slice;
import com.celeral.utils.Throwables;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

/**
 * @author Chetan Narsude <chetan@celeral.com>
 */
public class CipherStatefulStreamCodec<T> implements StatefulStreamCodec<T>
{
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

  public static Slice doFinal(Cipher cipher, Slice slice) throws IllegalBlockSizeException, BadPaddingException
  {
    if (true || cipher == null) {
      return slice;
    }

    byte[] newBuffer = new byte[cipher.getOutputSize(slice.length - 1) + 1];
    try {
      slice.length = cipher.doFinal(slice.buffer, slice.offset + 1, slice.length - 1, newBuffer, 1) + 1;
      newBuffer[0] = slice.buffer[slice.offset];
      slice.offset = 0;
      slice.buffer = newBuffer;
      return slice;
    }
    catch (ShortBufferException ex) {
      throw Throwables.throwFormatted(ex, IllegalStateException.class,
                                      "Incorrect implementation caused miscalculation of the buffer size! slice = {}, newbuffer = {}, cipher = {}",
                                      slice.length, newBuffer.length, cipher);
    }
  }


  @Override
  public DataStatePair toDataStatePair(T o)
  {
    try {
      DataStatePair pair = codec.toDataStatePair(o);
      pair.data = CipherStatefulStreamCodec.doFinal(encryption, pair.data);
      if (pair.state != null) {
        pair.state = CipherStatefulStreamCodec.doFinal(encryption, pair.state);
      }
      return pair;
    }
    catch (IllegalBlockSizeException | BadPaddingException ex) {
      throw new RuntimeException(ex);
    }
  }

  @Override
  public Object fromDataStatePair(DataStatePair pair)
  {
    try {
      pair.data = CipherStatefulStreamCodec.doFinal(decryption, pair.data);
      if (pair.state != null) {
        pair.state = CipherStatefulStreamCodec.doFinal(decryption, pair.state);
      }
      return codec.fromDataStatePair(pair);
    }
    catch (IllegalBlockSizeException | BadPaddingException ex) {
      throw new RuntimeException(ex);
    }
  }

  @Override
  public void resetState()
  {
    codec.resetState();
  }

  private static final Logger logger = LoggerFactory.getLogger(CipherStatefulStreamCodec.class);
}
