/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.celeral.netlet.codec;

import com.celeral.netlet.util.Slice;

/**
 * <p>
 * StatefulStreamCodec interface.</p>
 *
 * @param <T>
 *
 * @since 0.3.2
 */
public interface StatefulStreamCodec<T>
{
  /**
   * A convenience class which is used to hold 2 different values associated with each serialize/deserialize operation.
   */
  class DataStatePair
  {
    /**
     * This byte array corresponds to serialized form of the tuple of type T.
     */
    public Slice data;
    /**
     * This byte array corresponds to serialized form the incremental state the
     * codec built while serializing the tuple into data field.
     *
     * Since serialization and deserialization fall among the most expensive calculations
     * that a system can do, codecs are expected optimize these operations considerably.
     * An example of it is instead of storing fully qualified class name along with the
     * object, the codec can store an integer for it. This creates a mapping from an integer
     * to fully qualified class name and is only known to the codec instance which
     * serializes the object using this information. We call this dynamically changing
     * knowledge (mapping) a state. For deserializer instance to do its job, it also needs
     * to have this knowledge and can be passed through the state variable.
     *
     * Note that the state is incremental so it's additive to previous state. It does not
     * replace it. If state does not change during serialization, this field can be set to
     * null. Otherwise it will be delivered to all the instances of deserializing codecs of
     * this serializer in the same order as it was created. Due to the nature of the partitioning
     * the accompanying data field may not make it to the deserializer.
     */
    public Slice state;

    @Override
    public String toString()
    {
      return "DataStatePair{" + "data=" + data + ", state=" + state + '}';
    }

  }

  /**
   * Create POJO from the byte array for consumption by the downstream.
   *
   * @param dspair
   *
   * @return plain old java object, the type is intentionally not T since the consumer does not care for it.
   */
  Object fromDataStatePair(DataStatePair dspair);

  /**
   * Serialize the POJO emitted by the upstream node to byte array so that
   * it can be transmitted or stored in file
   *
   * @param object plain old java object
   *
   * @return serialized representation of the object
   */
  DataStatePair toDataStatePair(T object);

  /**
   * Reset the state of the codec to the default state before any of the tuples are processed.
   *
   * The state used to serialize/deserialize after resetState is the same as the state codec has after
   * it is instantiated. resetState is called periodically when the upstream operator checkpoints but
   * should not be confused with the resetState operation of upstream operator.
   *
   */
  void resetState();

  class Synchronized
  {
    static class $tatefulStreamCodec<T> implements com.celeral.netlet.codec.StatefulStreamCodec<T>
    {
      private final StatefulStreamCodec<T> codec;
      private final Object mutex;

      $tatefulStreamCodec(StatefulStreamCodec<T> codec, Object mutex)
      {
        this.mutex = mutex;
        this.codec = codec;
      }

      $tatefulStreamCodec(StatefulStreamCodec<T> codec)
      {
        this.codec = codec;
        this.mutex = this;
      }

      @Override
      public Object fromDataStatePair(DataStatePair dspair)
      {
        synchronized (mutex) {
          return codec.fromDataStatePair(dspair);
        }
      }

      @Override
      public DataStatePair toDataStatePair(T object)
      {
        synchronized (mutex) {
          return codec.toDataStatePair(object);
        }
      }

      @Override
      public void resetState()
      {
        synchronized (mutex) {
          codec.resetState();
        }
      }
    }

    public static <T> StatefulStreamCodec<T> wrap(StatefulStreamCodec<T> codec)
    {
      return new $tatefulStreamCodec<>(codec);
    }

    public static <T> StatefulStreamCodec<T> wrap(StatefulStreamCodec<T> codec, Object mutex)
    {
      return new $tatefulStreamCodec<>(codec, mutex);
    }

    public static <T> StatefulStreamCodec<T> unwrapIfWrapped(StatefulStreamCodec<T> codec)
    {
      while (codec instanceof $tatefulStreamCodec) {
        codec = (($tatefulStreamCodec<T>)codec).codec;
      }

      return codec;
    }

    public Object getMutexIfWrapped(StatefulStreamCodec<?> codec)
    {
      if (codec instanceof $tatefulStreamCodec) {
        return (($tatefulStreamCodec<?>)codec).mutex;
      }

      return null;
    }

  }

  /**
   *
   * @author chetan
   */
  enum MessageType
  {
    DATA((byte)0), STATE((byte)1);

    public final byte getByte()
    {
      return value;
    }

    public static MessageType valueOf(byte value)
    {
      switch (value) {
        case 0:
          return DATA;
        case 1:
          return STATE;
        default:
          return null;
      }
    }
    final byte value;

    MessageType(byte value)
    {
      this.value = value;
    }
  }

}
