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
package com.celeral.netlet.rpc;

import java.lang.reflect.Method;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.celeral.netlet.codec.CipherStatefulStreamCodec;
import com.celeral.netlet.codec.StatefulStreamCodec;
import com.celeral.netlet.rpc.RPC2Test.Authenticator.Introduction;

/**
 *
 * @author Chetan Narsude <chetan@celeral.com>
 */
class PKICalleeSwitch implements Analyses.Analysis.PostAnalyzer<RPC2Test.AuthenticatorImpl, RPC2Test.PKIIntroduction>
{
  @Override
  public void analyze(Client<Client.RPC> client, RPC2Test.AuthenticatorImpl authenticator, Method method, Object[] args, RPC2Test.PKIIntroduction retval, Throwable exception)
  {
    if (exception != null || retval == null) {
      return;
    }

    StatefulStreamCodec<Object> unwrappedSerdes = StatefulStreamCodec.Synchronized.unwrapIfWrapped(client.getSerdes());
    if (unwrappedSerdes instanceof CipherStatefulStreamCodec) {
      final CipherStatefulStreamCodec<Object> serdes = (CipherStatefulStreamCodec<Object>)unwrappedSerdes;
      final PublicKey encryption = ((Introduction) args[0]).getKey();
      final PrivateKey decryption = authenticator.master.getPrivate();

      client.execute(new Runnable()
      {
        @Override
        public void run()
        {
          serdes.initCipher(encryption, decryption);
        }
      });
    }
  }
  
}
