package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.dilithium;

import junit.framework.AssertionFailedError;
//Import dependencies
import junit.framework.TestCase;
import java.io.*;
import java.util.ArrayList;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;

import org.bouncycastle.util.Arrays;
//Asset Under Test
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;

public class DilithiumCheckSigned
    extends TestCase
{
    public void testBikeVectors() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "signed_java_ref_Dilithium2.rsp",
            "signed_java_ref_Dilithium3.rsp",
            "signed_java_ref_Dilithium5.rsp",
        };

        DilithiumParameters[] paramList = new DilithiumParameters[]{
            DilithiumParameters.dilithium2,
            DilithiumParameters.dilithium3,
            DilithiumParameters.dilithium5
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = DilithiumCheckSigned.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/dilithium/interoperability/" + name);
            BufferedReader br = new BufferedReader(new InputStreamReader(src));

            String line = null;
            while ((line = br.readLine()) != null){
                //Find next test
                int countIndex = line.indexOf("count = ");
                while (countIndex < 0){
                    line = br.readLine();
                    countIndex = line.indexOf("count = ");
                }
                String count = line.substring(countIndex + "count = ".length()).trim();
                line = br.readLine();
                int intCount = Integer.parseInt(count);

                //Get Seed
                int seedIndex = line.indexOf("seed = ");
                String seedString = line.substring(seedIndex + "seed = ".length()).trim();
                line = br.readLine();
                //Get Message Length
                int mlenIndex = line.indexOf("mlen = ");
                String mlenString = line.substring(mlenIndex + "mlen = ".length()).trim();
                line = br.readLine();
                //Get Message
                int messageIndex = line.indexOf("msg = ");
                String messageString = line.substring(messageIndex + "msg = ".length()).trim();
                line = br.readLine();
                //Get Public Key
                int publicKeyIndex = line.indexOf("pk = ");
                String publicKeyString = line.substring(publicKeyIndex + "pk = ".length()).trim();
                line = br.readLine();
                //Get Message Length
                int smlenIndex = line.indexOf("smlen = ");
                String smlenString = line.substring(smlenIndex + "mlen = ".length()).trim();
                line = br.readLine();
                //Get Message
                int signedmessageIndex = line.indexOf("sm = ");
                String signedmessageString = line.substring(signedmessageIndex + "sm = ".length()).trim();
                line = br.readLine();

                //convert all into byte arrays
                byte[] seed = Hex.decode(seedString); // seed for Dilithium secure random
                byte[] pk = Hex.decode(publicKeyString);     // private key
                byte[] sm = Hex.decode(signedmessageString);     // signed message
                int sm_len = Integer.parseInt(smlenString);
                byte[] msg = Hex.decode(messageString); // message
                int m_len = Integer.parseInt(mlenString);

                System.out.println("Testing Case: "+count);

                //Get Parameters
                DilithiumParameters parameters = paramList[fileIndex];

                DilithiumPublicKeyParameters publicKeyParams = new DilithiumPublicKeyParameters(parameters, pk);
                DilithiumSigner verifier = new DilithiumSigner();
                DilithiumPublicKeyParameters pgenerationParams = publicKeyParams;
                verifier.init(false, pgenerationParams);
                byte[] sigGenerated = Arrays.copyOfRange(sm, 0, sm_len-m_len);

                boolean vrfyrespass = verifier.verifySignature(msg, sigGenerated);
                assertTrue(name + " " + count + " verified", vrfyrespass);
            }
        }
    }
}