package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.falcon;

import junit.framework.AssertionFailedError;
//Import dependencies
import junit.framework.TestCase;
import java.io.*;
import java.util.ArrayList;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;

import org.bouncycastle.util.Arrays;
//Asset Under Test
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;

public class FalconCheckSigned
    extends TestCase
{
    public void testFalconVectors() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "signed_java_ref_falcon512.rsp",
            "signed_java_ref_falcon1024.rsp",
        };

        FalconParameters[] paramList = new FalconParameters[]{
            FalconParameters.falcon_512,
            FalconParameters.falcon_1024,
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = FalconCheckSigned.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/falcon/interoperability/" + name);
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
                byte[] seed = Hex.decode(seedString); // seed for Falcon secure random
                byte[] pk = Hex.decode(publicKeyString);     // private key
                byte[] sm = Hex.decode(signedmessageString);     // signed message
                int sm_len = Integer.parseInt(smlenString);
                byte[] msg = Hex.decode(messageString); // message
                int m_len = Integer.parseInt(mlenString);

                byte[] shortPK = Arrays.copyOfRange(pk, 1, pk.length);

                System.out.println("Testing Case: "+count);

                //Get Parameters
                FalconParameters parameters = paramList[fileIndex];

                FalconPublicKeyParameters publicKeyParams = new FalconPublicKeyParameters(parameters, shortPK);
                FalconSigner verifier = new FalconSigner();
                FalconPublicKeyParameters pgenerationParams = publicKeyParams;
                verifier.init(false, pgenerationParams);
                byte[] noncesig = new byte[sm_len - m_len - 2 + 1];
                noncesig[0] = (byte)(0x30 + parameters.getLogN());
                System.arraycopy(sm, 2, noncesig, 1, 40);
                System.arraycopy(sm, 2 + 40 + m_len, noncesig, 40 + 1, sm_len - 2 - 40 - m_len);

                boolean vrfyrespass = verifier.verifySignature(msg, noncesig);
                assertTrue(name + " " + count + " verified", vrfyrespass);
            }
        }
    }
}