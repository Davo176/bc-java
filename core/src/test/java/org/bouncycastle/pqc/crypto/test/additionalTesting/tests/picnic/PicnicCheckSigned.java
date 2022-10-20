package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.picnic;

import junit.framework.AssertionFailedError;
//Import dependencies
import junit.framework.TestCase;
import java.io.*;
import java.util.ArrayList;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;

import org.bouncycastle.util.Arrays;
//Asset Under Test
import org.bouncycastle.crypto.SecretWithEncapsulation;
//Asset Under Test
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.picnic.PicnicKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicKeyPairGenerator;
import org.bouncycastle.pqc.crypto.picnic.PicnicParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicPublicKeyParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicSigner;
import org.bouncycastle.util.Pack;

public class PicnicCheckSigned
    extends TestCase
{
    public void testPicnicVectors() 
        throws Exception
    {
        String[] files = new String[]{
            "3/signed_java_ref_L1.rsp",
            "3/signed_java_ref_L3.rsp",
            "3/signed_java_ref_L5.rsp",
            "fs/signed_java_ref_L1.rsp",
            "fs/signed_java_ref_L3.rsp",
            "fs/signed_java_ref_L5.rsp",
            "full/signed_java_ref_L1.rsp",
            "full/signed_java_ref_L3.rsp",
            "full/signed_java_ref_L5.rsp",
            "ur/signed_java_ref_L1.rsp",
            "ur/signed_java_ref_L3.rsp",
            "ur/signed_java_ref_L5.rsp",
        };

        PicnicParameters[] paramList = new PicnicParameters[]{
            PicnicParameters.picnic3l1,
            PicnicParameters.picnic3l3,
            PicnicParameters.picnic3l5,
            PicnicParameters.picnicl1fs,
            PicnicParameters.picnicl3fs,
            PicnicParameters.picnicl5fs,
            PicnicParameters.picnicl1full,
            PicnicParameters.picnicl3full,
            PicnicParameters.picnicl5full,
            PicnicParameters.picnicl1ur,
            PicnicParameters.picnicl3ur,
            PicnicParameters.picnicl5ur,
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = PicnicCheckSigned.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/picnic/interoperability/" + name);
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
                byte[] seed = Hex.decode(seedString); // seed for Picnic secure random
                byte[] pk = Hex.decode(publicKeyString);     // private key
                byte[] sm = Hex.decode(signedmessageString);     // signed message
                int sm_len = Integer.parseInt(smlenString);
                byte[] msg = Hex.decode(messageString); // message
                int m_len = Integer.parseInt(mlenString);

                System.out.println("Testing Case: "+count);

                //Get Parameters
                PicnicParameters parameters = paramList[fileIndex];

                PicnicPublicKeyParameters publicKeyParams = new PicnicPublicKeyParameters(parameters, pk);
                PicnicSigner verifier = new PicnicSigner();
                PicnicPublicKeyParameters pgenerationParams = publicKeyParams;
                verifier.init(false, pgenerationParams);
                byte[] sigGenerated = Arrays.copyOfRange(sm, 4+m_len, sm.length);

                boolean vrfyrespass = verifier.verifySignature(msg, sigGenerated);
                assertTrue(name + " " + count + " verified", vrfyrespass);
            }
        }
    }
}