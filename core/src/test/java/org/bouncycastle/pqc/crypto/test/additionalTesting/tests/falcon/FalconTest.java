package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.falcon;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;

import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import junit.framework.AssertionFailedError;
import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconSigner;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class FalconTest
    extends TestCase
{
    public void testVectors()
        throws Exception
    {
        String[] files = new String[]{
            "falcon512-Rand.rsp",
            "falcon1024-Rand.rsp"
        };
        FalconParameters[] parameters = new FalconParameters[]{
            FalconParameters.falcon_512,
            FalconParameters.falcon_1024
        };

        for (int fileindex = 0; fileindex < files.length; fileindex++)
        {
            String name = files[fileindex];
            System.out.println("testing: " + name);
            InputStream src = FalconTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/falcon/" + name);
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
                
                //Get Sed
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
                //Get Secret Key
                int publicKeyIndex = line.indexOf("pk = ");
                String publicKeyString = line.substring(publicKeyIndex + "pk = ".length()).trim();
                line = br.readLine();
                //Get Secret Key
                int secretKeyIndex = line.indexOf("sk = ");
                String secretKeyString = line.substring(secretKeyIndex + "sk = ".length()).trim();
                line = br.readLine();
                //Get signed message length
                int smlenIndex = line.indexOf("smlen = ");
                String smlenString = line.substring(smlenIndex + "smlen = ".length()).trim();
                line = br.readLine();
                //Get Shared Secret (session key)
                int smIndex = line.indexOf("sm = ");
                String smString = line.substring(smIndex + "sm = ".length()).trim();
                line = br.readLine();

                //convert all into byte arrays
                byte[] seed = Hex.decode(seedString); // seed for Falcon secure random
                byte[] expectedPk = Hex.decode(publicKeyString);
                byte[] expectedSk = Hex.decode(secretKeyString);
                byte[] expectedSm = Hex.decode(smString);     // signed message
                int expectedSm_len = Integer.parseInt(smlenString);
                byte[] msg = Hex.decode(messageString); // message
                int m_len = Integer.parseInt(mlenString);


                System.out.println("Testing Case: "+count);

                NISTSecureRandom random = new NISTSecureRandom(seed, null);
                //Get Parameters
                // keyGenerator
                FalconKeyGenerationParameters generationParams = new FalconKeyGenerationParameters(random, parameters[fileindex]);
                FalconKeyPairGenerator keyGenerator = new FalconKeyPairGenerator();
                keyGenerator.init(generationParams);
                AsymmetricCipherKeyPair keyPair = keyGenerator.generateKeyPair();
                byte[] respk = ((FalconPublicKeyParameters)keyPair.getPublic()).getH();
                byte[] ressk = ((FalconPrivateKeyParameters)keyPair.getPrivate()).getEncoded();

                // sign
                FalconSigner signer = new FalconSigner();              
                ParametersWithRandom skwrand = new ParametersWithRandom(keyPair.getPrivate(), random);
                signer.init(true, skwrand);
                byte[] sig = signer.generateSignature(msg);
                byte[] ressm = new byte[2 + msg.length + sig.length - 1];
                //huhhhh surely this should all be abstracted
                ressm[0] = (byte)((sig.length - 40 - 1) >>> 8);
                ressm[1] = (byte)(sig.length - 40 - 1);
                System.arraycopy(sig, 1, ressm, 2, 40);
                System.arraycopy(msg, 0, ressm, 2 + 40, msg.length);
                System.arraycopy(sig, 40 + 1, ressm, 2 + 40 + msg.length, sig.length - 40 - 1);
 
                // verify
                FalconSigner verifier = new FalconSigner();
                FalconPublicKeyParameters pgenerationParams = (FalconPublicKeyParameters)keyPair.getPublic();
                verifier.init(false, pgenerationParams);
                //huhhh surely this should all be abstracted
                byte[] noncesig = new byte[expectedSm_len - m_len - 2 + 1];
                noncesig[0] = (byte)(0x30 + parameters[fileindex].getLogN());
                System.arraycopy(expectedSm, 2, noncesig, 1, 40);
                System.arraycopy(expectedSm, 2 + 40 + m_len, noncesig, 40 + 1, expectedSm_len - 2 - 40 - m_len);

                boolean isValid = verifier.verifySignature(msg, noncesig);

                // AssertTrue
                //keyGenerator
                try {
                    
                } catch (AssertionFailedError e) {
                    // TODO: handle exception
                }
                assertTrue(name + " " + count + " public key", Arrays.areEqual(respk, 0, respk.length, expectedPk, 1, expectedPk.length));
                assertTrue(name + " " + count + " public key", Arrays.areEqual(ressk, 0, ressk.length, expectedSk, 1, expectedSk.length));
                //sign
                assertTrue(name + " " + count + " signature", Arrays.areEqual(ressm, ressm));
                //verify
                assertTrue(name + " " + count + " verify failed when should pass", isValid);
            }
        }
    }
}