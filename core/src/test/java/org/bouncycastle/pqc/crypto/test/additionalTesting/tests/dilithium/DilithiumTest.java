package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.dilithium;

//Import dependencies
import junit.framework.TestCase;
import java.io.*;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.crypto.params.ParametersWithRandom;
//Asset Under Test
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator;


public class DilithiumTest extends TestCase
{
    public void testDilithiumVectors() 
        throws Exception
    {
        //System.out.println("test");
        String[] files = new String[]{
            "addRand_Dilithium2.rsp",
            "addRand_Dilithium3.rsp",
            "addRand_Dilithium5.rsp"
        };
        DilithiumParameters[] parameters = new DilithiumParameters[]{
            DilithiumParameters.dilithium2,
            DilithiumParameters.dilithium3,
            DilithiumParameters.dilithium5
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = DilithiumTestSign.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/dilithium/" + name);
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
                //Get public Key
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
                byte[] seed = Hex.decode(seedString); // seed for Dilithium secure random
                byte[] pk = Hex.decode(publicKeyString);     // private key
                byte[] sk = Hex.decode(secretKeyString);     // private key
                byte[] sm = Hex.decode(smString);     // signed message
                int sm_len = Integer.parseInt(smlenString);
                byte[] msg = Hex.decode(messageString); // message
                int m_len = Integer.parseInt(mlenString);

                System.out.println("Testing Case: "+count);

                NISTSecureRandom random = new NISTSecureRandom(seed, null);

                // keyGenerator
                DilithiumKeyGenerationParameters generationParams = new DilithiumKeyGenerationParameters(random, parameters[fileIndex]);
                DilithiumKeyPairGenerator keyGenerator = new DilithiumKeyPairGenerator();
                keyGenerator.init(generationParams);

                AsymmetricCipherKeyPair keyPair = keyGenerator.generateKeyPair();
                DilithiumPublicKeyParameters publicKeyParams = (DilithiumPublicKeyParameters)keyPair.getPublic();
                DilithiumPrivateKeyParameters privateKeyParams = (DilithiumPrivateKeyParameters)keyPair.getPrivate();
                
                // sign
                DilithiumSigner signer = new DilithiumSigner();

                signer.init(true, privateKeyParams);

                byte[] sigGenerated = signer.generateSignature(msg);
                byte[] attachedSig = Arrays.concatenate(sigGenerated, msg);

                // verify
                DilithiumSigner verifier = new DilithiumSigner();
                DilithiumPublicKeyParameters pgenerationParams = publicKeyParams;
                verifier.init(false, pgenerationParams);

                boolean vrfyrespass = verifier.verifySignature(msg, sigGenerated);
                sigGenerated[3]++;
                boolean vrfyresfail = verifier.verifySignature(msg, sigGenerated);

                // AssertTrue
                assertTrue(name + " " + count + " public key", Arrays.areEqual(publicKeyParams.getEncoded(), pk));
                assertTrue(name + " " + count + " secret key", Arrays.areEqual(privateKeyParams.getEncoded(), sk));
                //sign

                assertTrue(name + " " + count + " signature", Arrays.areEqual(attachedSig, sm));
                //verify
                assertTrue(name + " " + count + " verify failed when should pass", vrfyrespass);
                assertFalse(name + " " + count + " verify passed when should fail", vrfyresfail);
            }
        }
    }
}