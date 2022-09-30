package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.saber;

//Import dependencies
import junit.framework.TestCase;
import java.io.*;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.util.Arrays;
//Asset Under Test
import org.bouncycastle.pqc.crypto.saber.SABERKEMExtractor;
import org.bouncycastle.pqc.crypto.saber.SABERKEMGenerator;
import org.bouncycastle.pqc.crypto.saber.SABERKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.saber.SABERKeyPairGenerator;
import org.bouncycastle.pqc.crypto.saber.SABERParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPublicKeyParameters;

public class SaberEncapsulationTest
    extends TestCase
{
    public void testSaberEncapsulation() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "additionalEncapTesting_1568.rsp",
            "additionalEncapTesting_2304.rsp",
            "additionalEncapTesting_3040.rsp",
        };

        SABERParameters[] paramList = new SABERParameters[] {
            SABERParameters.lightsaberkem256r3,
            SABERParameters.saberkem256r3,
            SABERParameters.firesaberkem256r3,
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = SaberEncapsulationTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/saber/" + name);
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
                //Get Public Key
                int publicKeyIndex = line.indexOf("pk = ");
                String publicKeyString = line.substring(publicKeyIndex + "pk = ".length()).trim();
                line = br.readLine();
                //Get Cipher Text
                int cipherTextIndex = line.indexOf("ct = ");
                String cipherTextString = line.substring(cipherTextIndex + "ct = ".length()).trim();
                line = br.readLine();
                //Get Shared Secret (session key)
                int sharedSecretIndex = line.indexOf("ss = ");
                String sharedSecretString = line.substring(sharedSecretIndex + "ss = ".length()).trim();
                line = br.readLine();

                //convert all into byte arrays
                byte[] seed = Hex.decode(seedString); 
                byte[] pk = Hex.decode(publicKeyString);
                byte[] expectedCt = Hex.decode(cipherTextString);
                byte[] expectedSs = Hex.decode(sharedSecretString);

                System.out.println("Testing Case: "+count);

                //Get Parameters
                SABERParameters params = paramList[fileIndex];
                //Generate Random from seed (assume this works correctly)
                NISTSecureRandom random = new NISTSecureRandom(seed, null);
                
                SABERPublicKeyParameters pubParams = new SABERPublicKeyParameters(params, pk);

                SABERKEMGenerator SABEREncCipher = new SABERKEMGenerator(random);
                SecretWithEncapsulation secretEncapsulation = SABEREncCipher.generateEncapsulated(pubParams);
                byte[] returnedCt = secretEncapsulation.getEncapsulation();

                byte[] returnedSecret = secretEncapsulation.getSecret();

                //ASSERT EQUAL
                String baseAssertMessage = "TEST FAILED: " + name+ " " + count + ": ";
                
                assertTrue(baseAssertMessage+"cipher text", Arrays.areEqual(expectedCt,returnedCt));

                //by equality axiom, if these two are equal, returned = decapsulated
                assertTrue(baseAssertMessage+"shared secret from party 1", Arrays.areEqual(expectedSs,returnedSecret));
                System.out.println("All Passed");
            }
        }
    }
}