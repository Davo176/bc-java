package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.frodo;

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
import org.bouncycastle.pqc.crypto.frodo.FrodoKEMExtractor;
import org.bouncycastle.pqc.crypto.frodo.FrodoKEMGenerator;
import org.bouncycastle.pqc.crypto.frodo.FrodoKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoKeyPairGenerator;
import org.bouncycastle.pqc.crypto.frodo.FrodoParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPublicKeyParameters;

public class FrodoTest
    extends TestCase
{
    public void testFrodoVectors() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "addRandTest_19888.rsp",
            "addRandTest_31296.rsp",
            "addRandTest_43088.rsp",
            "addRandTest_shake_19888.rsp",
            "addRandTest_shake_31296.rsp",
            "addRandTest_shake_43088.rsp",
        };

        FrodoParameters[] paramList = {
            FrodoParameters.frodokem640aes,
            FrodoParameters.frodokem976aes,
            FrodoParameters.frodokem1344aes,
            FrodoParameters.frodokem640shake,
            FrodoParameters.frodokem976shake,
            FrodoParameters.frodokem1344shake,
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = FrodoTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/frodo/" + name);
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
                //Get Secret Key
                int secretKeyIndex = line.indexOf("sk = ");
                String secretKeyString = line.substring(secretKeyIndex + "sk = ".length()).trim();
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
                byte[] expectedPk = Hex.decode(publicKeyString);
                byte[] expectedSk = Hex.decode(secretKeyString);
                byte[] expectedCt = Hex.decode(cipherTextString);
                byte[] expectedSs = Hex.decode(sharedSecretString);

                System.out.println("Testing Case: "+count);

                //Get Parameters
                FrodoParameters parameters = paramList[fileIndex];
                //Generate Random from seed (assume this works correctly)
                NISTSecureRandom random = new NISTSecureRandom(seed, null);

                FrodoKeyPairGenerator keyGenerator = new FrodoKeyPairGenerator();
                FrodoKeyGenerationParameters generationParams = new FrodoKeyGenerationParameters(random, parameters);
                
                keyGenerator.init(generationParams);
                AsymmetricCipherKeyPair keyPair = keyGenerator.generateKeyPair();

                FrodoPublicKeyParameters publicKeyParams = (FrodoPublicKeyParameters)keyPair.getPublic();
                FrodoPrivateKeyParameters privateKeyParams = (FrodoPrivateKeyParameters)keyPair.getPrivate();

                byte[] returnedPk = publicKeyParams.getEncoded();
                byte[] returnedSk = privateKeyParams.getEncoded();

                FrodoKEMGenerator encapsulator = new FrodoKEMGenerator(random);
                SecretWithEncapsulation encapsulatedSecret = encapsulator.generateEncapsulated(publicKeyParams);
                byte[] returnedCt = encapsulatedSecret.getEncapsulation();
                byte[] returnedSecret = encapsulatedSecret.getSecret();

                FrodoKEMExtractor decapsulator = new FrodoKEMExtractor(privateKeyParams);
                byte[] decapsulatedSecret = decapsulator.extractSecret(returnedCt);

                //ASSERT EQUAL
                String baseAssertMessage = "TEST FAILED: " + name+ " " + count + ": ";
                assertTrue(baseAssertMessage+"public key", Arrays.areEqual(expectedPk,returnedPk));
                assertTrue(baseAssertMessage+"secret key", Arrays.areEqual(expectedSk,returnedSk));
                
                assertTrue(baseAssertMessage+"cipher text", Arrays.areEqual(expectedCt,returnedCt));

                //by equality axiom, if these two are equal, returned = decapsulated
                assertTrue(baseAssertMessage+"shared secret from party 1", Arrays.areEqual(expectedSs,0,parameters.getSessionKeySize()/8,returnedSecret,0,parameters.getSessionKeySize()/8));
                assertTrue(baseAssertMessage+"shared secret from party 2", Arrays.areEqual(expectedSs,0,parameters.getSessionKeySize()/8,decapsulatedSecret,0,parameters.getSessionKeySize()/8));
                System.out.println("All Passed");
            }
        }
    }
}