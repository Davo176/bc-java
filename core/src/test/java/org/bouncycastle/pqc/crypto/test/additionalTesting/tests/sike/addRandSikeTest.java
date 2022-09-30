package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.sike;

import junit.framework.TestCase;
import java.io.*;

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;

import org.bouncycastle.pqc.crypto.sike.SIKEKEMExtractor;
import org.bouncycastle.pqc.crypto.sike.SIKEKEMGenerator;
import org.bouncycastle.pqc.crypto.sike.SIKEKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sike.SIKEKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sike.SIKEParameters;
import org.bouncycastle.pqc.crypto.sike.SIKEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sike.SIKEPublicKeyParameters;

public class addRandSikeTest extends TestCase {
    public void testSikeVectors() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "addRandTest_374.rsp",
            "addRandTest_503.rsp",
            "addRandTest_610.rsp",
            "addRandTest_751.rsp",
        };

        SIKEParameters[] paramList = {
            SIKEParameters.sikep434,
            SIKEParameters.sikep503,
            SIKEParameters.sikep610,
            SIKEParameters.sikep751,
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = SikeTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/sike/addRandTest/" + name);
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
                SIKEParameters parameters = paramList[fileIndex];
                //Generate Random from seed (assume this works correctly)
                NISTSecureRandom random = new NISTSecureRandom(seed, null);

                SIKEKeyPairGenerator keygen = new SIKEKeyPairGenerator();
                SIKEKeyGenerationParameters keygenParams = new SIKEKeyGenerationParameters(random, parameters);
                
                keygen.init(keygenParams);
                AsymmetricCipherKeyPair keyPair = keygen.generateKeyPair();

                SIKEPublicKeyParameters pubParams = (SIKEPublicKeyParameters)keyPair.getPublic();
                SIKEPrivateKeyParameters privParams = (SIKEPrivateKeyParameters)keyPair.getPrivate();

                byte[] returnedPk = pubParams.getEncoded();
                byte[] returnedSk = privParams.getEncoded();

                SIKEKEMGenerator SikeGenerator = new SIKEKEMGenerator(random);
                SecretWithEncapsulation secretWithEnc = SikeGenerator.generateEncapsulated(pubParams);
                byte[] returnedCt = secretWithEnc.getEncapsulation();
                byte[] returnedSecret = secretWithEnc.getSecret();

                SIKEKEMExtractor SikeExtractor = new SIKEKEMExtractor(privParams);
                byte[] decapsulatedSecret = SikeExtractor.extractSecret(returnedCt);

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

        System.out.println("test");
    }
}
