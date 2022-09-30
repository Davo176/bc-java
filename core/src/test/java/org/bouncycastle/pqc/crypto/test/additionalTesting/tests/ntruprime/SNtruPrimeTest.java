package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.ntruprime;

import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMExtractor;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

import junit.framework.TestCase;

public class SNtruPrimeTest 
extends TestCase
{
    public void testSNTRUPVectors() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "sntrup653.rsp",
            "sntrup761.rsp",
            "sntrup857.rsp",
            "sntrup953.rsp",
            "sntrup1013.rsp",
            "sntrup1277.rsp",
        };

        SNTRUPrimeParameters[] paramList = new SNTRUPrimeParameters[]
        {
            SNTRUPrimeParameters.sntrup653,
            SNTRUPrimeParameters.sntrup761,
            SNTRUPrimeParameters.sntrup857,
            SNTRUPrimeParameters.sntrup953,
            SNTRUPrimeParameters.sntrup1013,
            SNTRUPrimeParameters.sntrup1277
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = NtruLPRimeTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/ntruprime/sntrup/" + name);
            BufferedReader br = new BufferedReader(new InputStreamReader(src));

            // Condition holds true till
            // there is character in a string
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

                NISTSecureRandom random = new NISTSecureRandom(seed, null);
                SNTRUPrimeParameters params = paramList[fileIndex];

                SNTRUPrimeKeyPairGenerator keyPairGenerator = new SNTRUPrimeKeyPairGenerator();
                keyPairGenerator.init(new SNTRUPrimeKeyGenerationParameters(random, params));

                AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

                byte[] returnedPk = ((SNTRUPrimePublicKeyParameters)keyPair.getPublic()).getEncoded();
                byte[] returnedSk = ((SNTRUPrimePrivateKeyParameters)keyPair.getPrivate()).getEncoded();

                SNTRUPrimeKEMGenerator kemGenerator = new SNTRUPrimeKEMGenerator(random);
                SecretWithEncapsulation secretEncapsulation = kemGenerator.generateEncapsulated(keyPair.getPublic());
                byte[] returnedCt = secretEncapsulation.getEncapsulation();
                byte[] returnedSecret = secretEncapsulation.getSecret();


                SNTRUPrimeKEMExtractor kemExtractor = new SNTRUPrimeKEMExtractor((SNTRUPrimePrivateKeyParameters)keyPair.getPrivate());
                byte[] decapsulatedSecret = kemExtractor.extractSecret(secretEncapsulation.getEncapsulation());


                //ASSERT EQUAL
                String baseAssertMessage = "TEST FAILED: " + name+ " " + count + ": ";
                assertTrue(baseAssertMessage+"public key", Arrays.areEqual(expectedPk,returnedPk));
                assertTrue(baseAssertMessage+"secret key", Arrays.areEqual(expectedSk,returnedSk));
                
                assertTrue(baseAssertMessage+"cipher text", Arrays.areEqual(expectedCt,returnedCt));

                //by equality axiom, if these two are equal, returned = decapsulated
                assertTrue(baseAssertMessage+"shared secret from party 1", Arrays.areEqual(expectedSs,0,params.getSessionKeySize()/8,returnedSecret,0,params.getSessionKeySize()/8));
                assertTrue(baseAssertMessage+"shared secret from party 2", Arrays.areEqual(expectedSs,0,params.getSessionKeySize()/8,decapsulatedSecret,0,params.getSessionKeySize()/8));
                System.out.println("All Passed");
            }
        }
    }
}
