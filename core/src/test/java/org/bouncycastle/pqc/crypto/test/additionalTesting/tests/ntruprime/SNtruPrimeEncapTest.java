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

public class SNtruPrimeEncapTest 
extends TestCase
{
    public void testSNTRUPVectors() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "addEncap653.rsp",
            "addEncap761.rsp", //fail
            "addEncap857.rsp", //fail
            "addEncap953.rsp", //fail
            "addEncap1013.rsp", //fail
            "addEncap1277.rsp", //fail
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
            InputStream src = NtruLPRimeTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/ntruprime/encapTesting/sntru/" + name);
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

                NISTSecureRandom random = new NISTSecureRandom(seed, null);
                SNTRUPrimeParameters params = paramList[fileIndex];

                SNTRUPrimePublicKeyParameters pubParam = new SNTRUPrimePublicKeyParameters(params, pk);

                SNTRUPrimeKEMGenerator encapsulator = new SNTRUPrimeKEMGenerator(random);
                SecretWithEncapsulation secretEncapsulation = encapsulator.generateEncapsulated(pubParam);
                byte[] returnedCt = secretEncapsulation.getEncapsulation();
                byte[] returnedSecret = secretEncapsulation.getSecret();


                //ASSERT EQUAL
                String baseAssertMessage = "TEST FAILED: " + name+ " " + count + ": ";                
                assertTrue(baseAssertMessage+"cipher text", Arrays.areEqual(expectedCt,returnedCt));
                assertTrue(baseAssertMessage+"shared secret from party 1", Arrays.areEqual(expectedSs,0,params.getSessionKeySize()/8,returnedSecret,0,params.getSessionKeySize()/8));

                System.out.println("All Passed");
            }
        }
    }
}
