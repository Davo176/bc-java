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

public class SntruPrimeCheckDecapsulations 
extends TestCase
{
    public void testSNTRUPVectors() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "encapsulation_java_ref_1518.rsp", 
            "encapsulation_java_ref_1763.rsp", 
            "encapsulation_java_ref_1999.rsp", 
            "encapsulation_java_ref_2254.rsp", 
            "encapsulation_java_ref_2417.rsp",
            "encapsulation_java_ref_3059.rsp",
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
            InputStream src = NtruLPRimeTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/ntruprime/interoperability/sntru/" + name);
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
                byte[] sk = Hex.decode(secretKeyString);
                byte[] ct = Hex.decode(cipherTextString);
                byte[] expectedSs = Hex.decode(sharedSecretString);

                System.out.println("Testing Case: "+count);

                SNTRUPrimeParameters params = paramList[fileIndex];

                SNTRUPrimePrivateKeyParameters privateKeyParams = new SNTRUPrimePrivateKeyParameters(params,sk);

                SNTRUPrimeKEMExtractor decapsulator = new SNTRUPrimeKEMExtractor(privateKeyParams);
                byte[] decapsulatedSecret = decapsulator.extractSecret(ct);

                //ASSERT EQUAL
                String baseAssertMessage = "TEST FAILED: " + name+ " " + count + ": ";

                assertTrue(baseAssertMessage+"shared secret from party 2", Arrays.areEqual(expectedSs,0,params.getSessionKeySize()/8,decapsulatedSecret,0,params.getSessionKeySize()/8));
                System.out.println("All Passed");
            }
        }
    }
}
