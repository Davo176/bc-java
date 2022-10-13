package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.saber;

import junit.framework.AssertionFailedError;
//Import dependencies
import junit.framework.TestCase;
import java.io.*;
import java.util.ArrayList;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;

import org.bouncycastle.util.Arrays;
//Asset Under Test
import org.bouncycastle.pqc.crypto.saber.SABERKEMExtractor;
import org.bouncycastle.pqc.crypto.saber.SABERParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPrivateKeyParameters;

public class SaberCheckDecapsulation
    extends TestCase
{
    public void testSaberDecapsulation() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "encapsulation_java_ref_1568.rsp",
            "encapsulation_java_ref_2304.rsp",
            "encapsulation_java_ref_3040.rsp",
        };

        SABERParameters[] paramList = new SABERParameters[] {
            SABERParameters.lightsaberkem256r3,
            SABERParameters.saberkem256r3,
            SABERParameters.firesaberkem256r3,
        };

        ArrayList<String> failures = new ArrayList<String>();

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = SaberDecapsulationTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/saber/interoperability/" + name);
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

                //Get Parameters
                SABERParameters params = paramList[fileIndex];
                
                SABERPrivateKeyParameters privateKeyParams = new SABERPrivateKeyParameters(params, sk);

                SABERKEMExtractor decapsulator = new SABERKEMExtractor(privateKeyParams);
                
                byte[] decapsulatedSecret = decapsulator.extractSecret(ct);
                //ASSERT EQUAL
                String baseAssertMessage = "TEST FAILED: " + name+ " " + count + ": ";
                //by equality axiom, if these two are equal, returned = decapsulated
                try {
                    assertTrue(baseAssertMessage+"shared secret", Arrays.areEqual(expectedSs,decapsulatedSecret));
                    System.out.println("All Passed");
                } catch (AssertionFailedError e) {
                    failures.add(baseAssertMessage+"shared secret");
                }
            }
        }
        for (String fail:failures){
            System.out.println(fail);
        }
    }
}