package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.sike;

import junit.framework.AssertionFailedError;
//Import dependencies
import junit.framework.TestCase;
import java.io.*;
import java.util.ArrayList;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;

import org.bouncycastle.util.Arrays;
//Asset Under Test
import org.bouncycastle.pqc.crypto.sike.SIKEKEMExtractor;
import org.bouncycastle.pqc.crypto.sike.SIKEParameters;
import org.bouncycastle.pqc.crypto.sike.SIKEPrivateKeyParameters;

public class SikeCheckDecapsulation
    extends TestCase
{
    public void testSikeDecapsulation() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "encapsulation_java_ref_374.rsp",
            "encapsulation_java_ref_434.rsp",
            "encapsulation_java_ref_524.rsp",
            "encapsulation_java_ref_644.rsp",
        };

        SIKEParameters[] paramList = {
            SIKEParameters.sikep434,
            SIKEParameters.sikep503,
            SIKEParameters.sikep610,
            SIKEParameters.sikep751,
        };
        ArrayList<String> failures = new ArrayList<String>();

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = SikeCheckDecapsulation.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/sike/interoperability/" + name);
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
                SIKEParameters params = paramList[fileIndex];
                
                SIKEPrivateKeyParameters privateKeyParams = new SIKEPrivateKeyParameters(params, sk);

                SIKEKEMExtractor decapsulator = new SIKEKEMExtractor(privateKeyParams);
                
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