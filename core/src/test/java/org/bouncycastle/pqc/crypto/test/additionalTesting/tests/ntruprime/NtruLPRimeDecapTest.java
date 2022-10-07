package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.ntruprime;

//Import dependencies
import junit.framework.TestCase;
import java.io.*;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.Arrays;
//Asset Under Test
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKEMExtractor;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePrivateKeyParameters;

public class NtruLPRimeDecapTest
    extends TestCase
{
    public void testNTRULPRVectors() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "addDecap653.rsp", //fail
            "addDecap761.rsp", //fail
            "addDecap857.rsp", //fail
            "addDecap953.rsp", //fail
            "addDecap1013.rsp", //fail
            "addDecap1277.rsp", //fail
        };

        NTRULPRimeParameters[] paramList = new NTRULPRimeParameters[]
        {
            NTRULPRimeParameters.ntrulpr653,
            NTRULPRimeParameters.ntrulpr761,
            NTRULPRimeParameters.ntrulpr857,
            NTRULPRimeParameters.ntrulpr953,
            NTRULPRimeParameters.ntrulpr1013,
            NTRULPRimeParameters.ntrulpr1277
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = NtruLPRimeDecapTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/ntruprime/decapTesting/ntrulpr/" + name);
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
                byte[] sk = Hex.decode(secretKeyString);
                byte[] expectedCt = Hex.decode(cipherTextString);
                byte[] expectedSs = Hex.decode(sharedSecretString);

                System.out.println("Testing Case: "+count);

                //Get Parameters
                NTRULPRimeParameters params = paramList[fileIndex];
                
                //Calculate Values
                //Generate Key Pairs
                NTRULPRimePrivateKeyParameters privateKeyParams = new NTRULPRimePrivateKeyParameters(params,sk);


                NTRULPRimeKEMExtractor decapsulator = new NTRULPRimeKEMExtractor(privateKeyParams);
                byte[] decapsulatedSecret = decapsulator.extractSecret(expectedCt);


                //ASSERT EQUAL
                String baseAssertMessage = "TEST FAILED: " + name+ " " + count + ": ";

                assertTrue(baseAssertMessage+"shared secret", Arrays.areEqual(expectedSs,0,params.getSessionKeySize()/8,decapsulatedSecret,0,params.getSessionKeySize()/8));
                System.out.println("All Passed");
            }
        }
    }
}