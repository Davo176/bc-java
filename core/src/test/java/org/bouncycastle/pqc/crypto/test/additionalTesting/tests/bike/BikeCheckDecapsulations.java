package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.bike;

import junit.framework.AssertionFailedError;
//Import dependencies
import junit.framework.TestCase;
import java.io.*;
import java.util.ArrayList;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;

import org.bouncycastle.util.Arrays;
//Asset Under Test
import org.bouncycastle.pqc.crypto.bike.BIKEKEMExtractor;
import org.bouncycastle.pqc.crypto.bike.BIKEParameters;
import org.bouncycastle.pqc.crypto.bike.BIKEPrivateKeyParameters;

public class BikeCheckDecapsulations
    extends TestCase
{
    public void testBikeVectors() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "encapsulation_java_ref_3114.rsp",
            "encapsulation_java_ref_6198.rsp",
            "encapsulation_java_ref_10276.rsp",
        };

        BIKEParameters[] paramList = {
            BIKEParameters.bike128,
            BIKEParameters.bike192,
            BIKEParameters.bike256
        };

        ArrayList<String> failures = new ArrayList<String>();

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = BikeDecapsulationTesting.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/bike/interoperability/" + name);
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
                int intCount = Integer.parseInt(count);

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
                BIKEParameters parameters = paramList[fileIndex];

                byte[] h0 = Arrays.copyOfRange(sk,0,parameters.getRByte());
                byte[] h1 = Arrays.copyOfRange(sk,parameters.getRByte(),2*parameters.getRByte());
                byte[] sigma = Arrays.copyOfRange(sk,2*parameters.getRByte(),sk.length);

                BIKEPrivateKeyParameters privateKeyParams = new BIKEPrivateKeyParameters(parameters,h0, h1, sigma);

                BIKEKEMExtractor decapsulator = new BIKEKEMExtractor(privateKeyParams);
                byte[] decapsulatedSecret = decapsulator.extractSecret(ct);

                //ASSERT EQUAL
                String baseAssertMessage = "TEST FAILED: " + name+ " " + count + ": ";
                try {
                    assertTrue(baseAssertMessage+"shared secret from party 2", Arrays.areEqual(expectedSs,0,parameters.getSessionKeySize()/8,decapsulatedSecret,0,parameters.getSessionKeySize()/8));
                    System.out.println("All Passed");
                } catch (AssertionFailedError e) {
                    failures.add(baseAssertMessage+"shared secret from party 1");
                }
            }
        }
        for (String fail:failures){
            System.out.println(fail);
        }
    }
}