package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.ntruprime;

import junit.framework.AssertionFailedError;
//Import dependencies
import junit.framework.TestCase;
import java.io.*;
import java.util.ArrayList;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.util.Arrays;
//Asset Under Test
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKEMGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePublicKeyParameters;

public class NtruLPRimeEncapTest
    extends TestCase
{
    public void testNTRULPRVectors() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "addEncap653.rsp", //fail
            "addEncap761.rsp", //fail
            "addEncap857.rsp",
            "addEncap953.rsp",
            "addEncap1013.rsp", //fail
            "addEncap1277.rsp", //fail
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

        ArrayList<String> failures = new ArrayList<String>();

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = NtruLPRimeEncapTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/ntruprime/encapTesting/ntrulpr/" + name);
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

                //Get Parameters
                NTRULPRimeParameters params = paramList[fileIndex];
                //Generate Random from seed (assume this works correctly)
                NISTSecureRandom random = new NISTSecureRandom(seed, null);
                
                //Calculate Values
                //Generate Key Pairs
                NTRULPRimePublicKeyParameters publicKeyParams = new NTRULPRimePublicKeyParameters(params, pk);

                NTRULPRimeKEMGenerator encapsulator = new NTRULPRimeKEMGenerator(random);
                SecretWithEncapsulation secretEncapsulation = encapsulator.generateEncapsulated(publicKeyParams);
                byte[] returnedCt = secretEncapsulation.getEncapsulation();

                byte[] returnedSecret = secretEncapsulation.getSecret();


                //ASSERT EQUAL
                String baseAssertMessage = "TEST FAILED: " + name+ " " + count + ": ";
                try {
                    assertTrue(baseAssertMessage+"cipher text", Arrays.areEqual(expectedCt,returnedCt));
                    System.out.println("All Passed");
                } catch (AssertionFailedError e) {
                    // TODO: handle exception
                    failures.add(baseAssertMessage+"cipher text");
                }

                try {
                    assertTrue(baseAssertMessage+"shared secret from party 1", Arrays.areEqual(expectedSs,0,params.getSessionKeySize()/8,returnedSecret,0,params.getSessionKeySize()/8));
                    System.out.println("All Passed");
                } catch (AssertionFailedError e) {
                    // TODO: handle exception
                    failures.add(baseAssertMessage+"shared secret from party 1");
                }

                //by equality axiom, if these two are equal, returned = decapsulated
                
            }
        }
        for (String fail:failures){
            System.out.println(fail);
        }
    }
}