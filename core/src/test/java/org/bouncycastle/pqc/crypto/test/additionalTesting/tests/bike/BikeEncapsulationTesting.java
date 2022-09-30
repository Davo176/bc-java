package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.bike;

//Import dependencies
import junit.framework.TestCase;
import java.io.*;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.util.Arrays;
//Asset Under Test
import org.bouncycastle.pqc.crypto.bike.BIKEKEMGenerator;
import org.bouncycastle.pqc.crypto.bike.BIKEParameters;
import org.bouncycastle.pqc.crypto.bike.BIKEPublicKeyParameters;

public class BikeEncapsulationTesting
    extends TestCase
{
    public void testBikeVectors() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "additionalEncap3114.rsp",
            "additionalEncap6198.rsp",
            "additionalEncap10276.rsp",
        };

        BIKEParameters[] paramList = {
            BIKEParameters.bike128,
            BIKEParameters.bike192,
            BIKEParameters.bike256
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = BikeEncapsulationTesting.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/bike/" + name);
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
                BIKEParameters params = paramList[fileIndex];
                //Generate Random from seed (assume this works correctly)
                NISTSecureRandom random = new NISTSecureRandom(seed, null);

                BIKEPublicKeyParameters pubParams = new BIKEPublicKeyParameters(params, pk);


                BIKEKEMGenerator bikekemGenerator = new BIKEKEMGenerator(random);
                SecretWithEncapsulation secretWithEnc = bikekemGenerator.generateEncapsulated(pubParams);
                byte[] returnedCt = secretWithEnc.getEncapsulation();
                byte[] returnedSecret = secretWithEnc.getSecret();
                //CODE FOR PRINTING HEX VALUE OF BYTE ARRAY
                // byte[] hexCt = Hex.encode(returnedCt);
                // String test = new String(hexCt);
                // System.out.println(test);


                //ASSERT EQUAL
                String baseAssertMessage = "TEST FAILED: " + name+ " " + count + ": ";
                
                assertTrue(baseAssertMessage+"cipher text", Arrays.areEqual(expectedCt,returnedCt));

                //by equality axiom, if these two are equal, returned = decapsulated
                assertTrue(baseAssertMessage+"shared secret from party 1", Arrays.areEqual(expectedSs,0,params.getSessionKeySize()/8,returnedSecret,0,params.getSessionKeySize()/8));
                System.out.println("All Passed");
            }
        }
    }
}