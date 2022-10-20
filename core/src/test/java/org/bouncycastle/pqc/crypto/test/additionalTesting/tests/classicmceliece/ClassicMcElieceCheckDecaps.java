package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.classicmceliece;

import junit.framework.AssertionFailedError;
//Import dependencies
import junit.framework.TestCase;
import java.io.*;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.util.Arrays;
//Asset Under Test
import org.bouncycastle.pqc.crypto.cmce.CMCEKEMExtractor;
import org.bouncycastle.pqc.crypto.cmce.CMCEKEMGenerator;
import org.bouncycastle.pqc.crypto.cmce.CMCEKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEKeyPairGenerator;
import org.bouncycastle.pqc.crypto.cmce.CMCEParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEPublicKeyParameters;

public class ClassicMcElieceCheckDecaps
    extends TestCase
{
    public void testCMCEVectors() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "std/encapsulation_java_ref_6492.rsp",
            "f/encapsulation_java_ref_6492.rsp",
            "std/encapsulation_java_ref_13608.rsp",
            "f/encapsulation_java_ref_13608.rsp",
            "std/encapsulation_java_ref_13932.rsp",
            "f/encapsulation_java_ref_13932.rsp",
            "std/encapsulation_java_ref_13948.rsp",
            "f/encapsulation_java_ref_13948.rsp",
            "std/encapsulation_java_ref_14120.rsp",
            "f/encapsulation_java_ref_14120.rsp"
        };

        CMCEParameters[] paramList = new CMCEParameters[]{
            CMCEParameters.mceliece348864r3,
            CMCEParameters.mceliece348864fr3,
            CMCEParameters.mceliece460896r3,
            CMCEParameters.mceliece460896fr3,
            CMCEParameters.mceliece6688128r3,
            CMCEParameters.mceliece6688128fr3,
            CMCEParameters.mceliece6960119r3,
            CMCEParameters.mceliece6960119fr3,
            CMCEParameters.mceliece8192128r3,
            CMCEParameters.mceliece8192128fr3
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = ClassicMcElieceTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/cmce/interoperability/" + name);
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
                byte[] expectedSk = Hex.decode(secretKeyString);
                byte[] expectedCt = Hex.decode(cipherTextString);
                byte[] expectedSs = Hex.decode(sharedSecretString);

                System.out.println("Testing Case: "+count);

                //Get Parameters
                CMCEParameters parameters = paramList[fileIndex];
                //Generate Random from seed (assume this works correctly)
                
                CMCEPrivateKeyParameters privateKeyParams = new CMCEPrivateKeyParameters(parameters,expectedSk);

                CMCEKEMExtractor decapsulator = new CMCEKEMExtractor(privateKeyParams);

                byte[] decapsulatedSecret = decapsulator.extractSecret(expectedCt);
                //ASSERT EQUAL
                String baseAssertMessage = "TEST FAILED: " + name+ " " + count + ": ";

                //by equality axiom, if these two are equal, returned = decapsulated
                try {
                    
                    assertTrue(baseAssertMessage+"shared secret from party 1", Arrays.areEqual(expectedSs,0,parameters.getSessionKeySize()/8,decapsulatedSecret,0,parameters.getSessionKeySize()/8));
                    System.out.println("All Passed");
                } catch (AssertionFailedError e) {
                    //failures.add(baseAssertMessage+"shared secret from party 1");
                }
            }
        }
    }
}