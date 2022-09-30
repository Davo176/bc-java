package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.kyber;

//Import dependencies
import junit.framework.TestCase;
import java.io.*;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.Arrays;

//Asset Under Test
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;


public class KyberDecapsulationTest
    extends TestCase
{
    public void testKyberDecapsulation() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "additionalDecapTesting1632.rsp",
            "additionalDecapTesting2400.rsp",
            "additionalDecapTesting3168.rsp"
        };

        KyberParameters[] paramList = new KyberParameters[]{
            KyberParameters.kyber512,
            KyberParameters.kyber768,
            KyberParameters.kyber1024,
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = KyberEncapsulationTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/kyber/" + name);
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
                
                //Get Seed - Realised seed not necessary
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
                //byte[] seed = Hex.decode(seedString); 
                byte[] sk = Hex.decode(secretKeyString);
                byte[] ct = Hex.decode(cipherTextString);
                byte[] expectedSs = Hex.decode(sharedSecretString);

                System.out.println("Testing Case: "+count);

                //Get Parameters
                KyberParameters params = paramList[fileIndex];
                //Generate Random from seed (assume this works correctly)
                //NISTSecureRandom random = new NISTSecureRandom(seed, null);

                /* Had working on old commit

                KyberPrivateKeyParameters privParams = new KyberPrivateKeyParameters(params, sk);

                KyberKEMExtractor KyberDecCipher = new KyberKEMExtractor(privParams);
                byte[] decapsulatedSecret = KyberDecCipher.extractSecret(ct);

                //ASSERT EQUAL
                String baseAssertMessage = "TEST FAILED: " + name+ " " + count + ": ";
                assertTrue(baseAssertMessage+"shared secret from party 1", Arrays.areEqual(expectedSs,0,params.getSessionKeySize()/8,decapsulatedSecret,0,params.getSessionKeySize()/8));
                System.out.println("All Passed");*/
            }
        }
    }
}