package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.kyber;

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
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;

public class KyberTest
    extends TestCase
{
    public void testKyberVectors() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "kyber512.rsp",
            "kyber768.rsp",
            "kyber1024.rsp",
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
            InputStream src = KyberTest.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/kyber/" + name);
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
                byte[] expectedPk = Hex.decode(publicKeyString);
                byte[] expectedSk = Hex.decode(secretKeyString);
                byte[] expectedCt = Hex.decode(cipherTextString);
                byte[] expectedSs = Hex.decode(sharedSecretString);

                System.out.println("Testing Case: "+count);

                //Get Parameters
                KyberParameters params = paramList[fileIndex];
                //Generate Random from seed (assume this works correctly)
                NISTSecureRandom random = new NISTSecureRandom(seed, null);

                KyberKeyPairGenerator kpGen = new KyberKeyPairGenerator();
                KyberKeyGenerationParameters genParam = new KyberKeyGenerationParameters(random, params);

                kpGen.init(genParam);
                AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

                KyberPublicKeyParameters pubParams = (KyberPublicKeyParameters)(KyberPublicKeyParameters)kp.getPublic();
                KyberPrivateKeyParameters privParams = (KyberPrivateKeyParameters)(KyberPrivateKeyParameters)kp.getPrivate();

                byte[] returnedPk=pubParams.getPublicKey();
                byte[] returnedSk=privParams.getPrivateKey();

                KyberKEMGenerator KyberEncCipher = new KyberKEMGenerator(random);
                SecretWithEncapsulation secretWithEnc = KyberEncCipher.generateEncapsulated(pubParams);
                byte[] returnedCt = secretWithEnc.getEncapsulation();

                byte[] returnedSecret = secretWithEnc.getSecret();

                //KyberPrivateKeyParameters privParams2 = new KyberPrivateKeyParameters(params, expectedSk);;

                KyberKEMExtractor KyberDecCipher = new KyberKEMExtractor(privParams);
                byte[] decapsulatedSecret = KyberDecCipher.extractSecret(expectedCt);


                //ASSERT EQUAL
                String baseAssertMessage = "TEST FAILED: " + name+ " " + count + ": ";
                assertTrue(baseAssertMessage+"public key", Arrays.areEqual(expectedPk,returnedPk));
                assertTrue(baseAssertMessage+"secret key", Arrays.areEqual(expectedSk,returnedSk));
                
                assertTrue(baseAssertMessage+"cipher text", Arrays.areEqual(expectedCt,returnedCt));

                //by equality axiom, if these two are equal, returned = decapsulated
                assertTrue(baseAssertMessage+"shared secret from party 1", Arrays.areEqual(expectedSs,0,params.getSessionKeySize()/8,returnedSecret,0,params.getSessionKeySize()/8));
                assertTrue(baseAssertMessage+"shared secret from party 2", Arrays.areEqual(expectedSs,0,params.getSessionKeySize()/8,decapsulatedSecret,0,params.getSessionKeySize()/8));
                System.out.println("All Passed");
            }
        }
    }
}