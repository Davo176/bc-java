package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.ntruprime;

//Import dependencies
import junit.framework.TestCase;
import java.io.*;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

//Asset Under Test
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePublicKeyParameters;
public class NtruLPRimeCreateKeyPairs
    extends TestCase
{
    public void test() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "keypairs_java_1125.rsp",
            "keypairs_java_1294.rsp",
            "keypairs_java_1463.rsp",
            "keypairs_java_1652.rsp",
            "keypairs_java_1773.rsp",
            "keypairs_java_2231.rsp",
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
            try {
                File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/ntruprime/interoperability/ntrulpr/"+name);
                if (myObj.createNewFile()) {
                  System.out.println("File created: " + myObj.getName());
                } else {
                  System.out.println("File already exists.");
                }
              } catch (IOException e) {
                System.out.println("An error occurred.");
                e.printStackTrace();
              }
            
            System.out.println("testing: " + name);
            FileWriter file = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/ntruprime/interoperability/ntrulpr/"+name);

            byte[] seed = new byte[48];
            byte[] entropy_input = new byte[48];
            for (int i=0;i<48;i++){
                entropy_input[i]=(byte)i;
            }
            byte[] personalisation = new byte[48];
            for (int i=48;i>0;i--){
                personalisation[48-i]=(byte)i;
            }
            NISTSecureRandom random = new NISTSecureRandom(entropy_input, personalisation);
            NTRULPRimeParameters params = paramList[fileIndex];

            for (int i=0;i<100;i++){
                int count = i;
                System.out.println("Testing Case: "+count);

                random.nextBytes(seed);
                file.write("count = "+count+"\n");
                file.write("seed = "+Hex.toHexString(seed)+"\n");
                
                NTRULPRimeKeyPairGenerator keyGenerator = new NTRULPRimeKeyPairGenerator();
                NTRULPRimeKeyGenerationParameters generationParams = new NTRULPRimeKeyGenerationParameters(random, params);

                keyGenerator.init(generationParams);
                AsymmetricCipherKeyPair kp = keyGenerator.generateKeyPair();

                NTRULPRimePublicKeyParameters publicKeyParams = (NTRULPRimePublicKeyParameters)kp.getPublic();
                NTRULPRimePrivateKeyParameters privateKeyParams = (NTRULPRimePrivateKeyParameters)kp.getPrivate();

                byte[] returnedPk=publicKeyParams.getEncoded();
                byte[] returnedSk=privateKeyParams.getEncoded();
                file.write("pk = "+Hex.toHexString(returnedPk)+"\n");
                file.write("sk = "+Hex.toHexString(returnedSk)+"\n");
                file.write("\n");
            }
            file.close();
        }
    }
}