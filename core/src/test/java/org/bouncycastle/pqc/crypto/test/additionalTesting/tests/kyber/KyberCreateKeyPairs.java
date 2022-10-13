package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.kyber;

//Import dependencies
import junit.framework.TestCase;
import java.io.*;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

//Asset Under Test

import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;

public class KyberCreateKeyPairs
    extends TestCase
{
    public void testKyberVectors() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "keypairs_java_1632.rsp",
            "keypairs_java_2400.rsp",
            "keypairs_java_3168.rsp",
        };

        KyberParameters[] paramList = new KyberParameters[]{
            KyberParameters.kyber512,
            KyberParameters.kyber768,
            KyberParameters.kyber1024,
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            try {
                File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/kyber/interoperability/"+name);
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
            FileWriter file = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/kyber/interoperability/"+name);

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
            KyberParameters params = paramList[fileIndex];

            for (int i=0;i<100;i++){
                int count = i;
                System.out.println("Testing Case: "+count);

                random.nextBytes(seed);
                file.write("count = "+count+"\n");
                file.write("seed = "+Hex.toHexString(seed)+"\n");
                
                KyberKeyPairGenerator keyGenerator = new KyberKeyPairGenerator();
                KyberKeyGenerationParameters generationParams = new KyberKeyGenerationParameters(random, params);

                keyGenerator.init(generationParams);
                AsymmetricCipherKeyPair kp = keyGenerator.generateKeyPair();

                KyberPublicKeyParameters publicKeyParams = (KyberPublicKeyParameters)kp.getPublic();
                KyberPrivateKeyParameters privateKeyParams = (KyberPrivateKeyParameters)kp.getPrivate();

                byte[] returnedPk=publicKeyParams.getPublicKey();
                byte[] returnedSk=privateKeyParams.getPrivateKey();
                file.write("pk = "+Hex.toHexString(returnedPk)+"\n");
                file.write("sk = "+Hex.toHexString(returnedSk)+"\n");
                file.write("\n");
            }
            file.close();
        }
    }
}