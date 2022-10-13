package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.saber;

//Import dependencies
import junit.framework.TestCase;
import java.io.*;

//Import dependencies

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

//Asset Under Test
import org.bouncycastle.pqc.crypto.saber.SABERKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.saber.SABERKeyPairGenerator;
import org.bouncycastle.pqc.crypto.saber.SABERParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPublicKeyParameters;
public class SaberCreateKeyPairs
    extends TestCase
{
    public void test() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "keypairs_java_1568.rsp",
            "keypairs_java_2304.rsp",
            "keypairs_java_3040.rsp",
        };

        SABERParameters[] paramList = new SABERParameters[]{
            SABERParameters.lightsaberkem256r3,
            SABERParameters.saberkem256r3,
            SABERParameters.firesaberkem256r3,
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            try {
                File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/saber/interoperability/"+name);
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
            FileWriter file = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/saber/interoperability/"+name);

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
            SABERParameters params = paramList[fileIndex];

            for (int i=0;i<100;i++){
                int count = i;
                System.out.println("Testing Case: "+count);

                random.nextBytes(seed);
                file.write("count = "+count+"\n");
                file.write("seed = "+Hex.toHexString(seed)+"\n");
                
                SABERKeyPairGenerator keyGenerator = new SABERKeyPairGenerator();
                SABERKeyGenerationParameters generationParams = new SABERKeyGenerationParameters(random, params);

                keyGenerator.init(generationParams);
                AsymmetricCipherKeyPair kp = keyGenerator.generateKeyPair();

                SABERPublicKeyParameters publicKeyParams = (SABERPublicKeyParameters)kp.getPublic();
                SABERPrivateKeyParameters privateKeyParams = (SABERPrivateKeyParameters)kp.getPrivate();

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