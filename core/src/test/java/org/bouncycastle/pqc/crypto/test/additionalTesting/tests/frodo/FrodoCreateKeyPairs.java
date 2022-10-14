package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.frodo;

//Import dependencies
import junit.framework.TestCase;
import java.io.*;

//Import dependencies

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

//Asset Under Test
import org.bouncycastle.pqc.crypto.frodo.FrodoKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoKeyPairGenerator;
import org.bouncycastle.pqc.crypto.frodo.FrodoParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPublicKeyParameters;

public class FrodoCreateKeyPairs
    extends TestCase
{
    public void test() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "keypairs_java_19888.rsp",
            "keypairs_java_31296.rsp",
            "keypairs_java_43088.rsp",
        };

        FrodoParameters[] paramList = {
            FrodoParameters.frodokem640aes,
            FrodoParameters.frodokem976aes,
            FrodoParameters.frodokem1344aes,
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            try {
                File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/frodo/interoperability/"+name);
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
            FileWriter file = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/frodo/interoperability/"+name);

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
            FrodoParameters params = paramList[fileIndex];

            for (int i=0;i<100;i++){
                int count = i;
                System.out.println("Testing Case: "+count);

                random.nextBytes(seed);
                file.write("count = "+count+"\n");
                file.write("seed = "+Hex.toHexString(seed)+"\n");
                
                FrodoKeyPairGenerator keyGenerator = new FrodoKeyPairGenerator();
                FrodoKeyGenerationParameters generationParams = new FrodoKeyGenerationParameters(random, params);

                keyGenerator.init(generationParams);
                AsymmetricCipherKeyPair kp = keyGenerator.generateKeyPair();

                FrodoPublicKeyParameters publicKeyParams = (FrodoPublicKeyParameters)kp.getPublic();
                FrodoPrivateKeyParameters privateKeyParams = (FrodoPrivateKeyParameters)kp.getPrivate();

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