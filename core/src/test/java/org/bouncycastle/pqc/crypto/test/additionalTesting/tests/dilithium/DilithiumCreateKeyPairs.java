package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.dilithium;

//Import dependencies
import junit.framework.TestCase;
import java.io.*;

//Import dependencies

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

//Asset Under Test
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator;

public class DilithiumCreateKeyPairs
    extends TestCase
{
    public void test() 
        throws Exception
    {
        String[] files = new String[]{
            "keypairs_java_Dilithium2.rsp",
            "keypairs_java_Dilithium3.rsp",
            "keypairs_java_Dilithium5.rsp"
        };
        DilithiumParameters[] paramList = new DilithiumParameters[]{
            DilithiumParameters.dilithium2,
            DilithiumParameters.dilithium3,
            DilithiumParameters.dilithium5
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            try {
                File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/dilithium/interoperability/"+name);
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
            FileWriter file = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/dilithium/interoperability/"+name);

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
            DilithiumParameters params = paramList[fileIndex];

            for (int i=0;i<100;i++){
                int count = i;
                System.out.println("Testing Case: "+count);
                int messageLength = 33*(i+1);
                byte[] message = new byte[messageLength];

                random.nextBytes(seed);
                file.write("count = "+count+"\n");
                file.write("seed = "+Hex.toHexString(seed)+"\n");
                
                DilithiumKeyPairGenerator keyGenerator = new DilithiumKeyPairGenerator();
                DilithiumKeyGenerationParameters generationParams = new DilithiumKeyGenerationParameters(random, params);

                keyGenerator.init(generationParams);
                AsymmetricCipherKeyPair kp = keyGenerator.generateKeyPair();

                DilithiumPublicKeyParameters publicKeyParams = (DilithiumPublicKeyParameters)kp.getPublic();
                DilithiumPrivateKeyParameters privateKeyParams = (DilithiumPrivateKeyParameters)kp.getPrivate();
                random.nextBytes(message);

                byte[] returnedPk=publicKeyParams.getEncoded();
                byte[] returnedSk=privateKeyParams.getEncoded();

                file.write("mlen = "+Integer.toString(messageLength)+"\n");
                file.write("msg = "+Hex.toHexString(message)+"\n");
                file.write("pk = "+Hex.toHexString(returnedPk)+"\n");
                file.write("sk = "+Hex.toHexString(returnedSk)+"\n");
                file.write("\n");
            }
            file.close();
        }
    }
}