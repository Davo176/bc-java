package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.falcon;

//Import dependencies
import junit.framework.TestCase;
import java.io.*;

//Import dependencies

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

//Asset Under Test
import org.bouncycastle.pqc.crypto.falcon.FalconParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.falcon.FalconKeyPairGenerator;

public class FalconCreateKeypairs
    extends TestCase
{
    public void test() 
        throws Exception
    {
        String[] files = new String[]{
            "keypairs_java_falcon512.rsp",
            "keypairs_java_falcon1024.rsp",
        };
        FalconParameters[] paramList = new FalconParameters[]{
            FalconParameters.falcon_512,
            FalconParameters.falcon_1024,
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            try {
                File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/falcon/interoperability/"+name);
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
            FileWriter file = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/falcon/interoperability/"+name);

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
            FalconParameters params = paramList[fileIndex];

            for (int i=0;i<100;i++){
                int count = i;
                System.out.println("Testing Case: "+count);
                int messageLength = 33*(i+1);
                byte[] message = new byte[messageLength];

                random.nextBytes(seed);
                file.write("count = "+count+"\n");
                file.write("seed = "+Hex.toHexString(seed)+"\n");
                
                FalconKeyPairGenerator keyGenerator = new FalconKeyPairGenerator();
                FalconKeyGenerationParameters generationParams = new FalconKeyGenerationParameters(random, params);

                keyGenerator.init(generationParams);
                AsymmetricCipherKeyPair kp = keyGenerator.generateKeyPair();

                FalconPublicKeyParameters publicKeyParams = (FalconPublicKeyParameters)kp.getPublic();
                FalconPrivateKeyParameters privateKeyParams = (FalconPrivateKeyParameters)kp.getPrivate();
                random.nextBytes(message);

                byte[] returnedPk=publicKeyParams.getH();
                byte[] returnedSk=privateKeyParams.getEncoded();

                file.write("mlen = "+Integer.toString(messageLength)+"\n");
                file.write("msg = "+Hex.toHexString(message)+"\n");
                if (params.getName().equals("falcon-512")){
                    file.write("pk = 09"+Hex.toHexString(returnedPk)+"\n");
                    file.write("sk = 59"+Hex.toHexString(returnedSk)+"\n");
                }else{
                    file.write("pk = 0A"+Hex.toHexString(returnedPk)+"\n");
                    file.write("sk = 5A"+Hex.toHexString(returnedSk)+"\n");
                }
                file.write("\n");
            }
            file.close();
        }
    }
}