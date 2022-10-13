package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.bike;

//Import dependencies
import junit.framework.TestCase;
import java.io.*;

//Import dependencies

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

//Asset Under Test
import org.bouncycastle.pqc.crypto.bike.BIKEKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.bike.BIKEKeyPairGenerator;
import org.bouncycastle.pqc.crypto.bike.BIKEParameters;
import org.bouncycastle.pqc.crypto.bike.BIKEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.bike.BIKEPublicKeyParameters;

public class BikeCreateKeyPairs
    extends TestCase
{
    public void test() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "keypairs_java_3114.rsp",
            "keypairs_java_6198.rsp",
            "keypairs_java_10276.rsp",
        };

        BIKEParameters[] paramList = {
            BIKEParameters.bike128,
            BIKEParameters.bike192,
            BIKEParameters.bike256
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            try {
                File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/bike/interoperability/"+name);
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
            FileWriter file = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/bike/interoperability/"+name);

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
            BIKEParameters params = paramList[fileIndex];

            for (int i=0;i<100;i++){
                int count = i;
                System.out.println("Testing Case: "+count);

                random.nextBytes(seed);
                file.write("count = "+count+"\n");
                file.write("seed = "+Hex.toHexString(seed)+"\n");
                
                BIKEKeyPairGenerator keyGenerator = new BIKEKeyPairGenerator();
                BIKEKeyGenerationParameters generationParams = new BIKEKeyGenerationParameters(random, params);

                keyGenerator.init(generationParams);
                AsymmetricCipherKeyPair kp = keyGenerator.generateKeyPair();

                BIKEPublicKeyParameters publicKeyParams = (BIKEPublicKeyParameters)kp.getPublic();
                BIKEPrivateKeyParameters privateKeyParams = (BIKEPrivateKeyParameters)kp.getPrivate();

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