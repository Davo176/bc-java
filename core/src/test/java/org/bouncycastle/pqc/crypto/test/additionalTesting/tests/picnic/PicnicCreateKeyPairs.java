package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.picnic;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.HashMap;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.picnic.PicnicKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicKeyPairGenerator;
import org.bouncycastle.pqc.crypto.picnic.PicnicParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicPublicKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

public class PicnicCreateKeyPairs
    extends TestCase
{
    public void test() 
        throws Exception
    {
        String[] files = new String[]{
            "3/keypairs_java_L1.rsp",
            "3/keypairs_java_L3.rsp",
            "3/keypairs_java_L5.rsp",
            "fs/keypairs_java_L1.rsp",
            "fs/keypairs_java_L3.rsp",
            "fs/keypairs_java_L5.rsp",
            "full/keypairs_java_L1.rsp",
            "full/keypairs_java_L3.rsp",
            "full/keypairs_java_L5.rsp",
            "ur/keypairs_java_L1.rsp",
            "ur/keypairs_java_L3.rsp",
            "ur/keypairs_java_L5.rsp",
        };
        PicnicParameters[] paramList = new PicnicParameters[]{
            PicnicParameters.picnic3l1,
            PicnicParameters.picnic3l3,
            PicnicParameters.picnic3l5,
            PicnicParameters.picnicl1fs,
            PicnicParameters.picnicl3fs,
            PicnicParameters.picnicl5fs,
            PicnicParameters.picnicl1full,
            PicnicParameters.picnicl3full,
            PicnicParameters.picnicl5full,
            PicnicParameters.picnicl1ur,
            PicnicParameters.picnicl3ur,
            PicnicParameters.picnicl5ur,
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            try {
                File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/picnic/interoperability/"+name);
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
            FileWriter file = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/picnic/interoperability/"+name);

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
            PicnicParameters params = paramList[fileIndex];

            for (int i=0;i<100;i++){
                int count = i;
                System.out.println("Testing Case: "+count);
                int messageLength = 33*(i+1);
                byte[] message = new byte[messageLength];

                random.nextBytes(seed);
                file.write("count = "+count+"\n");
                file.write("seed = "+Hex.toHexString(seed)+"\n");
                
                PicnicKeyPairGenerator keyGenerator = new PicnicKeyPairGenerator();
                PicnicKeyGenerationParameters generationParams = new PicnicKeyGenerationParameters(random, params);

                keyGenerator.init(generationParams);
                AsymmetricCipherKeyPair kp = keyGenerator.generateKeyPair();

                PicnicPublicKeyParameters publicKeyParams = (PicnicPublicKeyParameters)kp.getPublic();
                PicnicPrivateKeyParameters privateKeyParams = (PicnicPrivateKeyParameters)kp.getPrivate();
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