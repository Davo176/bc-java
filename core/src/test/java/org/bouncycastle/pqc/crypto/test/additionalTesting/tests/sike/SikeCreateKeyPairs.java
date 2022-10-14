package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.sike;

import junit.framework.TestCase;
import java.io.*;

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;

import org.bouncycastle.pqc.crypto.sike.SIKEKEMExtractor;
import org.bouncycastle.pqc.crypto.sike.SIKEKEMGenerator;
import org.bouncycastle.pqc.crypto.sike.SIKEKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sike.SIKEKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sike.SIKEParameters;
import org.bouncycastle.pqc.crypto.sike.SIKEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sike.SIKEPublicKeyParameters;

public class SikeCreateKeyPairs
    extends TestCase
{
    public void test() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            //Parameter sets dont line up with secret key bytes intentionally
            "keypairs_java_374.rsp",
            "keypairs_java_434.rsp",
            "keypairs_java_524.rsp",
            "keypairs_java_644.rsp",
        };

        SIKEParameters[] paramList = {
            SIKEParameters.sikep434,
            SIKEParameters.sikep503,
            SIKEParameters.sikep610,
            SIKEParameters.sikep751,
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            try {
                File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/sike/interoperability/"+name);
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
            FileWriter file = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/sike/interoperability/"+name);

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
            SIKEParameters params = paramList[fileIndex];

            for (int i=0;i<100;i++){
                int count = i;
                System.out.println("Testing Case: "+count);

                random.nextBytes(seed);
                file.write("count = "+count+"\n");
                file.write("seed = "+Hex.toHexString(seed)+"\n");
                
                SIKEKeyPairGenerator keyGenerator = new SIKEKeyPairGenerator();
                SIKEKeyGenerationParameters generationParams = new SIKEKeyGenerationParameters(random, params);

                keyGenerator.init(generationParams);
                AsymmetricCipherKeyPair kp = keyGenerator.generateKeyPair();

                SIKEPublicKeyParameters publicKeyParams = (SIKEPublicKeyParameters)kp.getPublic();
                SIKEPrivateKeyParameters privateKeyParams = (SIKEPrivateKeyParameters)kp.getPrivate();

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