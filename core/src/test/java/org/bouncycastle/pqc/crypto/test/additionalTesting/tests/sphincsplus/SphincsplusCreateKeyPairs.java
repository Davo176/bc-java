package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.sphincsplus;

import junit.framework.TestCase;
import java.io.*;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;

public class SphincsplusCreateKeyPairs
    extends TestCase
{
    public void test() 
        throws Exception
    {
        String files[] = new String[]{
            "keypairs_java_haraka-128f-robust.rsp",
            "keypairs_java_haraka-128f-simple.rsp",
            "keypairs_java_haraka-128s-robust.rsp",
            "keypairs_java_haraka-128s-simple.rsp",
            "keypairs_java_haraka-192f-robust.rsp",
            "keypairs_java_haraka-192f-simple.rsp",
            "keypairs_java_haraka-192s-robust.rsp",
            "keypairs_java_haraka-192s-simple.rsp",
            "keypairs_java_haraka-256f-robust.rsp",
            "keypairs_java_haraka-256f-simple.rsp",
            "keypairs_java_haraka-256s-robust.rsp",
            "keypairs_java_haraka-256s-simple.rsp",
            "keypairs_java_sha2-128f-robust.rsp",
            "keypairs_java_sha2-128f-simple.rsp",
            "keypairs_java_sha2-128s-robust.rsp",
            "keypairs_java_sha2-128s-simple.rsp",
            "keypairs_java_sha2-192f-robust.rsp",
            "keypairs_java_sha2-192f-simple.rsp",
            "keypairs_java_sha2-192s-robust.rsp",
            "keypairs_java_sha2-192s-simple.rsp",
            "keypairs_java_sha2-256f-robust.rsp",
            "keypairs_java_sha2-256f-simple.rsp",
            "keypairs_java_sha2-256s-robust.rsp",
            "keypairs_java_sha2-256s-simple.rsp",
            "keypairs_java_shake-128f-robust.rsp",
            "keypairs_java_shake-128f-simple.rsp",
            "keypairs_java_shake-128s-robust.rsp",
            "keypairs_java_shake-128s-simple.rsp",
            "keypairs_java_shake-192f-robust.rsp",
            "keypairs_java_shake-192f-simple.rsp",
            "keypairs_java_shake-192s-robust.rsp",
            "keypairs_java_shake-192s-simple.rsp",
            "keypairs_java_shake-256f-robust.rsp",
            "keypairs_java_shake-256f-simple.rsp",
            "keypairs_java_shake-256s-robust.rsp",
            "keypairs_java_shake-256s-simple.rsp",
        };

        SPHINCSPlusParameters[] paramList = new SPHINCSPlusParameters[]{
            SPHINCSPlusParameters.haraka_128f,
            SPHINCSPlusParameters.haraka_128f_simple,
            SPHINCSPlusParameters.haraka_128s,
            SPHINCSPlusParameters.haraka_128s_simple,
            SPHINCSPlusParameters.haraka_192f,
            SPHINCSPlusParameters.haraka_192f_simple,
            SPHINCSPlusParameters.haraka_192s,
            SPHINCSPlusParameters.haraka_192s_simple,
            SPHINCSPlusParameters.haraka_256f,
            SPHINCSPlusParameters.haraka_256f_simple,
            SPHINCSPlusParameters.haraka_256s,
            SPHINCSPlusParameters.haraka_256s_simple,
            SPHINCSPlusParameters.sha2_128f,
            SPHINCSPlusParameters.sha2_128f_simple,
            SPHINCSPlusParameters.sha2_128s,
            SPHINCSPlusParameters.sha2_128s_simple,
            SPHINCSPlusParameters.sha2_192f,
            SPHINCSPlusParameters.sha2_192f_simple,
            SPHINCSPlusParameters.sha2_192s,
            SPHINCSPlusParameters.sha2_192s_simple,
            SPHINCSPlusParameters.sha2_256f,
            SPHINCSPlusParameters.sha2_256f_simple,
            SPHINCSPlusParameters.sha2_256s,
            SPHINCSPlusParameters.sha2_256s_simple,
            SPHINCSPlusParameters.shake_128f,
            SPHINCSPlusParameters.shake_128f_simple,
            SPHINCSPlusParameters.shake_128s,
            SPHINCSPlusParameters.shake_128s_simple,
            SPHINCSPlusParameters.shake_192f,
            SPHINCSPlusParameters.shake_192f_simple,
            SPHINCSPlusParameters.shake_192s,
            SPHINCSPlusParameters.shake_192s_simple,
            SPHINCSPlusParameters.shake_256f,
            SPHINCSPlusParameters.shake_256f_simple,
            SPHINCSPlusParameters.shake_256s,
            SPHINCSPlusParameters.shake_256s_simple,
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            try {
                File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/sphincsplus/interoperability/"+name);
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
            FileWriter file = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/sphincsplus/interoperability/"+name);

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
            SPHINCSPlusParameters params = paramList[fileIndex];

            for (int i=0;i<100;i++){
                int count = i;
                System.out.println("Testing Case: "+count);
                int messageLength = 33*(i+1); //keeping consistant messageLengths
                byte[] message = new byte[messageLength];

                random.nextBytes(seed);
                file.write("count = "+count+"\n");
                file.write("seed = "+Hex.toHexString(seed)+"\n");
                
                SPHINCSPlusKeyPairGenerator keyGenerator = new SPHINCSPlusKeyPairGenerator();
                SPHINCSPlusKeyGenerationParameters generationParams = new SPHINCSPlusKeyGenerationParameters(random, params);

                keyGenerator.init(generationParams);
                AsymmetricCipherKeyPair kp = keyGenerator.generateKeyPair();

                SPHINCSPlusPublicKeyParameters publicKeyParams = (SPHINCSPlusPublicKeyParameters)kp.getPublic();
                SPHINCSPlusPrivateKeyParameters privateKeyParams = (SPHINCSPlusPrivateKeyParameters)kp.getPrivate();
                random.nextBytes(message);

                //keeping consistant with how previous testing was done, obviously should raise this.
                //removing the additional info from start of keys
                byte[] returnedPk=Arrays.copyOfRange(publicKeyParams.getEncoded(),publicKeyParams.getParameters().getEncoded().length,publicKeyParams.getEncoded().length);
                byte[] returnedSk=Arrays.copyOfRange(privateKeyParams.getEncoded(),privateKeyParams.getParameters().getEncoded().length,privateKeyParams.getEncoded().length);

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