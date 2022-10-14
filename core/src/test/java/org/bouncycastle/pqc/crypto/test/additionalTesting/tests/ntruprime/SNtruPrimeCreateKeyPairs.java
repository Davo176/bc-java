package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.ntruprime;

//Import dependencies
import junit.framework.TestCase;
import java.io.*;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

//Asset Under Test
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters;
public class SNtruPrimeCreateKeyPairs
    extends TestCase
{
    public void test() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "keypairs_java_1518.rsp",
            "keypairs_java_1763.rsp",
            "keypairs_java_1999.rsp",
            "keypairs_java_2254.rsp",
            "keypairs_java_2417.rsp",
            "keypairs_java_3059.rsp",
        };

        SNTRUPrimeParameters[] paramList = new SNTRUPrimeParameters[]
        {
                SNTRUPrimeParameters.sntrup653,
                SNTRUPrimeParameters.sntrup761,
                SNTRUPrimeParameters.sntrup857,
                SNTRUPrimeParameters.sntrup953,
                SNTRUPrimeParameters.sntrup1013,
                SNTRUPrimeParameters.sntrup1277,
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String name = files[fileIndex];
            try {
                File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/ntruprime/interoperability/sntru/"+name);
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
            FileWriter file = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/ntruprime/interoperability/sntru/"+name);

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
            SNTRUPrimeParameters params = paramList[fileIndex];

            for (int i=0;i<100;i++){
                int count = i;
                System.out.println("Testing Case: "+count);

                random.nextBytes(seed);
                file.write("count = "+count+"\n");
                file.write("seed = "+Hex.toHexString(seed)+"\n");
                
                SNTRUPrimeKeyPairGenerator keyGenerator = new SNTRUPrimeKeyPairGenerator();
                SNTRUPrimeKeyGenerationParameters generationParams = new SNTRUPrimeKeyGenerationParameters(random, params);

                keyGenerator.init(generationParams);
                AsymmetricCipherKeyPair kp = keyGenerator.generateKeyPair();

                SNTRUPrimePublicKeyParameters publicKeyParams = (SNTRUPrimePublicKeyParameters)kp.getPublic();
                SNTRUPrimePrivateKeyParameters privateKeyParams = (SNTRUPrimePrivateKeyParameters)kp.getPrivate();

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