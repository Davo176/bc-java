package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.ntruprime;

//Import dependencies
import junit.framework.TestCase;
import java.io.*;
import java.util.ArrayList;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.util.Arrays;
//Asset Under Test
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters;

public class SNtruPrimeCreateEncapsulations extends TestCase
{
    public void testCreateEncapsulationsntrulpr() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "keypairs_ref_1518.rsp",
            "keypairs_ref_1763.rsp",
            "keypairs_ref_1999.rsp",
            "keypairs_ref_2254.rsp",
            "keypairs_ref_2417.rsp",
            "keypairs_ref_3059.rsp",
        };

        String[] newFiles = new String[]{
            "encapsulation_java_1518.rsp",
            "encapsulation_java_1763.rsp",
            "encapsulation_java_1999.rsp",
            "encapsulation_java_2254.rsp",
            "encapsulation_java_2417.rsp",
            "encapsulation_java_3059.rsp",
        };

        SNTRUPrimeParameters[] paramList = new SNTRUPrimeParameters[]
        {
            SNTRUPrimeParameters.sntrup653,
            SNTRUPrimeParameters.sntrup761,
            SNTRUPrimeParameters.sntrup857,
            SNTRUPrimeParameters.sntrup953,
            SNTRUPrimeParameters.sntrup1013,
            SNTRUPrimeParameters.sntrup1277
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String newFileName = newFiles[fileIndex];
            try {
            File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/ntruprime/interoperability/sntru/"+newFileName);
            if (myObj.createNewFile()) {
                    System.out.println("File created: " + myObj.getName());
            } else {
                    System.out.println("File already exists.");
            }
            } catch (IOException e) {
                System.out.println("An error occurred.");
                e.printStackTrace();
            }
            
            FileWriter newFile = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/ntruprime/interoperability/sntru/"+newFileName);
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = SNtruPrimeCreateEncapsulations.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/ntruprime/interoperability/sntru/" + name);
            BufferedReader br = new BufferedReader(new InputStreamReader(src));

            String line = null;
            while ((line = br.readLine()) != null){
                //Find next test
                int countIndex = line.indexOf("count = ");
                while (countIndex < 0){
                    line = br.readLine();
                    countIndex = line.indexOf("count = ");
                }
                String count = line.substring(countIndex + "count = ".length()).trim();
                line = br.readLine();
                
                //Get Seed
                int seedIndex = line.indexOf("seed = ");
                String seedString = line.substring(seedIndex + "seed = ".length()).trim();
                line = br.readLine();
                //Get Public Key
                int publicKeyIndex = line.indexOf("pk = ");
                String publicKeyString = line.substring(publicKeyIndex + "pk = ".length()).trim();
                line = br.readLine();
                //Get Secret Key
                int secretKeyIndex = line.indexOf("sk = ");
                String secretKeyString = line.substring(secretKeyIndex + "sk = ".length()).trim();
                line = br.readLine();

                //convert all into byte arrays
                byte[] seedOld = Hex.decode(seedString); 
                byte[] pk = Hex.decode(publicKeyString);

                System.out.println("Testing Case: "+count);

                byte[] seed = new byte[48];
                byte[] entropy_input = new byte[48];
                for (int i=0;i<48;i++){
                    entropy_input[i]=(byte)i;
                }

                //Get Parameters
                SNTRUPrimeParameters params = paramList[fileIndex];
                //Generate Random from seed (assume this works correctly)
                NISTSecureRandom random = new NISTSecureRandom(entropy_input, null);

                SNTRUPrimePublicKeyParameters publicKeyParams = new SNTRUPrimePublicKeyParameters(params, pk);

                SNTRUPrimeKEMGenerator encapsulator = new SNTRUPrimeKEMGenerator(random);
                SecretWithEncapsulation encapsulatedSecret = encapsulator.generateEncapsulated(publicKeyParams);
                byte[] returnedCt = encapsulatedSecret.getEncapsulation();
                byte[] returnedSecret = encapsulatedSecret.getSecret();

                newFile.write("count = "+count+"\n");
                newFile.write("pk = "+publicKeyString+"\n");
                newFile.write("sk = "+secretKeyString+"\n");
                newFile.write("ct = "+Hex.toHexString(returnedCt)+"\n");
                newFile.write("ss = "+Hex.toHexString(returnedSecret)+"\n");
                newFile.write("\n");
                System.out.println("All Passed");
            }
            newFile.close();
        }
    }
}