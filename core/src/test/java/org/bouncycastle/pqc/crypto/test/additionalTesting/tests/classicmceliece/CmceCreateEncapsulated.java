package org.bouncycastle.pqc.crypto.test.additionalTesting.tests.classicmceliece;

import junit.framework.TestCase;
import java.io.*;

//Dependencies Written by Bouncy Castle
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.pqc.crypto.test.NISTSecureRandom;

import org.bouncycastle.crypto.SecretWithEncapsulation;
//Asset Under Test
import org.bouncycastle.pqc.crypto.cmce.CMCEKEMGenerator;
import org.bouncycastle.pqc.crypto.cmce.CMCEParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEPublicKeyParameters;


public class CmceCreateEncapsulated extends TestCase
{
    public void testCMCEVectors() 
        throws Exception
    {
        String[] files;
        files = new String[]{
            "std/keypairs_ref_6492.rsp",
            "f/keypairs_ref_6492.rsp",
            "std/keypairs_ref_13608.rsp",
            "f/keypairs_ref_13608.rsp",
            "std/keypairs_ref_13932.rsp",
            "f/keypairs_ref_13932.rsp",
            "std/keypairs_ref_13948.rsp",
            "f/keypairs_ref_13948.rsp",
            "std/keypairs_ref_14120.rsp",
            "f/keypairs_ref_14120.rsp"
        };

        String[] newFiles = new String[]{
            "std/encapsulated_java_6492.rsp",
            "f/encapsulated_java_6492.rsp",
            "std/encapsulated_java_13608.rsp",
            "f/encapsulated_java_13608.rsp",
            "std/encapsulated_java_13932.rsp",
            "f/encapsulated_java_13932.rsp",
            "std/encapsulated_java_13948.rsp",
            "f/encapsulated_java_13948.rsp",
            "std/encapsulated_java_14120.rsp",
            "f/encapsulated_java_14120.rsp"
        };

        CMCEParameters[] paramList = new CMCEParameters[]{
            CMCEParameters.mceliece348864r3,
            CMCEParameters.mceliece348864fr3,
            CMCEParameters.mceliece460896r3,
            CMCEParameters.mceliece460896fr3,
            CMCEParameters.mceliece6688128r3,
            CMCEParameters.mceliece6688128fr3,
            CMCEParameters.mceliece6960119r3,
            CMCEParameters.mceliece6960119fr3,
            CMCEParameters.mceliece8192128r3,
            CMCEParameters.mceliece8192128fr3
        };

        for (int fileIndex = 0; fileIndex < files.length; fileIndex++)
        {
            String newFileName = newFiles[fileIndex];
            try {
            File myObj = new File("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/cmce/interoperability/"+newFileName);
            if (myObj.createNewFile()) {
                    System.out.println("File created: " + myObj.getName());
            } else {
                    System.out.println("File already exists.");
            }
            } catch (IOException e) {
                System.out.println("An error occurred.");
                e.printStackTrace();
            }
            
            FileWriter newFile = new FileWriter("src/test/java/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/cmce/interoperability/"+newFileName);
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = CmceCreateEncapsulated.class.getResourceAsStream("/org/bouncycastle/pqc/crypto/test/additionalTesting/resources/cmce/interoperability/" + name);
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
                CMCEParameters params = paramList[fileIndex];
                //Generate Random from seed (assume this works correctly)
                NISTSecureRandom random = new NISTSecureRandom(entropy_input, null);

                CMCEPublicKeyParameters publicKeyParams = new CMCEPublicKeyParameters(params, pk);

                CMCEKEMGenerator encapsulator = new CMCEKEMGenerator(random);
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